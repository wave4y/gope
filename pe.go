package gope

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	maxImageSize         uint32 = 1 << 31
	maxExportEntries     uint32 = 1 << 20
	maxExportString      uint32 = 64 << 10
	maxExportStringBytes uint64 = 16 << 20
)

// OpenPE64 validates headers for a PE32+ image already mapped in this process.
// It reads memory without dereferencing arbitrary Go pointers. The caller must
// keep the module loaded for subsequent reads and calls. Public header fields
// are snapshots, not mutable parser state. Exports validates symbol contents.
//
//go:uintptrescapes
func OpenPE64(baseAddr uintptr) (*PE64, error) {
	if baseAddr == 0 {
		return nil, ErrInvalidAddress
	}
	return openPE64(baseAddr, func(offset uint32, size uint32) ([]byte, error) {
		if uintptr(offset) > ^uintptr(0)-baseAddr {
			return nil, ErrInvalidAddress
		}
		address := baseAddr + uintptr(offset)
		if size > 0 && uintptr(size-1) > ^uintptr(0)-address {
			return nil, ErrInvalidAddress
		}
		return readProcessMemory(address, size)
	})
}

// NewPE64 is the compatibility constructor. It returns nil for an invalid
// image or unreadable address; use OpenPE64 to obtain the error.
//
//go:uintptrescapes
func NewPE64(baseAddr uintptr) *PE64 {
	pe, _ := OpenPE64(baseAddr)
	return pe
}

func openPE64(baseAddr uintptr, readAt func(offset uint32, size uint32) ([]byte, error)) (*PE64, error) {
	if baseAddr == 0 {
		return nil, ErrInvalidAddress
	}
	if readAt == nil {
		return nil, fmt.Errorf("%w: nil memory reader", ErrInvalidPE)
	}
	rawRead := func(offset, size uint32) ([]byte, error) {
		if uint64(offset)+uint64(size) > uint64(maxImageSize) {
			return nil, fmt.Errorf("%w: header range", ErrInvalidPE)
		}
		if uintptr(offset) > ^uintptr(0)-baseAddr || (size > 0 && uintptr(size-1) > ^uintptr(0)-(baseAddr+uintptr(offset))) {
			return nil, ErrInvalidAddress
		}
		data, err := readAt(offset, size)
		if err != nil {
			return nil, fmt.Errorf("gope: read header at %#x: %w", offset, err)
		}
		if uint64(len(data)) != uint64(size) {
			return nil, fmt.Errorf("%w: short header read", ErrInvalidPE)
		}
		return data, nil
	}
	dosData, err := rawRead(0, 64)
	if err != nil {
		return nil, err
	}
	var dos IMAGE_DOS_HEADER
	if err := decode(dosData, &dos); err != nil {
		return nil, err
	}
	if dos.E_magic != 0x5a4d || dos.E_lfanew < 64 {
		return nil, fmt.Errorf("%w: DOS header", ErrInvalidPE)
	}
	ntOffset := uint32(dos.E_lfanew)
	ntData, err := rawRead(ntOffset, 24)
	if err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(ntData[:4]) != 0x00004550 {
		return nil, fmt.Errorf("%w: NT signature", ErrInvalidPE)
	}
	var nt IMAGE_NT_HEADERS64
	nt.Signature = 0x00004550
	if err := decode(ntData[4:], &nt.FileHeader); err != nil {
		return nil, err
	}
	optionalSize := uint32(nt.FileHeader.SizeOfOptionalHeader)
	if optionalSize < 112 {
		return nil, fmt.Errorf("%w: short PE32+ optional header", ErrInvalidPE)
	}
	optionalOffset := ntOffset + 24 // rawRead above has already bounded this sum.
	optionalData, err := rawRead(optionalOffset, optionalSize)
	if err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint16(optionalData[:2]) != 0x20b {
		return nil, fmt.Errorf("%w: expected PE32+ optional header", ErrInvalidPE)
	}
	directoryCount := binary.LittleEndian.Uint32(optionalData[108:112])
	if uint64(directoryCount)*8+112 > uint64(optionalSize) {
		return nil, fmt.Errorf("%w: data directories exceed optional header", ErrInvalidPE)
	}
	// PE data directories are variable-length. Zero-fill entries not declared by
	// the image while retaining the historical fixed-size public snapshot type.
	paddedOptional := make([]byte, 240)
	copy(paddedOptional, optionalData[:112])
	knownDirectories := directoryCount
	if knownDirectories > IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
		knownDirectories = IMAGE_NUMBEROF_DIRECTORY_ENTRIES
	}
	copy(paddedOptional[112:], optionalData[112:112+knownDirectories*8])
	if err := decode(paddedOptional, &nt.OptionalHeader); err != nil {
		return nil, err
	}
	imageSize := uint32(nt.OptionalHeader.SizeOfImage)
	headerSize := uint32(nt.OptionalHeader.SizeOfHeaders)
	requiredHeaders := uint64(optionalOffset) + uint64(optionalSize) + uint64(nt.FileHeader.NumberOfSections)*40
	if imageSize == 0 || imageSize > maxImageSize || headerSize == 0 || headerSize > imageSize || requiredHeaders > uint64(headerSize) {
		return nil, fmt.Errorf("%w: image or header size", ErrInvalidPE)
	}
	if uintptr(imageSize-1) > ^uintptr(0)-baseAddr {
		return nil, ErrInvalidAddress
	}
	pe := &PE64{DllBase: baseAddr, dosbase: baseAddr, DosHeader: &dos, NtHeaders: &nt, reader: readAt, baseAddr: baseAddr, size: imageSize}
	if directoryCount > IMAGE_DIRECTORY_ENTRY_EXPORT {
		pe.exportDirectory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
		directory := pe.exportDirectory
		present, err := pe.directoryPresent(directory, 40)
		if err != nil {
			return nil, err
		}
		if present {
			data, err := pe.read(uint32(directory.VirtualAddress), 40)
			if err != nil {
				return nil, err
			}
			if err := decode(data, &pe.exportHeader); err != nil {
				return nil, err
			}
			pe.hasExports = true
			snapshot := pe.exportHeader
			pe.Export = &snapshot
			if err := pe.validateExportTables(); err != nil {
				return nil, err
			}
		}
	}
	if directoryCount > IMAGE_DIRECTORY_ENTRY_IMPORT {
		directory := nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
		present, err := pe.directoryPresent(directory, 20)
		if err != nil {
			return nil, err
		}
		if present {
			data, err := pe.read(uint32(directory.VirtualAddress), 20)
			if err != nil {
				return nil, err
			}
			var snapshot IMAGE_IMPORT_DESCRIPTOR
			if err := decode(data, &snapshot); err != nil {
				return nil, err
			}
			pe.Import = &snapshot
		}
	}
	return pe, nil
}

func decode(data []byte, value interface{}) error {
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, value); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPE, err)
	}
	return nil
}

func (pe *PE64) validRange(offset, size uint32) bool {
	return pe != nil && offset <= pe.size && size <= pe.size-offset
}

func (pe *PE64) read(offset, size uint32) ([]byte, error) {
	if pe == nil || pe.reader == nil || (size != 0 && !pe.validRange(offset, size)) {
		return nil, fmt.Errorf("%w: RVA range", ErrInvalidPE)
	}
	if size == 0 {
		return []byte{}, nil
	}
	data, err := pe.reader(offset, size)
	if err != nil {
		return nil, fmt.Errorf("gope: read RVA %#x: %w", offset, err)
	}
	if uint64(len(data)) != uint64(size) {
		return nil, fmt.Errorf("%w: short RVA read", ErrInvalidPE)
	}
	return data, nil
}

func (pe *PE64) directoryPresent(directory IMAGE_DATA_DIRECTORY, minimum uint32) (bool, error) {
	rva, size := uint32(directory.VirtualAddress), uint32(directory.Size)
	if rva == 0 && size == 0 {
		return false, nil
	}
	if rva == 0 || size < minimum || !pe.validRange(rva, size) {
		return false, fmt.Errorf("%w: data directory range", ErrInvalidPE)
	}
	return true, nil
}

func (pe *PE64) validateExportTables() error {
	h := pe.exportHeader
	functions, names := uint32(h.NumberOfFunctions), uint32(h.NumberOfNames)
	if functions > maxExportEntries || names > maxExportEntries {
		return fmt.Errorf("%w: export table exceeds %d entries", ErrInvalidPE, maxExportEntries)
	}
	if functions == 0 && names != 0 {
		return fmt.Errorf("%w: named exports without address table", ErrInvalidPE)
	}
	if functions > 0 && uint64(h.Base)+uint64(functions)-1 > uint64(^uint32(0)) {
		return fmt.Errorf("%w: export ordinal overflow", ErrInvalidPE)
	}
	for _, table := range []struct {
		rva          DWORD
		count, width uint32
	}{
		{h.AddressOfFunctions, functions, 4},
		{h.AddressOfNames, names, 4},
		{h.AddressOfNameOrdinals, names, 2},
	} {
		size := uint64(table.count) * uint64(table.width)
		if size == 0 {
			continue
		}
		if table.rva == 0 || size > uint64(pe.size) || !pe.validRange(uint32(table.rva), uint32(size)) {
			return fmt.Errorf("%w: export array range", ErrInvalidPE)
		}
	}
	return nil
}

// Exports returns named exports in name-table order, followed by ordinal-only
// exports in address-table order. Aliases are retained and empty address slots
// are omitted. Forwarders are described without resolution. Each table is
// limited to 1,048,576 entries, strings to 65,535 bytes plus NUL, and aggregate
// string reads to 16 MiB per call. Exported data is not distinguished from code.
func (pe *PE64) Exports() ([]ExportInfo, error) {
	if pe == nil || pe.reader == nil {
		return nil, fmt.Errorf("%w: uninitialized image", ErrInvalidPE)
	}
	if !pe.hasExports {
		return nil, nil
	}
	h := pe.exportHeader
	functions, names := uint32(h.NumberOfFunctions), uint32(h.NumberOfNames)
	addresses, err := pe.read(uint32(h.AddressOfFunctions), functions*4)
	if err != nil {
		return nil, err
	}
	nameRVAs, err := pe.read(uint32(h.AddressOfNames), names*4)
	if err != nil {
		return nil, err
	}
	ordinals, err := pe.read(uint32(h.AddressOfNameOrdinals), names*2)
	if err != nil {
		return nil, err
	}
	named := make([]bool, functions)
	budget := maxExportStringBytes
	result := make([]ExportInfo, 0)
	for i := uint32(0); i < names; i++ {
		index := uint32(binary.LittleEndian.Uint16(ordinals[i*2 : i*2+2]))
		if index >= functions {
			return nil, fmt.Errorf("%w: export name ordinal index", ErrInvalidPE)
		}
		nameRVA := binary.LittleEndian.Uint32(nameRVAs[i*4 : i*4+4])
		name, err := pe.readCString(nameRVA, pe.size, &budget)
		if err != nil {
			return nil, err
		}
		if name == "" {
			return nil, fmt.Errorf("%w: empty export name", ErrInvalidPE)
		}
		named[index] = true
		rva := binary.LittleEndian.Uint32(addresses[index*4 : index*4+4])
		if rva == 0 {
			continue
		}
		info, err := pe.exportInfo(name, index, rva, &budget)
		if err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	for i := uint32(0); i < functions; i++ {
		if named[i] {
			continue
		}
		rva := binary.LittleEndian.Uint32(addresses[i*4 : i*4+4])
		if rva == 0 {
			continue
		}
		info, err := pe.exportInfo("", i, rva, &budget)
		if err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	return result, nil
}

func (pe *PE64) exportInfo(name string, index, rva uint32, budget *uint64) (ExportInfo, error) {
	info := ExportInfo{Name: name, Ordinal: uint32(pe.exportHeader.Base) + index, RVA: rva}
	if !pe.validRange(rva, 1) {
		return ExportInfo{}, fmt.Errorf("%w: export address RVA", ErrInvalidPE)
	}
	start := uint32(pe.exportDirectory.VirtualAddress)
	end := start + uint32(pe.exportDirectory.Size) // directoryPresent checked this range.
	if rva >= start && rva < end {
		forwarder, err := pe.readCString(rva, end, budget)
		if err != nil {
			return ExportInfo{}, err
		}
		if forwarder == "" {
			return ExportInfo{}, fmt.Errorf("%w: empty export forwarder", ErrInvalidPE)
		}
		info.Forwarder = forwarder
	} else {
		info.Address = pe.baseAddr + uintptr(rva) // openPE64 checked the whole image range.
	}
	return info, nil
}

func (pe *PE64) readCString(rva, end uint32, budget *uint64) (string, error) {
	if rva == 0 || rva >= end || end > pe.size {
		return "", fmt.Errorf("%w: export string RVA", ErrInvalidPE)
	}
	limit := end - rva
	if limit > maxExportString {
		limit = maxExportString
	}
	text := make([]byte, 0, 64)
	for consumed := uint32(0); consumed < limit; {
		if *budget == 0 {
			return "", fmt.Errorf("%w: export strings exceed 16 MiB read budget", ErrInvalidPE)
		}
		count := limit - consumed
		if count > 256 {
			count = 256
		}
		if uint64(count) > *budget {
			count = uint32(*budget)
		}
		data, err := pe.read(rva+consumed, count)
		if err != nil && count > 1 {
			// A valid terminator can precede an unreadable page. Retrying one byte
			// avoids requiring bytes after the end of the string to be accessible.
			data, err = pe.read(rva+consumed, 1)
		}
		if err != nil {
			return "", err
		}
		*budget -= uint64(len(data))
		if terminator := bytes.IndexByte(data, 0); terminator >= 0 {
			text = append(text, data[:terminator]...)
			return string(text), nil
		}
		text = append(text, data...)
		consumed += uint32(len(data))
	}
	return "", fmt.Errorf("%w: unterminated or oversized export string", ErrInvalidPE)
}

// FindProc finds a named direct export. A forwarder returns ErrForwardedExport;
// no module is loaded as a side effect. Names are case-sensitive.
func (pe *PE64) FindProc(name string) (ExportFunc, error) {
	if name == "" {
		return ExportFunc{}, ErrNotFound
	}
	exports, err := pe.Exports()
	if err != nil {
		return ExportFunc{}, err
	}
	for _, info := range exports {
		if info.Name == name {
			return callableExport(info)
		}
	}
	return ExportFunc{}, ErrNotFound
}

// FindOrdinal finds a direct export by its public (base-biased) ordinal.
func (pe *PE64) FindOrdinal(ordinal uint32) (ExportFunc, error) {
	exports, err := pe.Exports()
	if err != nil {
		return ExportFunc{}, err
	}
	for _, info := range exports {
		if info.Ordinal == ordinal {
			return callableExport(info)
		}
	}
	return ExportFunc{}, ErrNotFound
}

func callableExport(info ExportInfo) (ExportFunc, error) {
	if info.Forwarder != "" {
		return ExportFunc{}, fmt.Errorf("%w: %s", ErrForwardedExport, info.Forwarder)
	}
	return ExportFunc{Name: info.Name, Addr: info.Address}, nil
}

// GetExportFunctions returns named direct exports and omits forwarders and
// empty address slots. Use Exports for complete metadata and explicit errors.
// As with FindProc, a direct export can describe data rather than executable code.
func (pe *PE64) GetExportFunctions() []ExportFunc {
	exports, err := pe.Exports()
	if err != nil {
		return nil
	}
	var functions []ExportFunc
	for _, info := range exports {
		if info.Name != "" && info.Forwarder == "" && info.Address != 0 {
			functions = append(functions, ExportFunc{Name: info.Name, Addr: info.Address})
		}
	}
	return functions
}

// NewProc is the compatibility lookup. It returns the zero value for a missing
// name, a forwarder, or a malformed image; use FindProc to obtain the error.
func (pe *PE64) NewProc(name string) ExportFunc {
	proc, _ := pe.FindProc(name)
	return proc
}
