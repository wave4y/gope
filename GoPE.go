package gope

import (
	"fmt"
	"reflect"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_DIRECTORY_ENTRY_EXPORT     = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT     = 1
)

// type WORD [2]byte
type WORD uint16
type DWORD uint32
type LONG int32
type BYTE int8
type ULONGLONG uint64

type PVOID uint32
type PVOID64 uintptr
type BOOLEAN BYTE

type IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    WORD
	E_cblp     WORD
	E_cp       WORD
	E_crlc     WORD
	E_cparhdr  WORD
	E_minalloc WORD
	E_maxalloc WORD
	E_ss       WORD
	E_sp       WORD
	E_csum     WORD
	E_ip       WORD
	E_cs       WORD
	E_lfarlc   WORD
	E_ovno     WORD
	E_res      [4]WORD
	E_oemid    WORD
	E_oeminfo  WORD
	E_res2     [10]WORD
	E_lfanew   LONG
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_FILE_HEADER struct {
	Machine              WORD
	NumberOfSections     WORD
	TimeDateStamp        DWORD
	PointerToSymbolTable DWORD
	NumberOfSymbols      DWORD
	SizeOfOptionalHeader WORD
	Characteristics      WORD
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}

type IMAGE_NT_HEADERS64 struct {
	Signature      DWORD
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       DWORD
	TimeDateStamp         DWORD
	MajorVersion          WORD
	MinorVersion          WORD
	Name                  DWORD
	Base                  DWORD
	NumberOfFunctions     DWORD
	NumberOfNames         DWORD
	AddressOfFunctions    DWORD
	AddressOfNames        DWORD
	AddressOfNameOrdinals DWORD
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	Characteristics_or_OriginalFirstThunk DWORD
	TimeDateStamp                         DWORD
	ForwarderChain                        DWORD
	Name                                  DWORD
	FirstThunk                            DWORD
}

// func strstr(addr uintptr, length int) {
//  Dll := *(*[4]byte)(unsafe.Pointer(uintptr(addr)))

// }

func Value(addr uintptr) uintptr {
	return *(*uintptr)(unsafe.Pointer(uintptr(addr)))
}

func Hex(addr interface{}) {
	fmt.Printf("%x\n", addr)
}

func sizeof(variable interface{}) {
	fmt.Println(unsafe.Sizeof(variable))
}

// func byte2bytes(bytearray interface{}) []byte {
//  return []byte(bytearray.va)
// }

func ptr(val interface{}) uintptr {
	switch val.(type) {
	case string:
		return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(val.(string))))
	case int:
		return uintptr(val.(int))
	default:
		return uintptr(0)
	}
}

var xiaoxingxing = []int{0, 523, 587, 659, 698, 784, 880, 932, 1046, 1175}
var t = []int{300, 300, 300, 300, 300, 300, 350, 300, 300, 300, 300, 300, 300, 300}
var s = []int{1, 1, 5, 5, 6, 6, 5, 4, 4, 3, 3, 2, 2, 1}

func BeepF(addr uintptr, volume int, timestep int) {
	syscall.Syscall(uintptr(addr), 2, uintptr(volume), uintptr(timestep), 0)
	time.Sleep(time.Microsecond * 270)
}

func Strptr(offset uintptr) string {
	var Name []byte
	for i := 0; i < 255; i++ {
		if *(*byte)(unsafe.Pointer(offset + uintptr(i))) == 0 {
			break
		}
		Name = append(Name, *(*byte)(unsafe.Pointer(offset + uintptr(i))))
	}
	return string(Name[:])
}

type PE64 struct {
	DllBase   uintptr
	dosbase   uintptr
	DosHeader *IMAGE_DOS_HEADER
	NtHeaders *IMAGE_NT_HEADERS64
	Export    *IMAGE_EXPORT_DIRECTORY
	Import    *IMAGE_IMPORT_DESCRIPTOR
}

type ExportFunc struct {
	Name string
	Addr uintptr
}

func NewPE64(baseAddr uintptr) *PE64 {
	pe := new(PE64)
	pe.DllBase = baseAddr
	pe.getDosHeader()
	pe.getNtHeaders()
	pe.getExportTable()
	pe.getImportTable()
	return pe
}

func (pe *PE64) getDosHeader() {
	bHdrDos := *(*[64]byte)(unsafe.Pointer(uintptr(pe.DllBase)))
	HdrDos := []byte(bHdrDos[:])
	pe.DosHeader = (*IMAGE_DOS_HEADER)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&HdrDos)).Data))
}

func (pe *PE64) getNtHeaders() {
	offset := uintptr(pe.DllBase) + uintptr(pe.DosHeader.E_lfanew)
	NtHeaders := []byte((*(*[16]byte)(unsafe.Pointer(uintptr(offset))))[:])
	pe.NtHeaders = (*IMAGE_NT_HEADERS64)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&NtHeaders)).Data))

}

func (pe *PE64) getExportTable() {
	offset := uintptr(pe.DllBase) + uintptr(pe.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	Export := []byte((*(*[16]byte)(unsafe.Pointer(uintptr(offset))))[:])
	pe.Export = (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&Export)).Data))

}

func (pe *PE64) getImportTable() {
	offset := uintptr(pe.DllBase) + uintptr(pe.NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	Import := []byte((*(*[14]byte)(unsafe.Pointer(uintptr(offset))))[:])
	pe.Import = (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&Import)).Data))

}

func (pe *PE64) GetExportFunctions() []ExportFunc {
	var Funcs []ExportFunc
	for i := 0; i < int(pe.Export.NumberOfFunctions); i++ {
		offsetName := uintptr(pe.DllBase) + uintptr(pe.Export.AddressOfNames) + uintptr(i*4)
		offsetName = uintptr(*(*DWORD)(unsafe.Pointer(offsetName))) + uintptr(pe.DllBase)
		offsetAddr := uintptr(pe.DllBase) + uintptr(pe.Export.AddressOfFunctions) + uintptr(i*4)
		offsetAddr = uintptr(*(*DWORD)(unsafe.Pointer(offsetAddr))) + uintptr(pe.DllBase)
		FuncName := Strptr(offsetName)
		tmpFunc := ExportFunc{Name: FuncName, Addr: offsetAddr}
		Funcs = append(Funcs, tmpFunc)
	}
	return Funcs
}

func (pe *PE64) NewProc(name string) ExportFunc {
	funcs := pe.GetExportFunctions()
	for _, funcname := range funcs {
		if name == funcname.Name {
			return funcname
		}
	}
	return ExportFunc{Name: "", Addr: uintptr(0)}
}

func (p *ExportFunc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	switch len(a) {
	case 0:
		return syscall.Syscall(p.Addr, uintptr(len(a)), 0, 0, 0)
	case 1:
		return syscall.Syscall(p.Addr, uintptr(len(a)), a[0], 0, 0)
	case 2:
		return syscall.Syscall(p.Addr, uintptr(len(a)), a[0], a[1], 0)
	case 3:
		return syscall.Syscall(p.Addr, uintptr(len(a)), a[0], a[1], a[2])
	case 4:
		return syscall.Syscall6(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], 0, 0)
	case 5:
		return syscall.Syscall6(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], 0)
	case 6:
		return syscall.Syscall6(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5])
	case 7:
		return syscall.Syscall9(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], 0, 0)
	case 8:
		return syscall.Syscall9(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], 0)
	case 9:
		return syscall.Syscall9(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
	case 10:
		return syscall.Syscall12(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], 0, 0)
	case 11:
		return syscall.Syscall12(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], 0)
	case 12:
		return syscall.Syscall12(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11])
	case 13:
		return syscall.Syscall15(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], 0, 0)
	case 14:
		return syscall.Syscall15(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], 0)
	case 15:
		return syscall.Syscall15(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14])
	case 16:
		return syscall.Syscall18(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15], 0, 0)
	case 17:
		return syscall.Syscall18(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15], a[16], 0)
	case 18:
		return syscall.Syscall18(p.Addr, uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15], a[16], a[17])
	default:
		panic("Call " + p.Name + " with too many arguments " + strconv.Itoa(len(a)) + ".")
	}
}
