package gope

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

const maxReadStringLength = 64 << 10

// ReadValue copies a pointer-sized unsigned value from current-process memory.
//
//go:uintptrescapes
func ReadValue(addr uintptr) (uintptr, error) {
	width := uint32(strconv.IntSize / 8)
	data, err := readProcessMemory(addr, width)
	if err != nil {
		return 0, err
	}
	if width == 8 {
		return uintptr(binary.LittleEndian.Uint64(data)), nil
	}
	return uintptr(binary.LittleEndian.Uint32(data)), nil
}

// Value retains the original single-result interface and returns zero on error.
// Deprecated: use ReadValue to distinguish a zero value from an invalid address.
//
//go:uintptrescapes
func Value(addr uintptr) uintptr {
	value, _ := ReadValue(addr)
	return value
}

// ReadString reads a NUL-terminated byte string from current-process memory.
// maxLength bounds the number of bytes examined, including the terminator, and
// must be in 1..65536. Missing terminators and unreadable memory return errors.
//
//go:uintptrescapes
func ReadString(addr uintptr, maxLength int) (string, error) {
	if maxLength < 1 || maxLength > maxReadStringLength {
		return "", fmt.Errorf("%w: string limit must be 1..%d", ErrInvalidLimit, maxReadStringLength)
	}
	data := make([]byte, 0, minStringCapacity(maxLength))
	for i := 0; i < maxLength; i++ {
		if addr > ^uintptr(0)-uintptr(i) {
			return "", ErrInvalidAddress
		}
		current, err := readProcessMemory(addr+uintptr(i), 1)
		if err != nil {
			return "", err
		}
		if current[0] == 0 {
			return string(data), nil
		}
		data = append(data, current[0])
	}
	return "", fmt.Errorf("%w: string is not NUL-terminated within %d bytes", ErrInvalidLimit, maxLength)
}

func minStringCapacity(limit int) int {
	if limit > 256 {
		return 256
	}
	return limit
}

// Strptr retains the original 255-byte string-read limit and returns an empty
// string on error. Deprecated: use ReadString to receive errors explicitly.
//
//go:uintptrescapes
func Strptr(offset uintptr) string {
	value, _ := ReadString(offset, 255)
	return value
}

// Hex prints a value in hexadecimal, retaining the original helper interface.
func Hex(addr interface{}) {
	fmt.Printf("%x\n", addr)
}

// BeepF retains the original native-call helper. It discards call errors.
// Deprecated: use ExportFunc.Call to receive call results and errors.
//
//go:uintptrescapes
func BeepF(addr uintptr, volume int, timestep int) {
	fn := ExportFunc{Name: "Beep", Addr: addr}
	_, _, _ = fn.Call(uintptr(volume), uintptr(timestep))
	time.Sleep(time.Microsecond * 270)
}
