//go:build windows && amd64
// +build windows,amd64

package gope

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var readProcessMemoryProc = syscall.NewLazyDLL("kernel32.dll").NewProc("ReadProcessMemory")

const maxMemoryRead = 32 << 20

// readProcessMemory copies current-process memory through Windows so inaccessible
// pages produce an error instead of an unchecked Go pointer dereference.
func readProcessMemory(address uintptr, size uint32) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	if size > maxMemoryRead {
		return nil, fmt.Errorf("%w: memory read exceeds %d bytes", ErrInvalidLimit, maxMemoryRead)
	}
	if address == 0 || address > ^uintptr(0)-uintptr(size-1) {
		return nil, ErrInvalidAddress
	}
	if err := readProcessMemoryProc.Find(); err != nil {
		return nil, fmt.Errorf("gope: ReadProcessMemory: %w", err)
	}
	buffer := make([]byte, int(size))
	var bytesRead uintptr
	result, _, callErr := readProcessMemoryProc.Call(
		^uintptr(0), // GetCurrentProcess pseudo-handle.
		address,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	runtime.KeepAlive(buffer)
	if result == 0 {
		return nil, fmt.Errorf("%w: ReadProcessMemory at %#x: %v", ErrInvalidAddress, address, callErr)
	}
	if bytesRead != uintptr(size) {
		return nil, fmt.Errorf("%w: ReadProcessMemory returned %d of %d bytes", ErrInvalidAddress, bytesRead, size)
	}
	return buffer, nil
}
