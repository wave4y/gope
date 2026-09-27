//go:build windows && amd64
// +build windows,amd64

package gope_test

import (
	"errors"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"github.com/wave4y/gope"
)

func loadedWindowsDLL(t *testing.T, name string) *syscall.DLL {
	t.Helper()
	// These system DLLs are already loaded in a Windows Go process. LoadDLL
	// retains a loader reference until this test finishes.
	dll, err := syscall.LoadDLL(name)
	if err != nil {
		t.Fatalf("LoadDLL(%q): %v", name, err)
	}
	t.Cleanup(func() {
		if err := dll.Release(); err != nil {
			t.Errorf("Release(%q): %v", name, err)
		}
	})
	return dll
}

func TestWindowsExportsMatchLoaderAndOrdinals(t *testing.T) {
	dll := loadedWindowsDLL(t, "ntdll.dll")
	pe, err := gope.OpenPE64(uintptr(dll.Handle))
	if err != nil {
		t.Fatal(err)
	}
	if pe.DllBase != uintptr(dll.Handle) {
		t.Fatalf("module base = %#x, want %#x", pe.DllBase, dll.Handle)
	}
	exports, err := pe.Exports()
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]gope.ExportInfo)
	for _, export := range exports {
		if export.Name != "" {
			byName[export.Name] = export
		}
	}
	loader := loadedWindowsDLL(t, "kernel32.dll")
	getProcAddress, err := loader.FindProc("GetProcAddress")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"NtClose", "NtQueryInformationProcess", "RtlGetVersion", "RtlAllocateHeap"} {
		t.Run(name, func(t *testing.T) {
			export, ok := byName[name]
			if !ok {
				t.Fatalf("named export %q missing", name)
			}
			if export.Forwarder != "" {
				t.Fatalf("known direct ntdll export is forwarded to %q", export.Forwarder)
			}
			want, err := syscall.GetProcAddress(dll.Handle, name)
			if err != nil {
				t.Fatal(err)
			}
			if export.Address != want || export.Address != uintptr(dll.Handle)+uintptr(export.RVA) {
				t.Fatalf("address/RVA = %#x/%#x, loader address = %#x", export.Address, export.RVA, want)
			}
			// MAKEINTRESOURCE-style ordinal lookup independently checks the
			// name-ordinal index instead of assuming names and functions align.
			if uint64(export.Ordinal) > 0xffff {
				t.Fatalf("ordinal %d cannot be passed to GetProcAddress", export.Ordinal)
			}
			byOrdinal, _, _ := getProcAddress.Call(uintptr(dll.Handle), uintptr(export.Ordinal))
			if byOrdinal != want {
				t.Fatalf("ordinal %d resolves to %#x, want %#x", export.Ordinal, byOrdinal, want)
			}
			proc, err := pe.FindProc(name)
			if err != nil || proc.Name != name || proc.Addr != want {
				t.Fatalf("FindProc(%q) = %+v, %v; want address %#x", name, proc, err, want)
			}
			legacy := pe.NewProc(name)
			if legacy.Name != name || legacy.Addr != want {
				t.Fatalf("NewProc(%q) = %+v; want address %#x", name, legacy, want)
			}
		})
	}
	if _, err := pe.FindProc("gope_test_nonexistent_export_8f4adba3"); err == nil {
		t.Fatal("FindProc accepted an absent export")
	}
	missing := pe.NewProc("gope_test_nonexistent_export_8f4adba3")
	if missing.Addr != 0 {
		t.Fatalf("legacy missing export address = %#x", missing.Addr)
	}
	if _, _, err := missing.Call(); !errors.Is(err, gope.ErrInvalidAddress) {
		t.Fatalf("calling legacy missing export: %v", err)
	}
}

func TestWindowsSafeNativeCallAndGuards(t *testing.T) {
	dll := loadedWindowsDLL(t, "kernel32.dll")
	address, err := syscall.GetProcAddress(dll.Handle, "GetCurrentProcessId")
	if err != nil {
		t.Fatal(err)
	}
	proc := gope.ExportFunc{Name: "GetCurrentProcessId", Addr: address}
	// GetCurrentProcessId is read-only and does not define GetLastError on
	// success, so its return value is the success criterion.
	result, _, _ := proc.Call()
	if result != uintptr(os.Getpid()) {
		t.Fatalf("GetCurrentProcessId = %d, want %d", result, os.Getpid())
	}
	for name, invalid := range map[string]*gope.ExportFunc{
		"nil":          nil,
		"zero address": {},
	} {
		t.Run(name, func(t *testing.T) {
			r1, r2, err := invalid.Call()
			if !errors.Is(err, gope.ErrInvalidAddress) || r1 != 0 || r2 != 0 {
				t.Fatalf("invalid Call = %#x, %#x, %v", r1, r2, err)
			}
		})
	}
	r1, r2, err := proc.Call(make([]uintptr, 19)...)
	if !errors.Is(err, gope.ErrTooManyArguments) || r1 != 0 || r2 != 0 {
		t.Fatalf("19-argument Call = %#x, %#x, %v", r1, r2, err)
	}
}

func TestWindowsMemoryReads(t *testing.T) {
	word := uintptr(0xfedcba9876543210)
	text := []byte("gope memory\x00ignored")
	empty := []byte{0, 0xff}
	// A cleanup closure keeps these fixtures heap-backed through the complete
	// test; KeepAlive also brackets each conversion to a raw address.
	t.Cleanup(func() {
		runtime.KeepAlive(&word)
		runtime.KeepAlive(text)
		runtime.KeepAlive(empty)
	})
	address := uintptr(unsafe.Pointer(&word))
	value, err := gope.ReadValue(address)
	legacyValue := gope.Value(address)
	runtime.KeepAlive(&word)
	if err != nil || value != word || legacyValue != word {
		t.Fatalf("ReadValue/Value = %#x/%#x, %v; want %#x", value, legacyValue, err, word)
	}
	textAddress := uintptr(unsafe.Pointer(&text[0]))
	got, err := gope.ReadString(textAddress, len(text))
	legacyText := gope.Strptr(textAddress)
	runtime.KeepAlive(text)
	if err != nil || got != "gope memory" || legacyText != "gope memory" {
		t.Fatalf("ReadString/Strptr = %q/%q, %v", got, legacyText, err)
	}
	got, err = gope.ReadString(uintptr(unsafe.Pointer(&empty[0])), len(empty))
	runtime.KeepAlive(empty)
	if err != nil || got != "" {
		t.Fatalf("empty ReadString = %q, %v", got, err)
	}
	var unsignedByte gope.BYTE = 255
	if unsignedByte != 255 {
		t.Fatalf("BYTE lost unsigned value: %v", unsignedByte)
	}
}

func TestWindowsRejectsUnreadableMemory(t *testing.T) {
	// These are read probes only. Never attempt a native Call at an arbitrary
	// invalid address, since the invocation API cannot make that safe.
	for _, address := range []uintptr{0, 1, ^uintptr(0)} {
		if pe, err := gope.OpenPE64(address); err == nil || pe != nil {
			t.Errorf("OpenPE64(%#x) = %v, %v", address, pe, err)
		}
		if pe := gope.NewPE64(address); pe != nil {
			t.Errorf("NewPE64(%#x) unexpectedly succeeded", address)
		}
		if value, err := gope.ReadValue(address); err == nil || value != 0 {
			t.Errorf("ReadValue(%#x) = %#x, %v", address, value, err)
		}
		if text, err := gope.ReadString(address, 16); err == nil || text != "" {
			t.Errorf("ReadString(%#x) = %q, %v", address, text, err)
		}
		if value := gope.Value(address); value != 0 {
			t.Errorf("Value(%#x) = %#x", address, value)
		}
		if text := gope.Strptr(address); text != "" {
			t.Errorf("Strptr(%#x) = %q", address, text)
		}
	}
}

func TestWindowsRejectsForwardedExports(t *testing.T) {
	dll := loadedWindowsDLL(t, "kernel32.dll")
	pe, err := gope.OpenPE64(uintptr(dll.Handle))
	if err != nil {
		t.Fatal(err)
	}
	exports, err := pe.Exports()
	if err != nil {
		t.Fatal(err)
	}
	for _, export := range exports {
		if export.Name == "" || export.Forwarder == "" {
			continue
		}
		proc, err := pe.FindProc(export.Name)
		if !errors.Is(err, gope.ErrForwardedExport) || proc.Addr != 0 {
			t.Fatalf("forwarded FindProc(%q) = %+v, %v", export.Name, proc, err)
		}
		if proc := pe.NewProc(export.Name); proc.Addr != 0 {
			t.Fatalf("legacy forwarder %q exposed callable address %#x", export.Name, proc.Addr)
		}
		return
	}
	t.Skip("this kernel32.dll contains no named forwarded exports")
}

func TestWindowsStringReadBounds(t *testing.T) {
	text := []byte("bounded\x00")
	t.Cleanup(func() { runtime.KeepAlive(text) })
	address := uintptr(unsafe.Pointer(&text[0]))
	for _, limit := range []int{-1, 0, 65537, len(text) - 1} {
		value, err := gope.ReadString(address, limit)
		runtime.KeepAlive(text)
		if !errors.Is(err, gope.ErrInvalidLimit) || value != "" {
			t.Errorf("ReadString(limit=%d) = %q, %v", limit, value, err)
		}
	}
	value, err := gope.ReadString(address, len(text))
	runtime.KeepAlive(text)
	if err != nil || value != "bounded" {
		t.Fatalf("ReadString including final terminator = %q, %v", value, err)
	}
}

func TestWindowsCallArgumentForwarding(t *testing.T) {
	wordType := reflect.TypeOf(uintptr(0))
	for count := 0; count <= 18; count++ {
		t.Run(strconv.Itoa(count)+" arguments", func(t *testing.T) {
			parameterTypes := make([]reflect.Type, count)
			arguments := make([]uintptr, count)
			for i := range arguments {
				parameterTypes[i] = wordType
				// Distinct values and set high bits detect reordered or truncated arguments.
				arguments[i] = 1<<32 + uintptr(0x101*(i+1)+3*count)
			}
			callback := reflect.MakeFunc(reflect.FuncOf(parameterTypes, []reflect.Type{wordType}, false), func(values []reflect.Value) []reflect.Value {
				sum := uintptr(17)
				for i, value := range values {
					sum += uintptr(i+1) * uintptr(value.Uint())
				}
				return []reflect.Value{reflect.ValueOf(sum)}
			})
			proc := gope.ExportFunc{Name: "weightedSum", Addr: syscall.NewCallback(callback.Interface())}
			got, _, _ := proc.Call(arguments...)
			runtime.KeepAlive(callback)
			// Independent closed-form sums of i and i*i, including the zero-argument case.
			n := uint64(count)
			want := uintptr(17 + (1<<32+3*n)*n*(n+1)/2 + 0x101*n*(n+1)*(2*n+1)/6)
			if got != want {
				t.Fatalf("Call(%d arguments) = %#x, want %#x", count, got, want)
			}
		})
	}
}
