//go:build windows && amd64
// +build windows,amd64

package gope

import "syscall"

// Call invokes a native function using the Windows amd64 calling convention.
// The caller must keep the owning module loaded and supply the correct ABI and
// argument types. A nonzero Windows last-error value is returned unchanged; its
// meaning depends on the called function's documented return-value contract.
//
//go:uintptrescapes
func (p *ExportFunc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	if p == nil || p.Addr == 0 {
		return 0, 0, ErrInvalidAddress
	}
	if len(a) > 18 {
		return 0, 0, ErrTooManyArguments
	}
	var args [18]uintptr
	copy(args[:], a)
	n := uintptr(len(a))
	var errno syscall.Errno
	switch {
	case len(a) <= 3:
		r1, r2, errno = syscall.Syscall(p.Addr, n, args[0], args[1], args[2])
	case len(a) <= 6:
		r1, r2, errno = syscall.Syscall6(p.Addr, n, args[0], args[1], args[2], args[3], args[4], args[5])
	case len(a) <= 9:
		r1, r2, errno = syscall.Syscall9(p.Addr, n, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8])
	case len(a) <= 12:
		r1, r2, errno = syscall.Syscall12(p.Addr, n, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11])
	case len(a) <= 15:
		r1, r2, errno = syscall.Syscall15(p.Addr, n, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14])
	default:
		r1, r2, errno = syscall.Syscall18(p.Addr, n, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15], args[16], args[17])
	}
	if errno != 0 {
		lastErr = errno
	}
	return
}
