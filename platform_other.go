//go:build !windows || !amd64
// +build !windows !amd64

package gope

func readProcessMemory(address uintptr, size uint32) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}

// Call is available only on Windows amd64.
//
//go:uintptrescapes
func (p *ExportFunc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	return 0, 0, ErrUnsupportedPlatform
}
