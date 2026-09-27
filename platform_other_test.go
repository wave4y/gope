//go:build !windows || !amd64
// +build !windows !amd64

package gope_test

import (
	"errors"
	"testing"

	"github.com/wave4y/gope"
)

func TestUnsupportedPlatformOperations(t *testing.T) {
	// A nonzero address reaches platform capability checks; no memory is read
	// and no native function is called on an unsupported target.
	if pe, err := gope.OpenPE64(1); !errors.Is(err, gope.ErrUnsupportedPlatform) || pe != nil {
		t.Errorf("OpenPE64 = %v, %v", pe, err)
	}
	if pe := gope.NewPE64(1); pe != nil {
		t.Error("legacy NewPE64 unexpectedly succeeded")
	}
	if value, err := gope.ReadValue(1); !errors.Is(err, gope.ErrUnsupportedPlatform) || value != 0 {
		t.Errorf("ReadValue = %#x, %v", value, err)
	}
	if text, err := gope.ReadString(1, 16); !errors.Is(err, gope.ErrUnsupportedPlatform) || text != "" {
		t.Errorf("ReadString = %q, %v", text, err)
	}
	if value := gope.Value(1); value != 0 {
		t.Errorf("legacy Value = %#x", value)
	}
	if text := gope.Strptr(1); text != "" {
		t.Errorf("legacy Strptr = %q", text)
	}
}

func TestUnsupportedPlatformCall(t *testing.T) {
	for name, proc := range map[string]*gope.ExportFunc{"nil": nil, "zero address": {}} {
		t.Run(name, func(t *testing.T) {
			r1, r2, err := proc.Call()
			if !errors.Is(err, gope.ErrUnsupportedPlatform) || r1 != 0 || r2 != 0 {
				t.Fatalf("unsupported Call = %#x, %#x, %v", r1, r2, err)
			}
		})
	}
}
