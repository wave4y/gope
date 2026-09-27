package gope

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const fixtureBase uintptr = 0x10000000

func put16(image []byte, offset int, value uint16) {
	binary.LittleEndian.PutUint16(image[offset:offset+2], value)
}
func put32(image []byte, offset int, value uint32) {
	binary.LittleEndian.PutUint32(image[offset:offset+4], value)
}

func mappedFixture() []byte {
	image := make([]byte, 0x2000)
	put16(image, 0, 0x5a4d)
	put32(image, 60, 0x80)
	put32(image, 0x80, 0x00004550)
	put16(image, 0x84, 0x8664)
	put16(image, 0x94, 240)
	put16(image, 0x98, 0x20b)
	image[0x9a] = 250
	put32(image, 0x98+32, 0x1000)
	put32(image, 0x98+36, 0x200)
	put32(image, 0x98+56, uint32(len(image)))
	put32(image, 0x98+60, 0x200)
	put32(image, 0x98+108, 16)
	put32(image, 0x98+112, 0x400)
	put32(image, 0x98+116, 0x300)
	put32(image, 0x400+12, 0x480)
	put32(image, 0x400+16, 7)
	put32(image, 0x400+20, 4)
	put32(image, 0x400+24, 2)
	put32(image, 0x400+28, 0x440)
	put32(image, 0x400+32, 0x460)
	put32(image, 0x400+36, 0x470)
	put32(image, 0x440, 0x1100)
	put32(image, 0x444, 0)
	put32(image, 0x448, 0x1000)
	put32(image, 0x44c, 0x1200)
	put32(image, 0x460, 0x500)
	put32(image, 0x464, 0x510)
	put16(image, 0x470, 2)
	put16(image, 0x472, 0)
	copy(image[0x480:], "fixture.dll\x00")
	copy(image[0x500:], "Alpha\x00")
	copy(image[0x510:], "Zulu\x00")
	return image
}

func fixtureReader(image []byte) func(uint32, uint32) ([]byte, error) {
	return func(offset, size uint32) ([]byte, error) {
		end := uint64(offset) + uint64(size)
		if end > uint64(len(image)) {
			return nil, ErrInvalidAddress
		}
		return image[int(offset):int(end)], nil
	}
}

func openFixture(t *testing.T, image []byte) *PE64 {
	t.Helper()
	pe, err := openPE64(fixtureBase, fixtureReader(image))
	if err != nil {
		t.Fatal(err)
	}
	return pe
}

func TestExportsUseNameOrdinalsAndSkipEmptySlots(t *testing.T) {
	pe := openFixture(t, mappedFixture())
	got, err := pe.Exports()
	if err != nil {
		t.Fatal(err)
	}
	want := []ExportInfo{
		{Name: "Alpha", Ordinal: 9, RVA: 0x1000, Address: fixtureBase + 0x1000},
		{Name: "Zulu", Ordinal: 7, RVA: 0x1100, Address: fixtureBase + 0x1100},
		{Ordinal: 10, RVA: 0x1200, Address: fixtureBase + 0x1200},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exports = %#v, want %#v", got, want)
	}
	named := pe.GetExportFunctions()
	if !reflect.DeepEqual(named, []ExportFunc{{"Alpha", fixtureBase + 0x1000}, {"Zulu", fixtureBase + 0x1100}}) {
		t.Fatalf("compatibility exports = %#v", named)
	}
	if proc, err := pe.FindProc("Alpha"); err != nil || proc.Addr != fixtureBase+0x1000 {
		t.Fatalf("named lookup: %#v, %v", proc, err)
	}
	if proc, err := pe.FindOrdinal(10); err != nil || proc.Name != "" || proc.Addr != fixtureBase+0x1200 {
		t.Fatalf("ordinal-only lookup: %#v, %v", proc, err)
	}
	for _, ordinal := range []uint32{6, 8, 11, ^uint32(0)} {
		if _, err := pe.FindOrdinal(ordinal); !errors.Is(err, ErrNotFound) {
			t.Fatalf("ordinal %d: %v", ordinal, err)
		}
	}
	for _, name := range []string{"", "alpha", "missing", "Alpha\x00"} {
		if _, err := pe.FindProc(name); !errors.Is(err, ErrNotFound) {
			t.Fatalf("name %q: %v", name, err)
		}
	}
	if got := pe.NewProc("missing"); got != (ExportFunc{}) {
		t.Fatalf("missing legacy proc = %#v", got)
	}
	if pe.NtHeaders.OptionalHeader.MajorLinkerVersion != BYTE(250) {
		t.Fatal("BYTE lost unsigned value")
	}
}

func TestExportsAllowAliasesAndOrdinalOnlyTables(t *testing.T) {
	t.Run("more names than addresses", func(t *testing.T) {
		image := mappedFixture()
		put32(image, 0x400+20, 1)
		put16(image, 0x470, 0)
		put16(image, 0x472, 0)
		got, err := openFixture(t, image).Exports()
		if err != nil || len(got) != 2 || got[0].Address != got[1].Address || got[0].Ordinal != got[1].Ordinal {
			t.Fatalf("aliases = %#v, %v", got, err)
		}
	})
	t.Run("ordinal-only", func(t *testing.T) {
		image := mappedFixture()
		put32(image, 0x400+24, 0)
		put32(image, 0x400+32, ^uint32(0))
		put32(image, 0x400+36, ^uint32(0))
		pe := openFixture(t, image)
		got, err := pe.Exports()
		if err != nil || len(got) != 3 {
			t.Fatalf("ordinal-only = %#v, %v", got, err)
		}
		for _, info := range got {
			if info.Name != "" {
				t.Fatal("unexpected named export")
			}
		}
		if len(pe.GetExportFunctions()) != 0 {
			t.Fatal("legacy names should be empty")
		}
	})
	t.Run("empty address table", func(t *testing.T) {
		image := mappedFixture()
		for offset := 0x440; offset < 0x450; offset += 4 {
			put32(image, offset, 0)
		}
		got, err := openFixture(t, image).Exports()
		if err != nil || len(got) != 0 {
			t.Fatalf("empty slots = %#v, %v", got, err)
		}
	})
}

func TestForwardedExportsRemainMetadata(t *testing.T) {
	image := mappedFixture()
	put32(image, 0x448, 0x600)
	copy(image[0x600:], "OTHER.Real\x00")
	pe := openFixture(t, image)
	got, err := pe.Exports()
	if err != nil || len(got) != 3 {
		t.Fatalf("exports = %#v, %v", got, err)
	}
	if got[0].Forwarder != "OTHER.Real" || got[0].Address != 0 || got[0].RVA != 0x600 {
		t.Fatalf("forwarder = %#v", got[0])
	}
	if _, err := pe.FindProc("Alpha"); !errors.Is(err, ErrForwardedExport) {
		t.Fatalf("lookup: %v", err)
	}
	if _, err := pe.FindOrdinal(9); !errors.Is(err, ErrForwardedExport) {
		t.Fatalf("ordinal lookup: %v", err)
	}
	if pe.NewProc("Alpha") != (ExportFunc{}) {
		t.Fatal("legacy forwarder must not expose a callable address")
	}
	if direct := pe.GetExportFunctions(); len(direct) != 1 || direct[0].Name != "Zulu" {
		t.Fatalf("direct exports = %#v", direct)
	}
}

func TestOptionalDirectoriesAndSnapshotOwnership(t *testing.T) {
	t.Run("no directories", func(t *testing.T) {
		image := mappedFixture()
		put16(image, 0x94, 112)
		put32(image, 0x98+108, 0)
		pe := openFixture(t, image)
		if pe.Export != nil || pe.Import != nil {
			t.Fatal("undeclared directories must be absent")
		}
		if pe.NtHeaders.OptionalHeader.DataDirectory[0] != (IMAGE_DATA_DIRECTORY{}) {
			t.Fatal("undeclared bytes leaked into snapshot")
		}
		if got, err := pe.Exports(); err != nil || len(got) != 0 {
			t.Fatalf("no exports = %#v, %v", got, err)
		}
	})
	t.Run("zero directories", func(t *testing.T) {
		image := mappedFixture()
		put32(image, 0x98+112, 0)
		put32(image, 0x98+116, 0)
		pe := openFixture(t, image)
		if pe.Export != nil || pe.Import != nil {
			t.Fatal("zero directories must be absent")
		}
	})
	t.Run("one directory", func(t *testing.T) {
		image := mappedFixture()
		put16(image, 0x94, 120)
		put32(image, 0x98+108, 1)
		put32(image, 0x98+120, ^uint32(0))
		put32(image, 0x98+124, ^uint32(0))
		pe := openFixture(t, image)
		if pe.Export == nil || pe.Import != nil {
			t.Fatal("directory count ignored")
		}
	})
	t.Run("extended optional header", func(t *testing.T) {
		image := mappedFixture()
		put16(image, 0x94, 248)
		put32(image, 0x98+108, 17)
		if _, err := openPE64(fixtureBase, fixtureReader(image)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("snapshot mutation", func(t *testing.T) {
		image := mappedFixture()
		put32(image, 0x98+120, 0x700)
		put32(image, 0x98+124, 20)
		pe := openFixture(t, image)
		before, err := pe.Exports()
		if err != nil {
			t.Fatal(err)
		}
		pe.DllBase = ^uintptr(0)
		*pe.DosHeader = IMAGE_DOS_HEADER{}
		*pe.NtHeaders = IMAGE_NT_HEADERS64{}
		*pe.Export = IMAGE_EXPORT_DIRECTORY{}
		*pe.Import = IMAGE_IMPORT_DESCRIPTOR{}
		after, err := pe.Exports()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("public mutation changed parser: %#v, %v", after, err)
		}
	})
}

func TestPE64RejectsMalformedHeadersAndTables(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"MZ", func(b []byte) { put16(b, 0, 0) }},
		{"negative e_lfanew", func(b []byte) { put32(b, 60, ^uint32(0)) }},
		{"e_lfanew overlaps DOS", func(b []byte) { put32(b, 60, 32) }},
		{"PE signature", func(b []byte) { put32(b, 0x80, 0) }},
		{"PE32 magic", func(b []byte) { put16(b, 0x98, 0x10b) }},
		{"short optional header", func(b []byte) { put16(b, 0x94, 111) }},
		{"directory count exceeds header", func(b []byte) { put32(b, 0x98+108, 17) }},
		{"directory count overflow", func(b []byte) { put32(b, 0x98+108, ^uint32(0)) }},
		{"zero image", func(b []byte) { put32(b, 0x98+56, 0) }},
		{"oversized image", func(b []byte) { put32(b, 0x98+56, maxImageSize+1) }},
		{"short declared headers", func(b []byte) { put32(b, 0x98+60, 0x100) }},
		{"headers outside image", func(b []byte) { put32(b, 0x98+60, 0x3000) }},
		{"sections exceed headers", func(b []byte) { put16(b, 0x86, 100) }},
		{"zero export RVA with size", func(b []byte) { put32(b, 0x98+112, 0) }},
		{"zero export size with RVA", func(b []byte) { put32(b, 0x98+116, 0) }},
		{"short export directory", func(b []byte) { put32(b, 0x98+116, 39) }},
		{"export range overflow", func(b []byte) { put32(b, 0x98+116, ^uint32(0)) }},
		{"import range overflow", func(b []byte) { put32(b, 0x98+120, 0x700); put32(b, 0x98+124, ^uint32(0)) }},
		{"short import directory", func(b []byte) { put32(b, 0x98+120, 0x700); put32(b, 0x98+124, 19) }},
		{"functions limit", func(b []byte) { put32(b, 0x400+20, maxExportEntries+1) }},
		{"names limit", func(b []byte) { put32(b, 0x400+24, maxExportEntries+1) }},
		{"names without functions", func(b []byte) { put32(b, 0x400+20, 0) }},
		{"biased ordinal overflow", func(b []byte) { put32(b, 0x400+16, ^uint32(0)) }},
		{"missing address table", func(b []byte) { put32(b, 0x400+28, 0) }},
		{"address table outside image", func(b []byte) { put32(b, 0x400+28, 0x1ffd) }},
		{"name table outside image", func(b []byte) { put32(b, 0x400+32, ^uint32(0)) }},
		{"ordinal table outside image", func(b []byte) { put32(b, 0x400+36, 0x1fff) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			image := mappedFixture()
			test.mutate(image)
			if _, err := openPE64(fixtureBase, fixtureReader(image)); !errors.Is(err, ErrInvalidPE) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestExportsRejectMalformedSymbolContents(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"ordinal index", func(b []byte) { put16(b, 0x470, 4) }},
		{"zero name RVA", func(b []byte) { put32(b, 0x460, 0) }},
		{"name RVA outside image", func(b []byte) { put32(b, 0x460, ^uint32(0)) }},
		{"empty name", func(b []byte) { b[0x500] = 0 }},
		{"unterminated name", func(b []byte) { put32(b, 0x460, 0x1ffe); b[0x1ffe] = 'a'; b[0x1fff] = 'b' }},
		{"function RVA outside image", func(b []byte) { put32(b, 0x448, 0x2000) }},
		{"empty forwarder", func(b []byte) { put32(b, 0x448, 0x600) }},
		{"unterminated forwarder", func(b []byte) { put32(b, 0x448, 0x6fe); b[0x6fe] = 'a'; b[0x6ff] = 'b' }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			image := mappedFixture()
			test.mutate(image)
			pe := openFixture(t, image)
			if _, err := pe.Exports(); !errors.Is(err, ErrInvalidPE) {
				t.Fatalf("error = %v", err)
			}
			if got := pe.GetExportFunctions(); got != nil {
				t.Fatal("legacy result must not contain partial exports")
			}
		})
	}
}

func TestExportStringBoundsAndBudget(t *testing.T) {
	t.Run("long name", func(t *testing.T) {
		image := mappedFixture()
		name := strings.Repeat("x", 300)
		put32(image, 0x460, 0x800)
		copy(image[0x800:], name+"\x00")
		got, err := openFixture(t, image).Exports()
		if err != nil || got[0].Name != name {
			t.Fatalf("long name lost: %v", err)
		}
	})
	t.Run("terminator at forwarder boundary", func(t *testing.T) {
		image := mappedFixture()
		put32(image, 0x448, 0x6fa)
		copy(image[0x6fa:], "A.B#1\x00")
		got, err := openFixture(t, image).Exports()
		if err != nil || got[0].Forwarder != "A.B#1" {
			t.Fatalf("boundary forwarder = %#v, %v", got, err)
		}
	})
	for _, length := range []int{int(maxExportString) - 1, int(maxExportString)} {
		t.Run("per-string limit "+strconv.Itoa(length), func(t *testing.T) {
			image := make([]byte, 0x20000)
			copy(image, mappedFixture())
			put32(image, 0x98+56, uint32(len(image)))
			put32(image, 0x460, 0x800)
			copy(image[0x800:], strings.Repeat("x", length)+"\x00")
			got, err := openFixture(t, image).Exports()
			if length < int(maxExportString) {
				if err != nil || len(got[0].Name) != length {
					t.Fatalf("valid limit: %v", err)
				}
			} else if !errors.Is(err, ErrInvalidPE) {
				t.Fatalf("oversized name: %v", err)
			}
		})
	}
	t.Run("aggregate read budget", func(t *testing.T) {
		image := make([]byte, 0x20000)
		copy(image, mappedFixture())
		put32(image, 0x98+56, uint32(len(image)))
		put32(image, 0x400+24, 300)
		put32(image, 0x400+32, 0x1000)
		put32(image, 0x400+36, 0x2000)
		for i := 0; i < 300; i++ {
			put32(image, 0x1000+i*4, 0x3000)
			put16(image, 0x2000+i*2, 2)
		}
		copy(image[0x3000:], strings.Repeat("x", int(maxExportString)-1)+"\x00")
		if _, err := openFixture(t, image).Exports(); !errors.Is(err, ErrInvalidPE) || !strings.Contains(err.Error(), "budget") {
			t.Fatalf("budget error = %v", err)
		}
	})
	t.Run("terminator before unreadable region", func(t *testing.T) {
		image := mappedFixture()
		put32(image, 0x460, 0x800)
		copy(image[0x800:], "A\x00")
		read := fixtureReader(image)
		pe, err := openPE64(fixtureBase, func(offset, size uint32) ([]byte, error) {
			if offset >= 0x800 && offset < 0x900 && uint64(offset)+uint64(size) > 0x802 {
				return nil, ErrInvalidAddress
			}
			return read(offset, size)
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := pe.Exports()
		if err != nil || got[0].Name != "A" {
			t.Fatalf("bounded string = %#v, %v", got, err)
		}
	})
}

func TestPE64ReaderFailuresAndUninitializedValues(t *testing.T) {
	image := mappedFixture()
	if _, err := openPE64(0, fixtureReader(image)); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("zero base: %v", err)
	}
	if _, err := openPE64(^uintptr(0)-63, fixtureReader(image)); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("overflow base: %v", err)
	}
	if _, err := openPE64(fixtureBase, nil); !errors.Is(err, ErrInvalidPE) {
		t.Fatalf("nil reader: %v", err)
	}
	if _, err := openPE64(fixtureBase, func(uint32, uint32) ([]byte, error) { return nil, ErrInvalidAddress }); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("read error: %v", err)
	}
	if _, err := openPE64(fixtureBase, func(uint32, uint32) ([]byte, error) { return []byte{0}, nil }); !errors.Is(err, ErrInvalidPE) {
		t.Fatalf("short read: %v", err)
	}
	if _, err := openPE64(fixtureBase, fixtureReader(image[:128])); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("truncated image: %v", err)
	}
	for _, pe := range []*PE64{nil, {}} {
		if _, err := pe.Exports(); !errors.Is(err, ErrInvalidPE) {
			t.Fatalf("uninitialized: %v", err)
		}
		if pe.NewProc("anything") != (ExportFunc{}) {
			t.Fatal("legacy lookup exposed invalid proc")
		}
	}
	if pe := NewPE64(0); pe != nil {
		t.Fatal("legacy constructor must reject zero address")
	}
	if _, err := OpenPE64(0); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("public constructor: %v", err)
	}
	read := fixtureReader(image)
	pe, err := openPE64(fixtureBase, func(offset, size uint32) ([]byte, error) {
		if offset == 0x440 {
			return []byte{0}, nil
		}
		return read(offset, size)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pe.Exports(); !errors.Is(err, ErrInvalidPE) {
		t.Fatalf("short table read: %v", err)
	}
}

func TestPublicHeaderLayout(t *testing.T) {
	for _, test := range []struct {
		value interface{}
		size  uintptr
	}{
		{IMAGE_DOS_HEADER{}, 64}, {IMAGE_FILE_HEADER{}, 20}, {IMAGE_OPTIONAL_HEADER64{}, 240},
		{IMAGE_NT_HEADERS64{}, 264}, {IMAGE_EXPORT_DIRECTORY{}, 40}, {IMAGE_IMPORT_DESCRIPTOR{}, 20},
	} {
		if got := reflect.TypeOf(test.value).Size(); got != test.size {
			t.Errorf("%T size=%d, want %d", test.value, got, test.size)
		}
	}
	optional := reflect.TypeOf(IMAGE_OPTIONAL_HEADER64{})
	for name, want := range map[string]uintptr{"ImageBase": 24, "SizeOfImage": 56, "NumberOfRvaAndSizes": 108, "DataDirectory": 112} {
		field, _ := optional.FieldByName(name)
		if field.Offset != want {
			t.Errorf("%s offset=%d, want %d", name, field.Offset, want)
		}
	}
	if reflect.TypeOf(BYTE(0)).Kind() != reflect.Uint8 {
		t.Fatal("BYTE must be unsigned")
	}
}
