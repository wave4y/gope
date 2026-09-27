package gope

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_DIRECTORY_ENTRY_EXPORT     = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT     = 1
)

type WORD uint16
type DWORD uint32
type LONG int32
type BYTE uint8
type ULONGLONG uint64

// PVOID retains the legacy 32-bit representation. Use uintptr for native addresses.
// Deprecated: this type cannot represent a native pointer on 64-bit Windows.
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

// PE64 describes a loaded PE32+ image. Public headers are independent snapshots;
// changing them does not change the bounds or metadata used by this reader.
type PE64 struct {
	DllBase   uintptr
	dosbase   uintptr
	DosHeader *IMAGE_DOS_HEADER
	NtHeaders *IMAGE_NT_HEADERS64
	Export    *IMAGE_EXPORT_DIRECTORY
	Import    *IMAGE_IMPORT_DESCRIPTOR

	reader          func(offset uint32, size uint32) ([]byte, error)
	baseAddr        uintptr
	size            uint32
	exportDirectory IMAGE_DATA_DIRECTORY
	exportHeader    IMAGE_EXPORT_DIRECTORY
	hasExports      bool
}

// ExportFunc preserves the original callable-export representation.
type ExportFunc struct {
	Name string
	Addr uintptr
}

// ExportInfo describes a named or ordinal-only export. Name is empty for an
// ordinal-only export. Forwarders have Address zero and Forwarder set; no DLL
// is loaded and no forwarder is resolved automatically. Data exports may also
// have a nonzero Address: the caller must know whether an export is callable.
type ExportInfo struct {
	Name      string
	Ordinal   uint32
	RVA       uint32
	Address   uintptr
	Forwarder string
}
