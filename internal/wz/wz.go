package wz

// Header is the header of a WZ file.
type Header struct {
	Magic      [4]byte // "PKG1" for valid WZ files
	BodySize   uint64  // size of data section (from BodyOffset to EOF)
	BodyOffset uint32  // where the data section starts
	Copyright  string
}

type Dir struct {
	EntryCount      int32
	EntriesMetadata []DirEntryMetadata
}

// DirEntryMetadata contains metadata for a single directory entry.
// All encrypted fields are stored in decrypted form after reading.
type DirEntryMetadata struct {
	Type       DirEntryType
	Name       string // Entry name (decrypted)
	FileSize   int32  // Size in bytes
	Checksum   int32  // Validation checksum
	DataOffset uint32 // Absolute file offset to entry data (decrypted)
}

type DirEntryType byte

const (
	// DirEntryTypeIgnore (0x01) indicates that the data for this entry
	// should be ignored. The next 10 bytes after discovering this byte
	// should be skipped.
	DirEntryTypeIgnore DirEntryType = iota + 1
	// DirEntryTypeReference (0x02) indicates that the data for this entry is stored
	// at another location in the file, probably for deduplication purposes.
	// The next read after discovering this byte will be an int32
	// indicating the offset (relative to Header.BodyOffset) where the
	// underlying type is located.
	//
	// [0x02][name_offset(int32)][size(compressed int32)][checksum(compressed int32)][data_offset(compressed int32)]
	DirEntryTypeReference
	// DirEntryTypeDir (0x03) indicates that this entry is a subdirectory.
	// [0x03][name(string)][size(compressed int32)][checksum(compressed int32)][data_offset(compressed int32)]
	DirEntryTypeDir
	// DirEntryTypeFile (0x04) indicates that this entry is a data file.
	// [0x04][name(string)][size(compressed int32)][checksum(compressed int32)][data_offset(compressed int32)]
	DirEntryTypeFile
)
