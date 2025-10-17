package wz

// Header is the header of a WZ file.
type Header struct {
	Magic      [4]byte // "PKG1" for valid WZ files
	FileSize   uint64  // the file size
	DataOffset uint32  // where the body starts
	Copyright  string  // the copyright string
}
