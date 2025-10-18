package parser

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/ossyrian/mintyparse/internal/config"
	"github.com/ossyrian/mintyparse/internal/wz"
)

// WzReader reads information from WZ files.
type WzReader struct {
	file   io.ReadSeeker
	config *config.Config
	logger *slog.Logger
	header *wz.Header // WZ file header

	// versionHeader is used to calculate the version hash,
	// which is required for offset decryption. For files without a version header,
	// versionHeader will be 0 and requires version number bruteforce (770-779).
	versionHeader uint16 // Version header (obfuscated checksum), 0 if no version header
}

// ReadHeader reads header information from a WZ file.
// This function will read at least 16 bytes of data,
// and will raise an error if the first 4 bytes read
// are not magic (wz.Magic).
func (r *WzReader) ReadHeader() (*wz.Header, error) {
	h := &wz.Header{}

	if _, err := io.ReadFull(r.file, h.Magic[:]); err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}
	if h.Magic != wz.Magic {
		return nil, fmt.Errorf("invalid WZ magic: expected %q, got %q",
			wz.Magic, h.Magic)
	}

	if err := binary.Read(r.file, binary.LittleEndian, &h.BodySize); err != nil {
		return nil, fmt.Errorf("failed to read body size: %w", err)
	}

	if err := binary.Read(r.file, binary.LittleEndian, &h.BodyOffset); err != nil {
		return nil, fmt.Errorf("failed to read body offset: %w", err)
	}

	// read everything from current position to BodyOffset
	pos, _ := r.file.Seek(0, io.SeekCurrent)
	remainingHeaderBytes := int(h.BodyOffset) - int(pos)
	if remainingHeaderBytes < 0 {
		return nil, fmt.Errorf("invalid BodyOffset: %d", h.BodyOffset)
	}

	headerData := make([]byte, remainingHeaderBytes)
	if _, err := io.ReadFull(r.file, headerData); err != nil {
		return nil, fmt.Errorf("failed to read header data: %w", err)
	}

	// extract copyright as ASCII
	copyrightEnd := 0
	for i, b := range headerData {
		if b == 0 || b < 32 || b > 126 {
			copyrightEnd = i
			break
		}
	}
	if copyrightEnd == 0 {
		copyrightEnd = len(headerData)
	}
	h.Copyright = string(headerData[:copyrightEnd])

	r.logger.Info("header is valid",
		"magic", h.Magic,
		"body_size", h.BodySize,
		"body_offset", h.BodyOffset,
		"copyright", h.Copyright,
	)

	r.header = h
	return h, nil
}

// DetectFormat determines whether the WZ file has a version header.
// Returns true if the file has a version header.
func (r *WzReader) DetectFormat() (hasVersionHeader bool, err error) {
	defer func() {
		if _, seekErr := r.file.Seek(int64(r.header.BodyOffset), io.SeekStart); seekErr != nil && err == nil {
			err = fmt.Errorf("failed to seek back to data offset: %w", seekErr)
		}
	}()

	// Read 2 bytes at data offset to check for version header
	var versionCheck uint16
	if err := binary.Read(r.file, binary.LittleEndian, &versionCheck); err != nil {
		return false, fmt.Errorf("failed to read version check bytes: %w", err)
	}

	// Default: assume has version header
	hasVersionHeader = true

	if versionCheck > 0xFF {
		// no version header present
		// version headers are single-byte values, so > 255 means no header
		hasVersionHeader = false
		r.logger.Debug("detected format without version header (value > 255)",
			"check_value", versionCheck,
		)
	} else if versionCheck == 0x80 {
		// special case: 0x80 is the compressed int marker
		// could be a version header OR the start of a compressed int
		// check if it looks like a valid compressed int pattern: 80 00 xx xx

		// seek back to data offset and read as compressed int
		if _, err := r.file.Seek(int64(r.header.BodyOffset), io.SeekStart); err != nil {
			return false, fmt.Errorf("failed to seek to data offset: %w", err)
		}

		var entryCount int32
		if err := wz.ReadCompressedInt32(r.file, &entryCount); err != nil {
			return false, fmt.Errorf("failed to read entry count: %w", err)
		}

		// check if it looks like a valid directory entry count
		// if the compressed int decoded to a reasonable value, no version header present
		// entry counts are typically small positive numbers
		if entryCount > 0 && entryCount <= 0xFFFF {
			hasVersionHeader = false
			r.logger.Debug("detected format without version header (compressed int pattern)",
				"entry_count", entryCount)
		} else {
			r.logger.Debug("detected format with version header (0x80 value)",
				"version_header", versionCheck)
		}
	} else {
		// version header present (values 0x00-0x7F, 0x81-0xFF)
		r.logger.Debug("detected format with version header",
			"version_header", versionCheck)
	}

	return hasVersionHeader, nil
}

// ReadVersionHeader reads the 2-byte version header from the WZ file.
// This is an obfuscated checksum derived from the MapleStory version number.
func (r *WzReader) ReadVersionHeader() (uint16, error) {
	var v uint16
	if err := binary.Read(r.file, binary.LittleEndian, &v); err != nil {
		return v, fmt.Errorf("failed to read version header: %w", err)
	}
	return v, nil
}

// ReadDirEntryMetadata reads the metadata for a single directory entry.
// Returns nil if the entry should be skipped (type 1).
func (r *WzReader) ReadDirEntryMetadata() (entry *wz.DirEntryMetadata, err error) {
	entry = &wz.DirEntryMetadata{}

	if err = binary.Read(r.file, binary.LittleEndian, &entry.Type); err != nil {
		return nil, fmt.Errorf("failed to read entry type: %w", err)
	}

	switch entry.Type {
	case wz.DirEntryTypeIgnore:
		if _, err := r.file.Seek(10, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to skip type 1 entry: %w", err)
		}
		return nil, nil
	case wz.DirEntryTypeReference:
		// 0x02 - data lives somewhere else
		var referenceOffset int32
		if err := binary.Read(r.file, binary.LittleEndian, &referenceOffset); err != nil {
			return nil, fmt.Errorf("failed to read reference offset: %w", err)
		}

		// remember where we are
		currentPos, err := r.file.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("failed to get current position: %w", err)
		}
		defer func() {
			if _, seekErr := r.file.Seek(currentPos, io.SeekStart); seekErr != nil {
				if err == nil {
					err = fmt.Errorf("failed to seek back: %w", seekErr)
				}
			}
		}()

		// go to data
		absoluteOffset := int64(r.header.BodyOffset) + int64(referenceOffset)
		if _, err := r.file.Seek(absoluteOffset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek to entry data at offset %d: %w", absoluteOffset, err)
		}

		// actually read the data there
		actualEntry, err := r.ReadDirEntryMetadata()
		if err != nil {
			return nil, fmt.Errorf("failed to read referenced entry: %w", err)
		}

		return actualEntry, nil
	case wz.DirEntryTypeDir, wz.DirEntryTypeFile:
		// 0x03, 0x04: read entry data directly
		var err error
		entry.Name, err = wz.ReadEncryptedString(r.file)
		if err != nil {
			return nil, fmt.Errorf("failed to read entry name: %w", err)
		}

		if err := wz.ReadCompressedInt32(r.file, &entry.FileSize); err != nil {
			return nil, fmt.Errorf("failed to read file size for %s: %w", entry.Name, err)
		}

		if err := wz.ReadCompressedInt32(r.file, &entry.Checksum); err != nil {
			return nil, fmt.Errorf("failed to read checksum for %s: %w", entry.Name, err)
		}

		entry.DataOffset, err = wz.ReadEncryptedOffset(r.file)
		if err != nil {
			return nil, fmt.Errorf("failed to read offset for %s: %w", entry.Name, err)
		}

		return entry, nil

	default:
		return nil, fmt.Errorf("unknown directory entry type: %d", entry.Type)
	}
}

func (r *WzReader) ReadDir() (*wz.Dir, error) {
	d := &wz.Dir{}
	if err := wz.ReadCompressedInt32(r.file, &d.EntryCount); err != nil {
		return nil, err
	}

	r.logger.Debug("reading directory entries",
		"entry_count", d.EntryCount,
	)

	d.EntriesMetadata = make([]wz.DirEntryMetadata, 0, d.EntryCount)

	for i := 0; i < int(d.EntryCount); i++ {
		entry, err := r.ReadDirEntryMetadata()
		if err != nil {
			return nil, fmt.Errorf("failed to read entry %d: %w", i, err)
		}
		// ignore skipped entries
		if entry == nil {
			continue
		}

		d.EntriesMetadata = append(d.EntriesMetadata, *entry)

		r.logger.Debug("read directory entry",
			"index", i,
			"type", entry.Type,
			"name", entry.Name,
			"file_size", entry.FileSize,
			"checksum", entry.Checksum,
			"offset", entry.DataOffset,
		)
	}

	r.logger.Info("read directory",
		"entry_count", d.EntryCount,
	)

	return d, nil
}

func Parse(file *os.File, cfg *config.Config) error {
	logger := slog.With(
		"file", cfg.InputFile,
	)

	logger.Info("starting")

	reader := &WzReader{
		file:   file,
		config: cfg,
		logger: logger,
	}

	_, err := reader.ReadHeader()
	if err != nil {
		return err
	}

	hasVersionHeader, err := reader.DetectFormat()
	if err != nil {
		return fmt.Errorf("failed to detect format: %w", err)
	}

	if hasVersionHeader {
		reader.versionHeader, err = reader.ReadVersionHeader()
		if err != nil {
			return err
		}

		logger.Info("detected format with version header",
			"version_header", reader.versionHeader,
		)
	} else {
		logger.Info("detected format without version header")
	}

	_, err = reader.ReadDir()
	if err != nil {
		return err
	}

	return nil
}
