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

	// Encryption state
	// versionHeader is the 2-byte version header from the file (0 if no version header).
	// For files without a version header, version numbers must be bruteforced (typically 770-779).
	versionHeader uint16

	// versionHash is the hash calculated from the MapleStory version number.
	// This hash is used for offset decryption. It's derived from the version string
	// (e.g., "83", "230", "777") using the VersionHash function.
	versionHash uint32

	// key is the encryption key stream used for string decryption.
	// It's generated from the initialization vector (IV) for the game region.
	key *wz.Key
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

// ReadVersionHeader detects and reads the version header if present.
// Returns the version header value (0 if not present) and any error.
// The version header is an obfuscated checksum derived from the MapleStory version number.
func (r *WzReader) ReadVersionHeader() (uint16, error) {
	var version uint16
	if err := binary.Read(r.file, binary.LittleEndian, &version); err != nil {
		return 0, fmt.Errorf("failed to read version header: %w", err)
	}

	// version headers are single-byte values, so > 255 means no header
	if version > 0xFF {
		r.logger.Debug("detected format without version header (value > 255)",
			"check_value", version)
		if _, err := r.file.Seek(int64(r.header.BodyOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek back to data offset: %w", err)
		}
		return 0, nil
	}

	// special case: 0x80 is the compressed int marker
	// could be a version header OR the start of a compressed int
	// try reading as compressed int to disambiguate
	if version == 0x80 {
		if _, err := r.file.Seek(int64(r.header.BodyOffset), io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek to data offset: %w", err)
		}

		var entryCount int32
		if err := wz.ReadCompressedInt32(r.file, &entryCount); err != nil {
			return 0, fmt.Errorf("failed to read entry count: %w", err)
		}

		// if the compressed int decoded to a reasonable entry count, no version header present
		if entryCount > 0 && entryCount <= 0xFFFF {
			r.logger.Debug("detected format without version header (compressed int pattern)",
				"entry_count", entryCount)
			return 0, nil
		}

		// looks like a version header after all, seek past it
		if _, err := r.file.Seek(int64(r.header.BodyOffset)+2, io.SeekStart); err != nil {
			return 0, fmt.Errorf("failed to seek past version header: %w", err)
		}
		r.logger.Debug("detected format with version header",
			"version_header", version)
		return version, nil
	}

	// version header present (values 0x00-0x7F, 0x81-0xFF)
	r.logger.Debug("detected format with version header",
		"version_header", version)

	return version, nil
}

// determineVersionHash calculates or bruteforces the version hash for offset decryption.
//
// If userProvidedVersion is not empty:
//   - Calculates hash directly from the version string
//   - Validates it matches the file's version header (if present)
//   - Falls back to bruteforce if validation fails
//
// If userProvidedVersion is empty:
//   - Bruteforces by trying version ranges until finding one that decrypts correctly
func (r *WzReader) determineVersionHash(userProvidedVersion string) error {
	// User provided explicit version
	if userProvidedVersion != "" {
		r.versionHash = wz.VersionHash(userProvidedVersion)

		// Validate against version header if present
		if r.versionHeader != 0 {
			expectedObfuscated := wz.ObfuscateVersionHash(r.versionHash)
			if expectedObfuscated != r.versionHeader {
				r.logger.Warn("version mismatch, trying bruteforce",
					"provided", userProvidedVersion,
					"expected_header", expectedObfuscated,
					"actual_header", r.versionHeader)

				if err := r.bruteforceVersion(); err != nil {
					r.logger.Warn("bruteforce failed, using provided version",
						"error", err)
				} else {
					return nil // Bruteforce succeeded
				}
			}
		}

		r.logger.Info("using MapleStory version",
			"version", userProvidedVersion,
			"version_hash", r.versionHash)
		return nil
	}

	// No version provided - bruteforce
	r.logger.Info("bruteforcing MapleStory version",
		"version_header", r.versionHeader)

	if err := r.bruteforceVersion(); err != nil {
		return fmt.Errorf("failed to find version: %w (hint: use --game-version flag)", err)
	}

	return nil
}

// bruteforceVersion finds the MapleStory version by trying candidate versions.
//
// For files with version header (old format):
//   - Only tries versions where ObfuscateVersionHash matches the header
//   - Typically finds a match quickly (version header narrows the search)
//
// For files without version header (64-bit format):
//   - Tries versions 770-779 (typical 64-bit encryption versions)
//
// Validation: A version is considered correct if the first directory entry name
// decrypts to valid ASCII (alphanumeric + common punctuation).
func (r *WzReader) bruteforceVersion() error {
	startPos, err := r.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to save position: %w", err)
	}
	defer r.file.Seek(startPos, io.SeekStart)

	// Version ranges to try, ordered by likelihood
	ranges := r.getVersionRanges()

	for _, vRange := range ranges {
		for v := vRange.start; v <= vRange.end; v++ {
			versionStr := fmt.Sprintf("%d", v)
			hash := wz.VersionHash(versionStr)

			// For old format, skip versions that don't match the version header
			if r.versionHeader != 0 {
				if wz.ObfuscateVersionHash(hash) != r.versionHeader {
					continue
				}
			}

			// Try parsing with this version hash
			if r.tryVersion(hash) {
				r.versionHash = hash
				r.logger.Info("found matching version",
					"version", versionStr,
					"version_hash", hash,
					"range", vRange.desc)
				return nil
			}
		}
	}

	return fmt.Errorf("no valid version found (version_header=%d)", r.versionHeader)
}

// getVersionRanges returns version number ranges to try during bruteforce.
func (r *WzReader) getVersionRanges() []struct {
	start int
	end   int
	desc  string
} {
	if r.versionHeader == 0 {
		// 64-bit format - try standard encryption version range
		return []struct {
			start int
			end   int
			desc  string
		}{
			{770, 779, "64-bit"},
		}
	}

	// Old format with version header - try MapleStory patch version ranges
	return []struct {
		start int
		end   int
		desc  string
	}{
		{200, 300, "modern"},
		{100, 199, "mid-era"},
		{80, 99, "classic"},
		{1, 79, "very old"},
	}
}

// tryVersion tests if a version hash correctly decrypts the directory structure.
// It attempts to read the first directory entry and validates the decrypted name.
func (r *WzReader) tryVersion(versionHash uint32) bool {
	// Seek to directory start (skip version header if present)
	dirStart := int64(r.header.BodyOffset)
	if r.versionHeader != 0 {
		dirStart += 2
	}

	if _, err := r.file.Seek(dirStart, io.SeekStart); err != nil {
		return false
	}

	// Temporarily use this version hash
	oldHash := r.versionHash
	r.versionHash = versionHash
	defer func() { r.versionHash = oldHash }()

	// Read and validate entry count
	var entryCount int32
	if err := wz.ReadCompressedInt32(r.file, &entryCount); err != nil {
		return false
	}

	// Sanity check: entry count should be reasonable
	if entryCount <= 0 || entryCount > 1000 {
		return false
	}

	// Try to read the first directory entry
	entry, err := r.ReadDirEntryMetadata()
	if err != nil || entry == nil {
		return false
	}

	// Validate the decrypted name
	return isValidWzName(entry.Name)
}

// isValidWzName checks if a decrypted string looks like a valid WZ directory/file name.
//
// Valid WZ names are typically English words (e.g., "Cash", "Consume", "Install")
// and should contain only:
//   - Letters (A-Z, a-z)
//   - Numbers (0-9)
//   - Common punctuation (_, ., -)
//
// This validation helps distinguish correctly decrypted names from garbage output.
func isValidWzName(name string) bool {
	if len(name) == 0 || len(name) > 100 {
		return false
	}

	hasLetter := false
	for _, ch := range name {
		switch {
		case (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'):
			hasLetter = true
		case ch >= '0' && ch <= '9':
			// Numbers OK
		case ch == '_' || ch == '.' || ch == '-':
			// Common filename characters OK
		default:
			// Any other character (including control chars) = invalid
			return false
		}
	}

	// Must have at least one letter to be a valid name
	return hasLetter
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

// ReadDirEntryMetadata reads the metadata for a single directory entry.
// Returns nil if the entry should be skipped (type 1).
func (r *WzReader) ReadDirEntryMetadata() (*wz.DirEntryMetadata, error) {
	entry := &wz.DirEntryMetadata{}

	if err := binary.Read(r.file, binary.LittleEndian, &entry.Type); err != nil {
		return nil, fmt.Errorf("failed to read entry type: %w", err)
	}

	switch entry.Type {
	case wz.DirEntryTypeIgnore:
		if _, err := r.file.Seek(10, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to skip ignored entry: %w", err)
		}
		return nil, nil

	case wz.DirEntryTypeReference:
		var referenceOffset int32
		if err := binary.Read(r.file, binary.LittleEndian, &referenceOffset); err != nil {
			return nil, fmt.Errorf("failed to read reference offset: %w", err)
		}

		currentPos, err := r.file.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("failed to get current position: %w", err)
		}
		defer r.file.Seek(currentPos, io.SeekStart)

		absoluteOffset := int64(r.header.BodyOffset) + int64(referenceOffset)
		if _, err := r.file.Seek(absoluteOffset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek to referenced entry at offset %d: %w", absoluteOffset, err)
		}

		return r.ReadDirEntryMetadata()

	case wz.DirEntryTypeDir, wz.DirEntryTypeFile:
		if err := wz.ReadEncryptedString(r.file, r.key, &entry.Name); err != nil {
			return nil, fmt.Errorf("failed to read entry name: %w", err)
		}

		if err := wz.ReadCompressedInt32(r.file, &entry.FileSize); err != nil {
			return nil, fmt.Errorf("failed to read file size for %s: %w", entry.Name, err)
		}

		if err := wz.ReadCompressedInt32(r.file, &entry.Checksum); err != nil {
			return nil, fmt.Errorf("failed to read checksum for %s: %w", entry.Name, err)
		}

		if err := wz.ReadEncryptedOffset(r.file, r.header.BodyOffset, r.versionHash, &entry.DataOffset); err != nil {
			return nil, fmt.Errorf("failed to read offset for %s: %w", entry.Name, err)
		}

		return entry, nil

	default:
		return nil, fmt.Errorf("unknown directory entry type: %d", entry.Type)
	}
}

func Parse(file *os.File, cfg *config.Config) error {
	logger := slog.With(
		"file", cfg.InputFile,
	)

	logger.Info("starting parse")

	reader := &WzReader{
		file:   file,
		config: cfg,
		logger: logger,
	}

	// Read file header
	_, err := reader.ReadHeader()
	if err != nil {
		return err
	}

	// Initialize encryption key from game region IV
	ivBytes, err := wz.IVForVersion(cfg.GameRegion)
	if err != nil {
		return fmt.Errorf("failed to get IV for game region %s: %w", cfg.GameRegion, err)
	}

	var iv [4]byte
	copy(iv[:], ivBytes)
	reader.key = wz.NewKey(iv)

	logger.Debug("initialized encryption key",
		"game_region", cfg.GameRegion,
		"iv", fmt.Sprintf("%02X %02X %02X %02X", iv[0], iv[1], iv[2], iv[3]))

	// Read version header (0 if not present)
	reader.versionHeader, err = reader.ReadVersionHeader()
	if err != nil {
		return fmt.Errorf("failed to read version header: %w", err)
	}

	// Determine version hash for offset decryption
	if err := reader.determineVersionHash(cfg.GameVersion); err != nil {
		return err
	}

	// Read directory structure
	_, err = reader.ReadDir()
	if err != nil {
		return err
	}

	return nil
}
