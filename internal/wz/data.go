package wz

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ReadCompressedInt32 reads a WZ compressed integer from r.
// The WZ "compressed 32-bit integer" format is a one- or
// five-byte data type which can be read as follows:
//   - The first byte is always an int8. If its value fits
//     in the range [-127, 127], then it is the value of the
//     compressed integer.
//   - If the first byte is exactly -128, then the next
//     4 bytes are a little-endian int32.
//
// Reference: MapleLib WzBinaryReader.ReadCompressedInt
func ReadCompressedInt32(r io.Reader, x *int32) error {
	var sb int8
	if err := binary.Read(r, binary.LittleEndian, &sb); err != nil {
		return fmt.Errorf("failed to read compressed int marker: %w", err)
	}

	if sb == -128 {
		if err := binary.Read(r, binary.LittleEndian, x); err != nil {
			return fmt.Errorf("failed to read compressed int value: %w", err)
		}
		return nil
	}

	*x = int32(sb)
	return nil
}

// ReadEncryptedString reads and decrypts a WZ encrypted string from r.
//
// Format:
//   1. Length indicator (1 byte, signed):
//      - 0: Empty string
//      - Positive (1-126): Unicode string with this many characters
//      - 127: Unicode string, read next 4 bytes (int32) for actual length
//      - Negative (-1 to -127): ASCII string, absolute value is length
//      - -128: ASCII string, read next 4 bytes (int32) for actual length
//   2. String data (encrypted):
//      - Unicode: 2 bytes per character (UTF-16LE)
//      - ASCII: 1 byte per character
//
// The key is used for decryption (see Key.DecryptString for algorithm details).
//
// Reference: MapleLib WzBinaryReader.ReadString
func ReadEncryptedString(r io.Reader, key *Key, str *string) error {
	var lengthIndicator int8
	if err := binary.Read(r, binary.LittleEndian, &lengthIndicator); err != nil {
		return fmt.Errorf("failed to read string length indicator: %w", err)
	}

	if lengthIndicator == 0 {
		*str = ""
		return nil
	}

	var length int32
	var isUnicode bool

	switch {
	case lengthIndicator > 0 && lengthIndicator < 127:
		// Unicode string, short length
		length = int32(lengthIndicator)
		isUnicode = true

	case lengthIndicator == 127:
		// Unicode string, long length
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return fmt.Errorf("failed to read unicode string length: %w", err)
		}
		isUnicode = true

	case lengthIndicator < 0 && lengthIndicator > -128:
		// ASCII string, short length
		length = int32(-lengthIndicator)
		isUnicode = false

	case lengthIndicator == -128:
		// ASCII string, long length
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return fmt.Errorf("failed to read ascii string length: %w", err)
		}
		isUnicode = false
	}

	if length < 0 {
		return fmt.Errorf("invalid string length: %d", length)
	}

	// Calculate byte length (Unicode uses 2 bytes per character)
	byteLength := int(length)
	if isUnicode {
		byteLength *= 2
	}

	// Read encrypted string data
	encrypted := make([]byte, byteLength)
	if _, err := io.ReadFull(r, encrypted); err != nil {
		return fmt.Errorf("failed to read string data: %w", err)
	}

	// Decrypt using the WZ key
	*str = key.DecryptString(encrypted, isUnicode)
	return nil
}

// ReadOffsetOrInlineString reads a string that may be stored inline or at an offset.
// Used for directory entry names and property names in WZ files.
//
// Format:
//   1. Indicator byte:
//      - 0x00 or 0x73: String data follows inline
//      - 0x01 or 0x1B: String is at offset (next 4 bytes = int32 offset)
//   2. String data (if inline) OR offset (if offset-based)
//
// If the string is stored at an offset, this function:
//   - Reads the int32 offset value
//   - Seeks to that position in the file
//   - Reads the encrypted string
//   - Seeks back to the original position (after indicator + offset bytes)
//
// Reference: MapleLib WzBinaryReader.ReadStringBlock
func ReadOffsetOrInlineString(rs io.ReadSeeker, key *Key, str *string) error {
	var indicator byte
	if err := binary.Read(rs, binary.LittleEndian, &indicator); err != nil {
		return fmt.Errorf("failed to read string indicator: %w", err)
	}

	switch indicator {
	case 0x00, 0x73:
		// String follows inline
		return ReadEncryptedString(rs, key, str)

	case 0x01, 0x1B:
		// String is at an offset
		var offset int32
		if err := binary.Read(rs, binary.LittleEndian, &offset); err != nil {
			return fmt.Errorf("failed to read string offset: %w", err)
		}

		// Save current position to return here after reading
		currentPos, err := rs.Seek(0, io.SeekCurrent)
		if err != nil {
			return fmt.Errorf("failed to get current position: %w", err)
		}
		defer func() {
			// Always seek back to where we were, even if reading fails
			rs.Seek(currentPos, io.SeekStart)
		}()

		// Seek to string location
		if _, err := rs.Seek(int64(offset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to string at offset %d: %w", offset, err)
		}

		// Read and decrypt the string
		if err := ReadEncryptedString(rs, key, str); err != nil {
			return fmt.Errorf("failed to read string at offset %d: %w", offset, err)
		}

		return nil

	default:
		return fmt.Errorf("unknown string indicator: 0x%02X", indicator)
	}
}

// ReadEncryptedOffset reads and decrypts a WZ file offset from r.
//
// File offsets in WZ files are encrypted using the version hash to prevent tampering.
// The current file position is used as part of the decryption algorithm, so the reader
// must be positioned exactly where the encrypted offset begins.
//
// Parameters:
//   - r: Reader positioned at the encrypted offset
//   - bodyOffset: Where WZ data begins (from file header)
//   - versionHash: Hash calculated from MapleStory version (e.g., "263" → 54036)
//   - offset: Output - decrypted absolute file offset
//
// The decryption uses bitwise operations (XOR, rotation) and the version hash.
// See DecryptOffset in crypto.go for the full algorithm.
func ReadEncryptedOffset(r io.ReadSeeker, bodyOffset uint32, versionHash uint32, offset *uint32) error {
	// Get current position before reading the encrypted offset
	currentPos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to get current position: %w", err)
	}

	// Read the encrypted offset value
	var encryptedOffset uint32
	if err := binary.Read(r, binary.LittleEndian, &encryptedOffset); err != nil {
		return fmt.Errorf("failed to read encrypted offset: %w", err)
	}

	// Decrypt and store in output parameter
	*offset = DecryptOffset(uint32(currentPos), bodyOffset, versionHash, encryptedOffset)
	return nil
}
