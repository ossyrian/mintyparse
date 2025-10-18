package wz

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ReadCompressedInt reads a WZ compressed integer from r.
// The WZ "compressed 32-bit integer" format is a one- or
// five-byte data type which can be read as follows:
//   - The first byte is always an int8. If its value fits
//     in the range [-127, 127], then it is the value of the
//     compressed integer.
//   - If the first byte is exactly -128, then the next
//     4 bytes are a little-endian int32.
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

// ReadEncryptedString reads a WZ encrypted string from r.
// TODO: This is a placeholder that reads unencrypted strings for now.
// The actual implementation requires WzKey for XOR decryption.
//
// Length indicator (1 byte, sbyte):
//   - 0: Empty string
//   - Positive (1 to 126): Unicode string, this many characters
//   - 127: Unicode string, read next 4 bytes (int32) for actual length
//   - Negative (-1 to -127): ASCII string, absolute value is length
//   - -128: ASCII string, read next 4 bytes (int32) for actual length
func ReadEncryptedString(r io.Reader) (string, error) {
	var lengthIndicator int8
	if err := binary.Read(r, binary.LittleEndian, &lengthIndicator); err != nil {
		return "", fmt.Errorf("failed to read string length indicator: %w", err)
	}

	// Empty string
	if lengthIndicator == 0 {
		return "", nil
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
			return "", fmt.Errorf("failed to read unicode string length: %w", err)
		}
		isUnicode = true

	case lengthIndicator < 0 && lengthIndicator > -128:
		// ASCII string, short length
		length = int32(-lengthIndicator)
		isUnicode = false

	case lengthIndicator == -128:
		// ASCII string, long length
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return "", fmt.Errorf("failed to read ascii string length: %w", err)
		}
		isUnicode = false
	}

	if length < 0 {
		return "", fmt.Errorf("invalid string length: %d", length)
	}

	// TODO: Implement proper decryption with WzKey
	// For now, read unencrypted bytes
	if isUnicode {
		// Unicode: 2 bytes per character (UTF-16LE)
		buf := make([]byte, length*2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("failed to read unicode string data: %w", err)
		}
		// TODO: XOR decryption with WzKey and mask (0xAAAA initial, increment)
		// For now, just convert UTF-16LE to string (placeholder)
		runes := make([]rune, length)
		for i := int32(0); i < length; i++ {
			runes[i] = rune(binary.LittleEndian.Uint16(buf[i*2:]))
		}
		return string(runes), nil
	} else {
		// ASCII: 1 byte per character
		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("failed to read ascii string data: %w", err)
		}
		// TODO: XOR decryption with WzKey and mask (0xAA initial, increment)
		return string(buf), nil
	}
}

// ReadStringBlock reads a string that may be stored inline or at an offset.
// This is used for directory entry names and property names.
//
// Indicator byte:
//   - 0x00 or 0x73: String data follows inline
//   - 0x01 or 0x1B: Read int32 offset, then read string at that position
func ReadStringBlock(rs io.ReadSeeker) (string, error) {
	var indicator byte
	if err := binary.Read(rs, binary.LittleEndian, &indicator); err != nil {
		return "", fmt.Errorf("failed to read string block indicator: %w", err)
	}

	switch indicator {
	case 0x00, 0x73:
		// String follows inline
		return ReadEncryptedString(rs)

	case 0x01, 0x1B:
		// String is at an offset
		var offset int32
		if err := binary.Read(rs, binary.LittleEndian, &offset); err != nil {
			return "", fmt.Errorf("failed to read string offset: %w", err)
		}

		// Save current position
		currentPos, err := rs.Seek(0, io.SeekCurrent)
		if err != nil {
			return "", fmt.Errorf("failed to get current position: %w", err)
		}

		// Seek to string location
		if _, err := rs.Seek(int64(offset), io.SeekStart); err != nil {
			return "", fmt.Errorf("failed to seek to string at offset %d: %w", offset, err)
		}

		// Read string
		str, err := ReadEncryptedString(rs)
		if err != nil {
			return "", fmt.Errorf("failed to read string at offset %d: %w", offset, err)
		}

		// Seek back to saved position
		if _, err := rs.Seek(currentPos, io.SeekStart); err != nil {
			return "", fmt.Errorf("failed to seek back to position %d: %w", currentPos, err)
		}

		return str, nil

	default:
		return "", fmt.Errorf("unknown string block indicator: 0x%02X", indicator)
	}
}

// ReadEncryptedOffset reads an encrypted uint32 offset from r.
// TODO: This is a placeholder that reads unencrypted offsets for now.
// The actual implementation requires version hash calculation and complex XOR operations:
//  1. Calculate: (position - dataOffset) XOR 0xFFFFFFFF
//  2. Multiply by version hash
//  3. Subtract constant: 0x581C3F6D
//  4. Rotate left by (result & 0x1F) bits
//  5. Read encrypted offset (4 bytes, uint32)
//  6. XOR with result from step 4
//  7. Add dataOffset × 2
func ReadEncryptedOffset(r io.Reader) (uint32, error) {
	var offset uint32
	if err := binary.Read(r, binary.LittleEndian, &offset); err != nil {
		return 0, fmt.Errorf("failed to read encrypted offset: %w", err)
	}
	// TODO: Implement proper offset decryption using version hash
	return offset, nil
}
