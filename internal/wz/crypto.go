package wz

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
)

// Constants for WZ encryption
const (
	// OffsetConstant is used in WZ offset decryption.
	// Reference: MapleLib WzAESConstant.WZ_OffsetConstant
	OffsetConstant = 0x581C3F6D

	// KeyBatchSize is the size in bytes of each key expansion batch.
	// Keys are generated lazily in 4096-byte chunks to avoid allocating
	// the entire key stream upfront.
	KeyBatchSize = 4096
)

// UserKey is the 128-byte AES constant used by MapleStory.
// This is the default key extracted from the MapleStory client.
//
// Reference: MapleLib MapleCryptoConstants.MAPLESTORY_USERKEY_DEFAULT
var UserKey = [128]byte{
	0x13, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x5B, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00,
	0xB4, 0x00, 0x00, 0x00, 0x4B, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x1B, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x5F, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
	0x0F, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x00, 0x00,
	0x33, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
	0x52, 0x00, 0x00, 0x00, 0xDE, 0x00, 0x00, 0x00, 0xC7, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00,
}

// Key generates and manages the WZ encryption key stream.
//
// The key stream is used for string decryption and offset decryption in WZ files.
//
// Key generation process:
//  1. Trim the 128-byte UserKey to create a 32-byte AES key (see NewKey for details)
//  2. Create a 16-byte initial block by repeating the 4-byte IV (IV, IV, IV, IV)
//  3. Encrypt the initial block with AES-256 ECB to get the first 16 bytes of key stream
//  4. Use the previous 16 bytes as input to generate the next 16 bytes
//  5. Repeat until the desired key length is reached
//
// Special case: If IV is all zeros {0, 0, 0, 0}, the key stream is all zeros
// (used for BMS/Classic MapleStory).
//
// Keys are generated lazily in KeyBatchSize (4096) byte batches to avoid
// allocating the entire key stream upfront.
//
// Reference: MapleLib WzMutableKey
type Key struct {
	iv      [4]byte  // Initialization vector for this WZ file
	aesKey  [32]byte // AES key for key stream generation (see NewKey for how it's derived)
	keyData []byte   // Generated key stream (expanded on demand)
}

// NewKey creates a new WZ key generator from an initialization vector.
// The IV is a 4-byte array specific to each MapleStory region/version.
//
// Example IVs:
//   - GMS: {0x4D, 0x23, 0xC7, 0x2B}
//   - KMS: {0xB9, 0x7D, 0x63, 0xE9}
//   - BMS/Classic: {0x00, 0x00, 0x00, 0x00}
func NewKey(iv [4]byte) *Key {
	// Derive a 32-byte AES key from the 128-byte UserKey.
	// This takes every 16th byte from UserKey and places it at specific positions.
	// Loop: i = 0, 16, 32, 48, 64, 80, 96, 112 (8 iterations)
	// Positions: aesKey[0, 4, 8, 12, 16, 20, 24, 28] = UserKey[0, 16, 32, ...]
	// The remaining 24 bytes of aesKey are zero-initialized.
	//
	// Reference: MapleLib MapleCryptoConstants.GetTrimmedUserKey
	var aesKey [32]byte
	for i := 0; i < 128; i += 16 {
		aesKey[i/4] = UserKey[i]
	}

	return &Key{
		iv:     iv,
		aesKey: aesKey,
	}
}

// ByteAt returns the key byte at the given index.
// If the key stream has not been generated up to this index,
// it will be expanded automatically.
func (k *Key) ByteAt(index int) byte {
	k.expandTo(index + 1)
	return k.keyData[index]
}

// expandTo expands the key stream to at least size bytes.
// Keys are generated in KeyBatchSize (4096) byte batches.
func (k *Key) expandTo(size int) {
	if len(k.keyData) >= size {
		return
	}

	// Special case: zero IV means zero key stream
	// This is used for BMS/Classic MapleStory
	if k.iv == [4]byte{0, 0, 0, 0} {
		k.keyData = make([]byte, size)
		return
	}

	// Round up to next batch boundary
	newSize := ((size + KeyBatchSize - 1) / KeyBatchSize) * KeyBatchSize
	newData := make([]byte, newSize)

	// Copy existing key data
	startIndex := copy(newData, k.keyData)

	// Generate new key blocks using AES-256 ECB
	block, err := aes.NewCipher(k.aesKey[:])
	if err != nil {
		// This should never happen with a valid 32-byte key
		panic(fmt.Sprintf("failed to create AES cipher: %v", err))
	}

	input := make([]byte, 16)
	output := make([]byte, 16)

	// Generate key stream in 16-byte blocks
	for i := startIndex; i < newSize; i += 16 {
		if i == 0 {
			// First block: repeat IV pattern (IV, IV, IV, IV)
			// This creates a 16-byte block from the 4-byte IV
			for j := 0; j < 16; j++ {
				input[j] = k.iv[j%4]
			}
		} else {
			// Subsequent blocks: use previous output as input
			// This chains the encryption to create a continuous key stream
			copy(input, newData[i-16:i])
		}

		// Encrypt the input block to get the next 16 bytes of key stream
		block.Encrypt(output, input)
		copy(newData[i:], output)
	}

	k.keyData = newData
}

// DecryptString decrypts a WZ string (Unicode or ASCII).
//
// Decryption uses an incrementing XOR mask:
//   - Unicode: mask starts at 0xAAAA, increments by 1 per character
//   - ASCII: mask starts at 0xAA, increments by 1 per byte
//
// Note: MapleLib's source shows additional key XOR operations (lines 143, 181),
// but empirical testing shows v263 WZ files decrypt correctly with only the mask.
// The key may be used in other WZ versions or contexts not yet tested.
//
// Reference: MapleLib WzBinaryReader.DecodeUnicode / DecodeAscii
func (k *Key) DecryptString(encrypted []byte, isUnicode bool) string {
	if isUnicode {
		return k.decryptUnicode(encrypted)
	}
	return k.decryptASCII(encrypted)
}

// decryptUnicode decrypts a Unicode (UTF-16LE) WZ string.
// Reference: MapleLib WzBinaryReader.DecodeUnicode (lines 127-157)
func (k *Key) decryptUnicode(data []byte) string {
	length := len(data) / 2
	result := make([]rune, length)
	mask := uint16(0xAAAA)

	for i := 0; i < length; i++ {
		encChar := binary.LittleEndian.Uint16(data[i*2:])
		result[i] = rune(encChar ^ mask)
		mask++
	}

	return string(result)
}

// decryptASCII decrypts an ASCII WZ string.
// Reference: MapleLib WzBinaryReader.DecodeAscii (lines 165-195)
func (k *Key) decryptASCII(data []byte) string {
	result := make([]byte, len(data))
	mask := byte(0xAA)

	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ mask
		mask++
	}

	return string(result)
}

// rotateLeft performs a left bitwise rotation on a 32-bit unsigned integer.
// This is used in WZ offset decryption.
func rotateLeft(x uint32, n byte) uint32 {
	return (x << n) | (x >> (32 - n))
}

// DecryptOffset decrypts a WZ file offset using the version hash.
//
// The decryption algorithm:
//  1. Calculate: (currentPos - bodyOffset) XOR 0xFFFFFFFF
//  2. Multiply by version hash
//  3. Subtract constant: 0x581C3F6D
//  4. Rotate left by (result & 0x1F) bits
//  5. XOR with the encrypted offset read from file
//  6. Add bodyOffset × 2
//
// Parameters:
//   - currentPos: The file position where the encrypted offset was read (before reading the 4 bytes)
//   - bodyOffset: The offset where WZ data begins (from file header)
//   - versionHash: The hash calculated from the MapleStory version number
//   - encryptedOffset: The 4-byte encrypted offset value read from the file
//
// Returns: The decrypted absolute file offset
//
// Reference: MapleLib WzBinaryReader.ReadOffset
func DecryptOffset(currentPos, bodyOffset uint32, versionHash uint32, encryptedOffset uint32) uint32 {
	offset := (currentPos - bodyOffset) ^ 0xFFFFFFFF
	offset *= versionHash
	offset -= OffsetConstant
	offset = rotateLeft(offset, byte(offset&0x1F))
	offset ^= encryptedOffset
	offset += bodyOffset * 2
	return offset
}

// VersionHash calculates the version hash from a MapleStory version string.
//
// Algorithm:
//
//	hash = 0
//	for each character:
//	  hash = (hash * 32) + ASCII_value + 1
//
// This hash is used for offset decryption (see DecryptOffset).
// For old-format WZ files, an obfuscated form is stored in the version header.
// For 64-bit WZ files without version headers, version numbers must be bruteforced (typically 770-779).
//
// Reference: MapleLib version hash calculation (multiple locations in codebase)
func VersionHash(version string) uint32 {
	hash := uint32(0)
	for _, ch := range version {
		hash = (hash * 32) + uint32(ch) + 1
	}
	return hash
}

// ObfuscateVersionHash applies the obfuscation used in old-format WZ version headers.
//
// Algorithm:
//  1. XOR all 4 bytes of the hash together
//  2. Bitwise NOT the result
//  3. Return low byte as uint16
//
// This is used during bruteforce version detection to match against the version header.
// The version header in old-format WZ files contains this obfuscated hash value.
//
// Reference: MapleLib version header validation logic
func ObfuscateVersionHash(hash uint32) uint16 {
	b1 := byte(hash & 0xFF)
	b2 := byte((hash >> 8) & 0xFF)
	b3 := byte((hash >> 16) & 0xFF)
	b4 := byte((hash >> 24) & 0xFF)

	result := b1 ^ b2 ^ b3 ^ b4
	return uint16(^result) & 0xFF
}
