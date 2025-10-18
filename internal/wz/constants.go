package wz

import "fmt"

// Magic is the magic number identifying valid WZ files ("PKG1")
var Magic = [4]byte{'P', 'K', 'G', '1'}

// IVForVersion returns the initialization vector (IV) bytes for known game versions/regions.
func IVForVersion(region string) ([]byte, error) {
	switch region {
	case "gms":
		return []byte{0x4D, 0x23, 0xC7, 0x2B}, nil
	case "kms":
		return []byte{0xB9, 0x7D, 0x63, 0xE9}, nil
	case "sea":
		return []byte{0x2E, 0x23, 0x12, 0x61}, nil
	case "tms":
		return []byte{0x2E, 0x12, 0x61, 0x9A}, nil
	default:
		return nil, fmt.Errorf("unknown game region: %s", region)
	}
}
