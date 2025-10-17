package config

import (
	"fmt"
)

// Config holds app configuration
type Config struct {
	GameVersion string `mapstructure:"game_version"`

	InputFile        string `mapstructure:"input"`
	OutputFile       string `mapstructure:"output"`
	SpritesOutputDir string `mapstructure:"sprites_dir"`

	DryRun       bool   `mapstructure:"dry_run"`
	LogLevel     string `mapstructure:"log_level"`
	LogOutputDir string `mapstructure:"log_output_dir"`
}

// parseWzIV returns the IV bytes for known WZ versions
func parseWzIV(version string) ([]byte, error) {
	switch version {
	case "gms":
		return []byte{0x4D, 0x23, 0xC7, 0x2B}, nil
	case "kms":
		return []byte{0xB9, 0x7D, 0x63, 0xE9}, nil
	case "sea":
		return []byte{0x2E, 0x23, 0x12, 0x61}, nil
	case "tms":
		return []byte{0x2E, 0x12, 0x61, 0x9A}, nil
	default:
		return nil, fmt.Errorf("unknown WZ version: %s", version)
	}
}
