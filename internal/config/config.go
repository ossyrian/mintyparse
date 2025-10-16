package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// Config holds application configuration
type Config struct {
	// WZ Parser settings
	WzVersion string `mapstructure:"wz_version"`
	WzIV      []byte

	// Input/Output
	Input      string `mapstructure:"input"`
	Output     string `mapstructure:"output"`
	SpritesDir string `mapstructure:"sprites_dir"`

	// Behavior
	Verbose bool `mapstructure:"verbose"`
	DryRun  bool `mapstructure:"dry_run"`
}

// Load loads configuration from Viper (env vars, config file, flags)
func Load() (*Config, error) {
	cfg := &Config{}

	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Parse WZ IV based on version
	iv, err := parseWzIV(cfg.WzVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid WZ version: %w", err)
	}
	cfg.WzIV = iv

	return cfg, nil
}

// parseWzIV returns the IV bytes for known WZ versions
func parseWzIV(version string) ([]byte, error) {
	switch version {
	case "gms", "auto", "":
		return []byte{0x4D, 0x23, 0xC7, 0x2B}, nil
	case "kms":
		return []byte{0xB9, 0x7D, 0x63, 0xE9}, nil
	case "sea":
		return []byte{0x2E, 0x23, 0x12, 0x61}, nil
	case "tms":
		return []byte{0x2E, 0x12, 0x61, 0x9A}, nil
	case "classic":
		// Classic MapleStory IV (unknown until release)
		return []byte{0x4D, 0x23, 0xC7, 0x2B}, nil // Default to GMS for now
	default:
		return nil, fmt.Errorf("unknown WZ version: %s", version)
	}
}
