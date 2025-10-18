package config

// Config holds app configuration
type Config struct {
	// GameRegion is the MapleStory region/edition (gms, kms, sea, tms)
	// Used to determine the encryption IV
	GameRegion string `mapstructure:"game_region"`

	// GameVersion is the MapleStory patch version number (e.g., "263", "230")
	// Used to calculate the version hash for offset decryption
	// If not provided, the parser will attempt to bruteforce it
	GameVersion string `mapstructure:"game_version"`

	InputFile        string `mapstructure:"input"`
	OutputFile       string `mapstructure:"output"`
	SpritesOutputDir string `mapstructure:"sprites_dir"`

	DryRun       bool   `mapstructure:"dry_run"`
	LogLevel     string `mapstructure:"log_level"`
	LogOutputDir string `mapstructure:"log_output_dir"`
}
