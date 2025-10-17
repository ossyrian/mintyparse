package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ossyrian/mintyparse/internal/config"
	"github.com/ossyrian/mintyparse/internal/logging"
	"github.com/ossyrian/mintyparse/internal/parser"
)

var (
	cfgFile string
	cfg     *config.Config
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "mintyparse",
	Short: "Parse MapleStory WZ files to JSON and extract sprites",
	RunE:  parse,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "path to config file")

	// i/o
	rootCmd.Flags().StringP("input", "i", "", "path to .wz file to parse (required)")
	rootCmd.Flags().StringP("output", "o", "", "path to output JSON file")
	rootCmd.Flags().StringP("sprites-output", "s", "", "directory to extract sprites to")
	rootCmd.MarkFlagRequired("input")
	rootCmd.MarkFlagRequired("output")

	// WZ settings
	rootCmd.Flags().String("game-version", "gms", "MapleStory game version (gms, kms, sea, tms)")

	// other opts
	rootCmd.Flags().String("log-level", "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.Flags().String("log-output-dir", "", "directory to write log files (if set, logs are written to both stdout and file)")
	rootCmd.Flags().Bool("dry-run", false, "parse without writing output (validation)")

	viper.BindPFlag("input", rootCmd.Flags().Lookup("input"))
	viper.BindPFlag("output", rootCmd.Flags().Lookup("output"))
	viper.BindPFlag("sprites_dir", rootCmd.Flags().Lookup("sprites-output"))
	viper.BindPFlag("game_version", rootCmd.Flags().Lookup("game-version"))
	viper.BindPFlag("log_level", rootCmd.Flags().Lookup("log-level"))
	viper.BindPFlag("log_output_dir", rootCmd.Flags().Lookup("log-output-dir"))
	viper.BindPFlag("dry_run", rootCmd.Flags().Lookup("dry-run"))
}

// initConfig reads in config file and environment variables if set
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, ".config", "mintyparse"))
		}
		viper.AddConfigPath("/etc/mintyparse/mintyparse")
		viper.SetConfigName("config")
		viper.SetConfigType("toml")
	}

	viper.SetEnvPrefix("MINTYPARSE")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	}
}

// parse runs the main mintyparse command in order to parse
// the specified WZ file
func parse(cmd *cobra.Command, args []string) error {
	cfg = &config.Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	if err := logging.Setup(cfg.LogLevel, cfg.LogOutputDir); err != nil {
		return fmt.Errorf("could not set up logging: %w", err)
	}

	slog.Info("parsing file", "input", cfg.InputFile)

	file, err := os.Open(cfg.InputFile)
	if err != nil {
		return fmt.Errorf("failed to open WZ file: %w", err)
	}
	defer file.Close()

	if err := parser.Parse(file); err != nil {
		slog.Error(fmt.Sprintf("error parsing %s", cfg.InputFile), "error", err)

		return nil
	}

	// TODO: output JSON
	// TODO: output sprites

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
