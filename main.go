package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ossyrian/mintyparse/internal/config"
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

// multiHandler sends log records to multiple handlers
type multiHandler []slog.Handler

func (mh multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range mh {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (mh multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range mh {
		if err := h.Handle(ctx, r.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (mh multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make(multiHandler, len(mh))
	for i, h := range mh {
		handlers[i] = h.WithAttrs(attrs)
	}
	return handlers
}

func (mh multiHandler) WithGroup(name string) slog.Handler {
	handlers := make(multiHandler, len(mh))
	for i, h := range mh {
		handlers[i] = h.WithGroup(name)
	}
	return handlers
}

// setupLogging overwrites the global logger based on relevant
// command args/config
func setupLogging(cfg *config.Config) error {
	level := parseLogLevel(cfg.LogLevel)

	consoleHandler := tint.NewHandler(os.Stdout, &tint.Options{Level: level})

	if cfg.LogOutputDir != "" {
		logDir := os.ExpandEnv(cfg.LogOutputDir)

		if err := os.MkdirAll(logDir, 0o755); err != nil {
			return fmt.Errorf("failed to create log output directory: %w", err)
		}

		timestamp := time.Now().Format("20060102_150405")
		logFileName := fmt.Sprintf("mintyparse_%s.log", timestamp)
		logFilePath := filepath.Join(logDir, logFileName)

		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("failed to create log file: %w", err)
		}

		fileHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: level})

		slog.SetDefault(slog.New(multiHandler{consoleHandler, fileHandler}))

		fmt.Fprintf(os.Stderr, "Logging to file: %s\n", logFilePath)
	} else {
		slog.SetDefault(slog.New(consoleHandler))
	}

	return nil
}

// parseLogLevel converts a string log level to slog.Level
func parseLogLevel(levelStr string) slog.Level {
	switch levelStr {
	case "trace", "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error", "fatal":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// parse runs the main mintyparse command in order to parse
// the specified WZ file
func parse(cmd *cobra.Command, args []string) error {
	cfg = &config.Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	if err := setupLogging(cfg); err != nil {
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
