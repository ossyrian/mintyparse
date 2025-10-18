package logging

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/lmittmann/tint"
	slogmulti "github.com/samber/slog-multi"
)

// Setup configures the global slog logger
// If logOutputDir is non-empty, logs are written to both stdout and a timestamped file in that directory
func Setup(levelStr string, logOutputDir string) error {
	level := parseLogLevel(levelStr)

	consoleHandler := tint.NewHandler(os.Stdout, &tint.Options{Level: level})

	if logOutputDir != "" {
		logDir := os.ExpandEnv(logOutputDir)

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

		slog.SetDefault(slog.New(
			slogmulti.Fanout(consoleHandler, fileHandler),
		))

		fmt.Fprintf(os.Stderr, "Logging to file: %s\n", logFilePath)
	} else {
		slog.SetDefault(slog.New(consoleHandler))
	}

	return nil
}

// parseLogLevel converts a string log level to slog.Level
func parseLogLevel(levelStr string) slog.Level {
	switch levelStr {
	case "debug":
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
