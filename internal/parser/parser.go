package parser

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/ossyrian/mintyparse/internal/wz"
)

// WzReader reads information from WZ files.
type WzReader struct {
	file io.ReadSeeker
}

// ReadHeader reads header information from a WZ file.
func (r *WzReader) ReadHeader() (*wz.Header, error) {
	h := &wz.Header{}

	if _, err := io.ReadFull(r.file, h.Magic[:]); err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}

	if h.Magic != wz.Magic {
		return nil, fmt.Errorf("invalid WZ magic: expected %q, got %q",
			wz.Magic, h.Magic)
	}

	if err := binary.Read(r.file, binary.LittleEndian, &h.FileSize); err != nil {
		return nil, fmt.Errorf("failed to read file size: %w", err)
	}

	if err := binary.Read(r.file, binary.LittleEndian, &h.DataOffset); err != nil {
		return nil, fmt.Errorf("failed to read data start offset: %w", err)
	}

	// read offset = magic (4) + file size (8) + offset (4) = 16
	copyrightLen := int(h.DataOffset) - 16 // this many bytes to get to data start
	if copyrightLen < 0 {
		return nil, fmt.Errorf("invalid DataOffset value: %d", h.DataOffset)
	}

	copyrightBytes := make([]byte, copyrightLen)
	if _, err := io.ReadFull(r.file, copyrightBytes); err != nil {
		return nil, fmt.Errorf("failed to read copyright: %w", err)
	}
	h.Copyright = string(copyrightBytes)

	return h, nil
}

func Parse(file *os.File) error {
	reader := &WzReader{file: file}

	header, err := reader.ReadHeader()
	if err != nil {
		return err
	}

	slog.Info("it worked", "header", header)

	return nil
}
