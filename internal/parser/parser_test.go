package parser_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"reflect"
	"testing"

	"github.com/ossyrian/mintyparse/internal/parser"
	"github.com/ossyrian/mintyparse/internal/wz"
)

// buildValidHeader creates a valid WZ header byte sequence for testing
func buildValidHeader(fileSize uint64, copyright string) []byte {
	buf := new(bytes.Buffer)

	// Write magic
	buf.Write([]byte{'P', 'K', 'G', '1'})

	// Write file size (little endian uint64)
	binary.Write(buf, binary.LittleEndian, fileSize)

	// Write data offset (little endian uint32)
	// DataOffset = magic(4) + fileSize(8) + dataOffset(4) + copyright length
	dataOffset := uint32(16 + len(copyright))
	binary.Write(buf, binary.LittleEndian, dataOffset)

	// Write copyright (plain bytes)
	buf.Write([]byte(copyright))

	return buf.Bytes()
}

func TestWzReader_ReadHeader(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *wz.Header
		wantErr bool
		errMsg  string
	}{
		{
			name:  "valid header with minimal copyright",
			input: buildValidHeader(500000, "Test"),
			want: &wz.Header{
				Magic:      [4]byte{'P', 'K', 'G', '1'},
				FileSize:   500000,
				DataOffset: 20,
				Copyright:  "test",
			},
			wantErr: false,
		},
		{
			name:  "valid header with empty copyright",
			input: buildValidHeader(100000, ""),
			want: &wz.Header{
				Magic:      [4]byte{'P', 'K', 'G', '1'},
				FileSize:   100000,
				DataOffset: 16,
				Copyright:  "",
			},
			wantErr: false,
		},
		{
			name:    "invalid magic number",
			input:   append([]byte{'P', 'K', 'G', '2'}, make([]byte, 100)...),
			wantErr: true,
			errMsg:  "invalid WZ magic",
		},
		{
			name:    "EOF when reading magic",
			input:   []byte{'P', 'K'},
			wantErr: true,
			errMsg:  "failed to read magic",
		},
		{
			name:    "EOF when reading file size",
			input:   []byte{'P', 'K', 'G', '1', 0x00, 0x00},
			wantErr: true,
			errMsg:  "failed to read file size",
		},
		{
			name: "EOF when reading data offset",
			input: func() []byte {
				buf := new(bytes.Buffer)
				buf.Write([]byte{'P', 'K', 'G', '1'})
				binary.Write(buf, binary.LittleEndian, uint64(1000))
				buf.Write([]byte{0x00, 0x00}) // incomplete uint32
				return buf.Bytes()
			}(),
			wantErr: true,
			errMsg:  "failed to read data start offset",
		},
		{
			name: "invalid data offset (too small)",
			input: func() []byte {
				buf := new(bytes.Buffer)
				buf.Write([]byte{'P', 'K', 'G', '1'})
				binary.Write(buf, binary.LittleEndian, uint64(1000))
				binary.Write(buf, binary.LittleEndian, uint32(10)) // offset < 16
				return buf.Bytes()
			}(),
			wantErr: true,
			errMsg:  "invalid DataOffset value",
		},
		{
			name: "EOF when reading copyright",
			input: func() []byte {
				buf := new(bytes.Buffer)
				buf.Write([]byte{'P', 'K', 'G', '1'})
				binary.Write(buf, binary.LittleEndian, uint64(1000))
				binary.Write(buf, binary.LittleEndian, uint32(50)) // expects 34 bytes of copyright
				buf.Write([]byte("short"))                         // only 5 bytes
				return buf.Bytes()
			}(),
			wantErr: true,
			errMsg:  "failed to read copyright",
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
			errMsg:  "failed to read magic",
		},
		{
			name:  "large file size",
			input: buildValidHeader(999999999999, "Large file test"),
			want: &wz.Header{
				Magic:      [4]byte{'P', 'K', 'G', '1'},
				FileSize:   999999999999,
				DataOffset: 31, // 16 + len("Large file test") = 16 + 15 = 31
				Copyright:  "Large file test",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.input)
			r := &parser.WzReader{}

			// Use reflection to set the private file field
			// This is necessary because WzReader.file is unexported
			setReaderFile(t, r, reader)

			got, err := r.ReadHeader()

			if tt.wantErr {
				if err == nil {
					t.Fatal("ReadHeader() succeeded unexpectedly, wanted error")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ReadHeader() error = %v, should contain %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ReadHeader() failed: %v", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadHeader() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// setReaderFile uses reflection to set the unexported file field in WzReader
func setReaderFile(t *testing.T, r *parser.WzReader, reader io.ReadSeeker) {
	t.Helper()

	v := reflect.ValueOf(r).Elem()
	fileField := v.FieldByName("file")

	if !fileField.IsValid() {
		t.Fatal("field 'file' not found in WzReader")
	}

	// Use unsafe reflection to set unexported field
	fileField = reflect.NewAt(fileField.Type(), fileField.Addr().UnsafePointer()).Elem()
	fileField.Set(reflect.ValueOf(reader))
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
