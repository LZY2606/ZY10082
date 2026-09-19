package forensic

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
)

func zipList(r io.Reader) ([]byte, string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxDeriveInput+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(data)) > maxDeriveInput {
		return nil, "", fmt.Errorf("%w: archive too large for ziplist", ErrInvalidInput)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, "", fmt.Errorf("ziplist: %w", err)
	}
	var b strings.Builder
	for _, f := range zr.File {
		fmt.Fprintf(&b, "%-10d  %s\n", f.UncompressedSize64, f.Name)
	}
	return []byte(b.String()), "", nil
}
