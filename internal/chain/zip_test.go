package chain

import (
	"archive/zip"
	"io"
	"os"
	"testing"
)

func rewriteZipEntry(t *testing.T, sourcePath, destinationPath, entryName string, transform func([]byte) []byte) {
	t.Helper()
	reader, err := zip.OpenReader(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	output, err := os.Create(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	writer := zip.NewWriter(output)
	for _, file := range reader.File {
		entry, err := writer.Create(file.Name)
		if err != nil {
			t.Fatal(err)
		}
		readCloser, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(readCloser)
		readCloser.Close()
		if err != nil {
			t.Fatal(err)
		}
		if file.Name == entryName {
			data = transform(data)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}
