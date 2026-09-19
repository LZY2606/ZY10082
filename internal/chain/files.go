package chain

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func writeStreaming(destination string, reader io.Reader) (Hashes, int64, error) {
	if err := ensureDir(filepath.Dir(destination)); err != nil {
		return Hashes{}, 0, err
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return Hashes{}, 0, err
	}
	hasher := newMultiHasher()
	target := io.MultiWriter(file, hasher)
	size, writeErr := io.Copy(target, reader)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		os.Remove(destination)
		return Hashes{}, 0, writeErr
	}
	if syncErr != nil {
		os.Remove(destination)
		return Hashes{}, 0, syncErr
	}
	if closeErr != nil {
		os.Remove(destination)
		return Hashes{}, 0, closeErr
	}
	return hasher.hashes(), size, nil
}

func blockFileName(number int) string {
	return fmt.Sprintf("block-%08d.bin", number)
}

func writeManifest(path string, batch Batch) error {
	temp := path + ".tmp"
	data, err := json.MarshalIndent(batchManifest{Batch: batch}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(temp, data, 0o640); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func readManifest(path string) (Batch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Batch{}, err
	}
	var manifest batchManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Batch{}, err
	}
	return manifest.Batch, nil
}

func hashOrderedBlocks(dir string, blocks []BlockInfo) (Hashes, int64, error) {
	hasher := newMultiHasher()
	var total int64
	for _, block := range blocks {
		blockPath := filepath.Join(dir, blockFileName(block.Number))
		file, err := os.Open(blockPath)
		if err != nil {
			return Hashes{}, 0, err
		}
		hashes, size, err := hashReader(io.TeeReader(file, hasher))
		_ = file.Close()
		if err != nil {
			return Hashes{}, 0, err
		}
		if size != block.Size {
			return Hashes{}, 0, validationError("block %d size changed", block.Number)
		}
		if hashes != block.Hashes || size != block.Size {
			return Hashes{}, 0, validationError("block %d was altered after write", block.Number)
		}
		total += size
	}
	return hasher.hashes(), total, nil
}

func assembleBlocks(dir string, blocks []BlockInfo, destination string) error {
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		blockFile, err := os.Open(filepath.Join(dir, blockFileName(block.Number)))
		if err != nil {
			file.Close()
			os.Remove(destination)
			return err
		}
		if _, err := io.Copy(file, blockFile); err != nil {
			_ = blockFile.Close()
			file.Close()
			os.Remove(destination)
			return err
		}
		_ = blockFile.Close()
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(destination)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(destination)
		return err
	}
	return nil
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		os.Remove(destination)
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		os.Remove(destination)
		return err
	}
	return output.Close()
}
