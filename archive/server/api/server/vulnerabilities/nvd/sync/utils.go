package nvdsync

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
)

// CompressFile compresses a file using gzip and writes it to a new file
// with the given name and removes the old file.
func CompressFile(fileName string, newFileName string) error {
	// Read old file
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	read := bufio.NewReader(file)
	data, err := io.ReadAll(read)
	if err != nil {
		return err
	}

	// Write new file
	newFile, err := os.Create(newFileName)
	if err != nil {
		return err
	}
	defer newFile.Close()

	writer := gzip.NewWriter(newFile)
	defer writer.Close()
	if _, err = writer.Write(data); err != nil {
		return err
	}

	// Remove old file
	if err = os.Remove(fileName); err != nil {
		return err
	}

	return nil
}
