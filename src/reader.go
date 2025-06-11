package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ProcessMongoLogFile reads a MongoDB log file line-by-line, redacts each entry, and writes the result to the provided writer.
// It supports both plain JSON files and gzipped JSON files (.gz).
func ProcessMongoLogFile(filePath string, outWriter io.Writer) error {
	var file *os.File
	var err error

	file, err = os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var scanner *bufio.Scanner

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".gz" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		scanner = bufio.NewScanner(gzReader)
	} else {
		scanner = bufio.NewScanner(file)
	}

	for scanner.Scan() {
		line := scanner.Text()
		redacted, err := RedactMongoLog(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to redact line: %v\n", err)
			continue
		}
		out, err := json.Marshal(redacted)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal redacted log: %v\n", err)
			continue
		}
		fmt.Fprintln(outWriter, string(out))
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
