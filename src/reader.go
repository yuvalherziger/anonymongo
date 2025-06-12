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

	"github.com/schollz/progressbar/v3"
)

// processMongoLogStream reads from any io.Reader, redacts each line, and writes to outWriter.
// If bar is not nil, it increments the progress bar for each line.
func processMongoLogStream(r io.Reader, outWriter io.Writer, bar *progressbar.ProgressBar) error {
	scanner := bufio.NewScanner(r)
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
		if bar != nil {
			bar.Add(1)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// ProcessMongoLogFile reads a MongoDB log file (plain or gzipped), redacts each entry, and writes the result.
// If bar is not nil, it is updated as lines are processed.
func ProcessMongoLogFile(filePath string, outWriter io.Writer, bar *progressbar.ProgressBar) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".gz" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		return processMongoLogStream(gzReader, outWriter, bar)
	}
	return processMongoLogStream(file, outWriter, bar)
}

// ProcessMongoLogFileFromReader reads from any io.Reader (such as stdin), redacts each line, and writes the result.
// Progress bar is not used for stdin.
func ProcessMongoLogFileFromReader(r io.Reader, outWriter io.Writer, bar *progressbar.ProgressBar) error {
	return processMongoLogStream(r, outWriter, bar)
}
