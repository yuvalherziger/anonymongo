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

func addOneToBar(bar *progressbar.ProgressBar) {
	if bar != nil {
		err := bar.Add(1)
		if err != nil {
			return
		}
	}
}

func processMongoLogStream(r io.Reader, outWriter io.Writer, bar *progressbar.ProgressBar) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" && bar.State().CurrentNum == bar.GetMax64() {
			addOneToBar(bar)
			continue
		}
		redacted, err := RedactMongoLog(line)
		if err != nil {
			addOneToBar(bar)
			continue
		}
		out, err := json.Marshal(redacted)
		if err != nil {
			addOneToBar(bar)
			continue
		}
		fmt.Fprintln(outWriter, string(out))
		if bar != nil {
			addOneToBar(bar)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

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
