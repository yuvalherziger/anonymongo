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
	"time"

	"github.com/schollz/progressbar/v3"
)

var (
	atlasLogStartDate  = 0
	atlasLogEndDate    = 0
	defaultLogDuration = 60 * 60 * 24 * 7 // 7 days
)

func SetAtlasLogStartDate(startDate int) { atlasLogStartDate = startDate }
func SetAtlasLogEndDate(endDate int)     { atlasLogEndDate = endDate }

func GetStartAndEndDates() (int, int) {
	if atlasLogStartDate == 0 && atlasLogEndDate == 0 {
		now := int(time.Now().Unix())
		return now - defaultLogDuration, now
	}
	if atlasLogStartDate == 0 {
		atlasLogStartDate = atlasLogEndDate - defaultLogDuration
	}
	if atlasLogEndDate == 0 {
		atlasLogEndDate = atlasLogStartDate + defaultLogDuration
	}
	return atlasLogStartDate, atlasLogEndDate
}

// FileReader defines the interface for file system operations needed by ProcessMongoLogFile.
// This allows mocking file system access in tests.
type FileReader interface {
	Open(filePath string) (io.ReadCloser, error)
	GetExtension(filePath string) string
}

// DefaultFileReader implements FileReader using standard os and filepath functions.
type DefaultFileReader struct{}

// Open implements the Open method of FileReader using os.Open.
func (d *DefaultFileReader) Open(filePath string) (io.ReadCloser, error) {
	return os.Open(filePath)
}

// GetExtension implements the GetExtension method of FileReader using filepath.Ext.
func (d *DefaultFileReader) GetExtension(filePath string) string {
	return strings.ToLower(filepath.Ext(filePath))
}

func addOneToBar(bar *progressbar.ProgressBar) {
	if bar != nil {
		err := bar.Add(1)
		if err != nil {
			// In a real application, you might log this error.
			// For a progress bar, silently returning is often acceptable.
			return
		}
	}
}

func processMongoLogStream(r io.Reader, outWriter io.Writer, bar *progressbar.ProgressBar) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		// Ensure bar is not nil before accessing its state to prevent panics.
		// The condition itself (empty line at max progress) is specific to the original logic.
		if line == "" && bar != nil && bar.State().CurrentNum == bar.GetMax64() {
			addOneToBar(bar)
			continue
		}
		// RedactMongoLog is not provided in the context, assuming it's defined elsewhere.
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
		// addOneToBar already handles the nil check for 'bar', so no need for an 'if' here.
		addOneToBar(bar)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// ProcessMongoLogFile processes a MongoDB log file from the given filePath.
// It now accepts a FileReader interface, allowing for dependency injection.
// In production, you would pass &DefaultFileReader{}. In tests, you can pass a mock.
func ProcessMongoLogFile(fileReader FileReader, filePath string, outWriter io.Writer, bar *progressbar.ProgressBar) error {
	file, err := fileReader.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	ext := fileReader.GetExtension(filePath)
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
// This function remains unchanged as it already accepts an io.Reader and doesn't directly access the filesystem.
func ProcessMongoLogFileFromReader(r io.Reader, outWriter io.Writer, bar *progressbar.ProgressBar) error {
	return processMongoLogStream(r, outWriter, bar)
}

// No changes needed here for Atlas mode; all orchestration is handled in main.go
