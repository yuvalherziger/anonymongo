package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"            // Added for reading fixture files
	"path/filepath" // Added for path manipulation
	"runtime"       // Added for getting current file path
	"strings"
	"testing"
)

// MockFileReader is a test implementation of the FileReader interface.
// It allows us to simulate file operations without touching the disk.
type MockFileReader struct {
	// MockOpen is a function that will be called when Open is invoked.
	MockOpen func(filePath string) (io.ReadCloser, error)
	// MockGetExtension is a function that will be called when GetExtension is invoked.
	MockGetExtension func(filePath string) string
}

// Open implements the FileReader.Open method for testing.
func (m *MockFileReader) Open(filePath string) (io.ReadCloser, error) {
	if m.MockOpen != nil {
		return m.MockOpen(filePath)
	}
	// Return a default error if the mock function is not provided.
	return nil, errors.New("MockOpen not implemented")
}

// GetExtension implements the FileReader.GetExtension method for testing.
func (m *MockFileReader) GetExtension(filePath string) string {
	if m.MockGetExtension != nil {
		return m.MockGetExtension(filePath)
	}
	// Return a default value if the mock function is not provided.
	return ""
}

// getFixtureContent reads a fixture file, removes line breaks, and returns its content.
// It uses t.Fatalf for unrecoverable errors during test setup.
func getFixtureContent(t *testing.T, fixturePath string) string {
	// Get the directory of the current test file.
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("Failed to get current file path for fixture loading")
	}
	currentDir := filepath.Dir(currentFile)

	// Construct the full path to the fixture.
	// Assuming reader_test.go is in src/ and fixtures are in test_fixtures/
	fullPath := filepath.Join(currentDir, "..", fixturePath)

	contentBytes, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("Failed to read fixture file %s: %v", fullPath, err)
	}

	content := string(contentBytes)
	// Remove all newline characters (both Unix and Windows style)
	content = strings.ReplaceAll(content, "\n", "")
	content = strings.ReplaceAll(content, "\r", "")
	return content
}

// generateExpectedOutput generates the expected JSON output based on the mock RedactMongoLog.
// It marshals the result of RedactMongoLog and appends a newline.
func generateExpectedOutput(t *testing.T, inputLine string) string {
	redacted, err := RedactMongoLog(inputLine)
	if err != nil {
		t.Fatalf("Mock RedactMongoLog failed for input '%s': %v", inputLine, err)
	}
	out, err := MarshalOrdered(redacted)
	if err != nil {
		t.Fatalf("Failed to marshal redacted output for test: %v", err)
	}
	return string(out) + "\n"
}

// TestProcessMongoLogFile_Standard tests processing a standard, non-gzipped log file.
func TestProcessMongoLogFile_Standard(t *testing.T) {
	logContent := getFixtureContent(t, "test_fixtures/simple_find.json")
	expectedOutput := generateExpectedOutput(t, logContent)

	// Create a mock FileReader that simulates reading a plain text file.
	mockReader := &MockFileReader{
		MockOpen: func(filePath string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(logContent)), nil
		},
		MockGetExtension: func(filePath string) string {
			return ".log" // Simulate a non-gzipped file extension.
		},
	}

	var outBuffer bytes.Buffer
	// Call the function under test with the mock reader.
	err := ProcessMongoLogFile(mockReader, "/fake/path/test.log", &outBuffer, nil)

	if err != nil {
		t.Fatalf("ProcessMongoLogFile returned an unexpected error: %v", err)
	}

	if outBuffer.String() != expectedOutput {
		t.Errorf("Unexpected output.\nGot:\n%s\nWant:\n%s", outBuffer.String(), expectedOutput)
	}
}

// TestProcessMongoLogFile_Gzip tests processing a gzipped log file.
func TestProcessMongoLogFile_Gzip(t *testing.T) {
	logContent := getFixtureContent(t, "test_fixtures/simple_find.json")

	// Prepare mock gzipped content in memory.
	var gzippedBuffer bytes.Buffer
	gzWriter := gzip.NewWriter(&gzippedBuffer)
	_, err := gzWriter.Write([]byte(logContent)) // Write the processed fixture content
	if err != nil {
		t.Fatalf("Failed to create gzip data for test: %v", err)
	}
	gzWriter.Close()

	expectedOutput := generateExpectedOutput(t, logContent)

	// Create a mock FileReader that simulates reading a gzipped file.
	mockReader := &MockFileReader{
		MockOpen: func(filePath string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(gzippedBuffer.Bytes())), nil
		},
		MockGetExtension: func(filePath string) string {
			return ".gz" // Simulate a gzipped file extension.
		},
	}

	var outBuffer bytes.Buffer
	err = ProcessMongoLogFile(mockReader, "/fake/path/test.log.gz", &outBuffer, nil)

	if err != nil {
		t.Fatalf("ProcessMongoLogFile returned an unexpected error for gzip: %v", err)
	}

	if outBuffer.String() != expectedOutput {
		t.Errorf("Unexpected gzip output.\nGot:\n%s\nWant:\n%s", outBuffer.String(), expectedOutput)
	}
}

// TestProcessMongoLogFile_FileOpenError tests the behavior when the file cannot be opened.
func TestProcessMongoLogFile_FileOpenError(t *testing.T) {
	expectedErr := errors.New("simulated file not found")

	// Create a mock FileReader that returns an error on Open.
	mockReader := &MockFileReader{
		MockOpen: func(filePath string) (io.ReadCloser, error) {
			return nil, expectedErr
		},
		MockGetExtension: func(filePath string) string {
			return ".log"
		},
	}

	var outBuffer bytes.Buffer
	err := ProcessMongoLogFile(mockReader, "/fake/path/nonexistent.log", &outBuffer, nil)

	if err == nil {
		t.Fatal("Expected an error, but got none")
	}

	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error '%v', but got '%v'", expectedErr, err)
	}

	if outBuffer.Len() > 0 {
		t.Errorf("Expected no output on error, but got: %s", outBuffer.String())
	}
}

// TestProcessMongoLogFile_GzipReaderError tests behavior with corrupted gzip data.
func TestProcessMongoLogFile_GzipReaderError(t *testing.T) {
	// This is not a valid gzip header, so gzip.NewReader should fail.
	invalidGzipContent := []byte("this is not gzipped")

	mockReader := &MockFileReader{
		MockOpen: func(filePath string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(invalidGzipContent)), nil
		},
		MockGetExtension: func(filePath string) string {
			return ".gz"
		},
	}

	var outBuffer bytes.Buffer
	err := ProcessMongoLogFile(mockReader, "/fake/path/corrupted.log.gz", &outBuffer, nil)

	if err == nil {
		t.Fatal("Expected an error for corrupted gzip data, but got none")
	}

	expectedErrorString := "failed to create gzip reader"
	if !strings.Contains(err.Error(), expectedErrorString) {
		t.Errorf("Expected error message to contain '%s', but got: %v", expectedErrorString, err)
	}
}

// TestProcessMongoLogFileFromReader tests the function that processes from an io.Reader.
func TestProcessMongoLogFileFromReader(t *testing.T) {
	logContent := getFixtureContent(t, "test_fixtures/simple_find.json")
	expectedOutput := generateExpectedOutput(t, logContent)

	inputReader := strings.NewReader(logContent)
	var outBuffer bytes.Buffer

	err := ProcessMongoLogFileFromReader(inputReader, &outBuffer, nil)

	if err != nil {
		t.Fatalf("ProcessMongoLogFileFromReader returned an unexpected error: %v", err)
	}

	if outBuffer.String() != expectedOutput {
		t.Errorf("Unexpected output from reader.\nGot:\n%s\nWant:\n%s", outBuffer.String(), expectedOutput)
	}
}
