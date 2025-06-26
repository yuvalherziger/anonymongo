package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// TestCountLines verifies the line counting logic against various inputs.
func TestCountLines(t *testing.T) {
	testCases := []struct {
		name          string
		fileContent   string
		expectedLines int
	}{
		{
			name:          "Empty file",
			fileContent:   "",
			expectedLines: 0,
		},
		{
			name:          "Single line with newline",
			fileContent:   "hello world\n",
			expectedLines: 1,
		},
		{
			name:          "Single line without trailing newline",
			fileContent:   "hello world",
			expectedLines: 0, // Correctly counts '\n' characters, not logical lines
		},
		{
			name:          "Multiple lines with trailing newline",
			fileContent:   "line 1\nline 2\nline 3\n",
			expectedLines: 3,
		},
		{
			name:          "Multiple lines without trailing newline",
			fileContent:   "line 1\nline 2",
			expectedLines: 1,
		},
		{
			name:          "File containing only newlines",
			fileContent:   "\n\n\n",
			expectedLines: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange: Set up the mock reader to return the test case content.
			mockReader := &MockFileReader{
				MockOpen: func(filePath string) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(tc.fileContent)), nil
				},
			}

			// Act: Call the function under test.
			count, err := countLines(mockReader, "fakefile.txt")

			// Assert: Check for errors and correct line count.
			if err != nil {
				t.Fatalf("countLines returned an unexpected error: %v", err)
			}
			if count != tc.expectedLines {
				t.Errorf("Expected %d lines, but got %d", tc.expectedLines, count)
			}
		})
	}
}

// TestCountLines_FileOpenError ensures that errors from the FileReader are propagated correctly.
func TestCountLines_FileOpenError(t *testing.T) {
	// Arrange
	expectedErr := errors.New("permission denied")
	mockReader := &MockFileReader{
		MockOpen: func(filePath string) (io.ReadCloser, error) {
			return nil, expectedErr
		},
	}

	// Act
	count, err := countLines(mockReader, "unreadable.txt")

	// Assert
	if err == nil {
		t.Fatal("Expected an error but got nil")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error '%v', but got '%v'", expectedErr, err)
	}
	if count != 0 {
		t.Errorf("Expected count to be 0 on error, but got %d", count)
	}
}

// TestIndexOf tests the byte-searching utility function.
func TestIndexOf(t *testing.T) {
	testCases := []struct {
		name     string
		haystack []byte
		needle   []byte
		expected int
	}{
		{"Found at start", []byte("hello world"), []byte("hello"), 0},
		{"Found in middle", []byte("hello world"), []byte("world"), 6},
		{"Not found", []byte("hello world"), []byte("goodbye"), -1},
		{"Empty needle", []byte("hello world"), []byte(""), 0},
		{"Empty haystack", []byte(""), []byte("hello"), -1},
		{"Both empty", []byte(""), []byte(""), 0},
		{"Needle longer than haystack", []byte("hi"), []byte("hello"), -1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := indexOf(tc.haystack, tc.needle)
			if result != tc.expected {
				t.Errorf("For haystack '%s' and needle '%s', expected index %d, but got %d", tc.haystack, tc.needle, tc.expected, result)
			}
		})
	}
}

// TestCountOccurrences tests the occurrence counting utility function.
func TestCountOccurrences(t *testing.T) {
	testCases := []struct {
		name     string
		haystack []byte
		needle   []byte
		expected int
	}{
		{"Multiple occurrences of newline", []byte("one\ntwo\nthree\n"), []byte("\n"), 3},
		{"No occurrences", []byte("one two three"), []byte("\n"), 0},
		{"Multiple occurrences of multi-byte separator", []byte("ab-ab-ab-"), []byte("ab-"), 3},
		{"Empty haystack", []byte(""), []byte("\n"), 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := countOccurrences(tc.haystack, tc.needle)
			if result != tc.expected {
				t.Errorf("For haystack '%s' and needle '%s', expected count %d, but got %d", tc.haystack, tc.needle, tc.expected, result)
			}
		})
	}
}
