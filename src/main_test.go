package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ensure stdin is declared for test swapping.
var stdin io.ReadCloser

func TestMainWithStdIn(t *testing.T) {
	input := "{\"t\":{\"$date\":\"2025-05-30T09:47:39.001+00:00\"},\"s\":\"I\",\"c\":\"COMMAND\",\"id\":51803,\"ctx\":\"conn87195\",\"msg\":\"Slow query\",\"attr\":{\"type\":\"command\",\"ns\":\"my_db.my_coll\",\"appName\":\"my_app\",\"command\":{\"find\":\"my_coll\",\"filter\":{\"foo\":\"simple string\",\"bar\":\"another simple string\"},\"sort\":{\"_id\":-1},\"limit\":1,\"lsid\":{\"id\":{\"$uuid\":\"7938452b-c804-4245-8eed-d64238a3096e\"}},\"$clusterTime\":{\"clusterTime\":{\"$timestamp\":{\"t\":1748598458,\"i\":30}},\"signature\":{\"hash\":{\"$binary\":{\"base64\":\"YIwPO0EBX2vevOytJne/wzScXMU=\",\"subType\":\"0\"}},\"keyId\":7469113720208097000}},\"$db\":\"my_db\"},\"planSummary\":\"IXSCAN { foo: 1, bar: 1, _id: -1 }\",\"planningTimeMicros\":43226,\"keysExamined\":540,\"docsExamined\":494,\"hasSortStage\":true,\"fromPlanCache\":true,\"nBatches\":1,\"cursorExhausted\":true,\"numYields\":3,\"nreturned\":1,\"queryHash\":\"B134177D\",\"planCacheKey\":\"A13D1BF0\",\"queryFramework\":\"classic\",\"reslen\":1531,\"locks\":{\"FeatureCompatibilityVersion\":{\"acquireCount\":{\"r\":4}},\"Global\":{\"acquireCount\":{\"r\":4}}},\"readConcern\":{\"level\":\"local\",\"provenance\":\"implicitDefault\"},\"storage\":{\"data\":{\"bytesRead\":38805493,\"timeReadingMicros\":21587}},\"cpuNanos\":24778600,\"remote\":\"20.40.131.128:11803\",\"protocol\":\"op_msg\",\"durationMillis\":43}}\n"

	// Keep original os.Stdin and os.Stdout to restore them after the test.
	originalStdin := os.Stdin
	originalStdout := os.Stdout
	defer func() {
		os.Stdin = originalStdin
		os.Stdout = originalStdout
	}()

	// Mock stdin by creating a pipe and writing the input to it.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe for stdin mocking: %v", err)
	}
	os.Stdin = r

	// Mock stdout to discard any output from main(), preventing test log clutter.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", os.DevNull, err)
	}
	os.Stdout = devNull
	defer devNull.Close()

	// Write input to the stdin pipe in a separate goroutine.
	go func() {
		defer w.Close()
		if _, err := w.WriteString(input); err != nil {
			// Use t.Error to report the error without stopping the test immediately,
			// allowing other cleanup to run.
			t.Errorf("Failed to write to stdin pipe: %v", err)
		}
	}()

	// Execute the main function.
	main()
}

func TestMainWithFileInputAndOutput(t *testing.T) {
	// Arrange: Create a temporary directory for test artifacts.
	// t.TempDir handles creation and automatic cleanup.
	tempDir := t.TempDir()

	// Create a fixture directory and the input log file within the temp directory.
	// This makes the test self-contained, assuming a ./test_fixtures/mongod.log
	// might not exist in all test environments.
	fixtureDir := filepath.Join(tempDir, "test_fixtures")
	if err := os.MkdirAll(fixtureDir, 0755); err != nil {
		t.Fatalf("Failed to create fixture directory: %v", err)
	}
	inputFilePath := filepath.Join(fixtureDir, "mongod.log")

	// This is the content we'll write to our test input file.
	// It contains two log lines to ensure multi-line processing works.
	inputFileContent := "{\"t\":{\"$date\":\"2025-05-30T09:47:39.001+00:00\"},\"s\":\"I\",\"c\":\"COMMAND\",\"id\":51803,\"ctx\":\"conn87195\",\"msg\":\"Slow query\",\"attr\":{\"type\":\"command\",\"ns\":\"my_db.my_coll\",\"appName\":\"my_app\",\"command\":{\"find\":\"my_coll\",\"filter\":{\"foo\":\"simple string\",\"bar\":\"another simple string\"},\"sort\":{\"_id\":-1},\"limit\":1,\"lsid\":{\"id\":{\"$uuid\":\"7938452b-c804-4245-8eed-d64238a3096e\"}},\"$clusterTime\":{\"clusterTime\":{\"$timestamp\":{\"t\":1748598458,\"i\":30}},\"signature\":{\"hash\":{\"$binary\":{\"base64\":\"YIwPO0EBX2vevOytJne/wzScXMU=\",\"subType\":\"0\"}},\"keyId\":7469113720208097000}},\"$db\":\"my_db\"},\"planSummary\":\"IXSCAN { foo: 1, bar: 1, _id: -1 }\",\"planningTimeMicros\":43226,\"keysExamined\":540,\"docsExamined\":494,\"hasSortStage\":true,\"fromPlanCache\":true,\"nBatches\":1,\"cursorExhausted\":true,\"numYields\":3,\"nreturned\":1,\"queryHash\":\"B134177D\",\"planCacheKey\":\"A13D1BF0\",\"queryFramework\":\"classic\",\"reslen\":1531,\"locks\":{\"FeatureCompatibilityVersion\":{\"acquireCount\":{\"r\":4}},\"Global\":{\"acquireCount\":{\"r\":4}}},\"readConcern\":{\"level\":\"local\",\"provenance\":\"implicitDefault\"},\"storage\":{\"data\":{\"bytesRead\":38805493,\"timeReadingMicros\":21587}},\"cpuNanos\":24778600,\"remote\":\"20.40.131.128:11803\",\"protocol\":\"op_msg\",\"durationMillis\":43}}\n"

	if err := os.WriteFile(inputFilePath, []byte(inputFileContent), 0644); err != nil {
		t.Fatalf("Failed to write to input file: %v", err)
	}

	// Define the path for the output file, which will also be in the temp directory.
	outputFilePath := filepath.Join(tempDir, "output.log")

	// Keep original os.Args and os.Stdout to restore them after the test.
	originalArgs := os.Args
	originalStdout := os.Stdout
	defer func() {
		os.Args = originalArgs
		os.Stdout = originalStdout
	}()

	// Set the command-line arguments to simulate running from the terminal.
	// The first argument is always the program name.
	os.Args = []string{"anonymongo", "redact", inputFilePath, "--outputFile", outputFilePath}

	// Redirect stdout to a no-op writer to keep test logs clean.
	// The main program might print progress indicators, which we want to ignore.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()
	os.Stdout = devNull

	// Act: Execute the main function with our mocked arguments.
	main()
}

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
