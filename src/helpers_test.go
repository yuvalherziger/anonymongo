package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestParsePlanSummary(t *testing.T) {
	testCases := []struct {
		name        string
		planSummary string
		expected    []string
	}{
		{
			name:        "Empty plan summary",
			planSummary: "",
			expected:    []string{},
		},
		{
			name:        "No IXSCAN stage",
			planSummary: "COLLSCAN",
			expected:    []string{},
		},
		{
			name:        "Single IXSCAN with one field",
			planSummary: "IXSCAN { a: 1 }",
			expected:    []string{"a"},
		},
		{
			name:        "Single IXSCAN with multiple fields",
			planSummary: "IXSCAN { b: -1, a: 1 }",
			expected:    []string{"a", "b"},
		},
		{
			name:        "Single IXSCAN with compound field",
			planSummary: "IXSCAN { a.b: 1 }",
			expected:    []string{"a", "b"},
		},
		{
			name:        "Single IXSCAN with multiple compound fields",
			planSummary: "IXSCAN { c.d: 1, a.b: 1 }",
			expected:    []string{"a", "b", "c", "d"},
		},
		{
			name:        "Multiple IXSCAN stages with duplicates",
			planSummary: "IXSCAN { c: 1 } IXSCAN { a: 1, b: 1, c: 1 }",
			expected:    []string{"a", "b", "c"},
		},
		{
			name:        "IXSCAN with extra whitespace",
			planSummary: "IXSCAN  {  b : -1,  a:1 }",
			expected:    []string{"a", "b"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ParsePlanSummary(tc.planSummary)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("ParsePlanSummary() got = %v, want %v", actual, tc.expected)
			}
		})
	}
}

func TestHashFieldName(t *testing.T) {
	originalRedactedString := redactedString
	redactedString = "REDACTED"
	defer func() { redactedString = originalRedactedString }()

	calcHash := func(part string) string {
		h := sha256.Sum256([]byte(part))
		return fmt.Sprintf("%s_%x", redactedString, h[:8])
	}

	testCases := []struct {
		name         string
		field        string
		expectedHash string
		expectedMap  map[string]string
	}{
		{
			name:         "Simple field",
			field:        "myField",
			expectedHash: calcHash("myField"),
			expectedMap:  map[string]string{"myField": calcHash("myField")},
		},
		{
			name:         "Compound field",
			field:        "myObject.myField",
			expectedHash: fmt.Sprintf("%s.%s", calcHash("myObject"), calcHash("myField")),
			expectedMap:  map[string]string{"myObject": calcHash("myObject"), "myField": calcHash("myField")},
		},
		{
			name:         "Field with leading dollar sign",
			field:        "$match",
			expectedHash: calcHash("match"),
			expectedMap:  map[string]string{"match": calcHash("match")},
		},
		{
			name:         "Empty field",
			field:        "",
			expectedHash: calcHash(""),
			expectedMap:  map[string]string{"": calcHash("")},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			RedactedFieldMapping = make(map[string]string)

			actualHash := HashFieldName(tc.field)

			if actualHash != tc.expectedHash {
				t.Errorf("HashFieldName() hash = %q, want %q", actualHash, tc.expectedHash)
			}

			if !reflect.DeepEqual(RedactedFieldMapping, tc.expectedMap) {
				t.Errorf("HashFieldName() map = %v, want %v", RedactedFieldMapping, tc.expectedMap)
			}
		})
	}
}

func TestRemoveElementAfter(t *testing.T) {
	testCases := []struct {
		name     string
		slice    []string
		marker   string
		expected []string
	}{
		{
			name:     "Marker in the middle",
			slice:    []string{"a", "b", "c", "d"},
			marker:   "b",
			expected: []string{"a", "b", "d"},
		},
		{
			name:     "Marker at the beginning",
			slice:    []string{"a", "b", "c"},
			marker:   "a",
			expected: []string{"a", "c"},
		},
		{
			name:     "Marker at the end (no change)",
			slice:    []string{"a", "b", "c"},
			marker:   "c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Marker not found (no change)",
			slice:    []string{"a", "b", "c"},
			marker:   "d",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Empty slice",
			slice:    []string{},
			marker:   "a",
			expected: []string{},
		},
		{
			name:     "Slice with one element",
			slice:    []string{"a"},
			marker:   "a",
			expected: []string{"a"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RemoveElementAfter(tc.slice, tc.marker)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("RemoveElementAfter() = %v, want %v", actual, tc.expected)
			}
		})
	}
}

func TestRemoveElementsBeforeIncluding(t *testing.T) {
	testCases := []struct {
		name     string
		slice    []string
		marker   string
		expected []string
	}{
		{
			name:     "Marker in the middle",
			slice:    []string{"a", "b", "c", "d"},
			marker:   "b",
			expected: []string{"c", "d"},
		},
		{
			name:     "Marker at the beginning",
			slice:    []string{"a", "b", "c"},
			marker:   "a",
			expected: []string{"b", "c"},
		},
		{
			name:     "Marker at the end",
			slice:    []string{"a", "b", "c"},
			marker:   "c",
			expected: []string{},
		},
		{
			name:     "Marker not found",
			slice:    []string{"a", "b", "c"},
			marker:   "d",
			expected: []string{},
		},
		{
			name:     "Empty slice",
			slice:    []string{},
			marker:   "a",
			expected: []string{},
		},
		{
			name:     "Slice with one element",
			slice:    []string{"a"},
			marker:   "a",
			expected: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RemoveElementsBeforeIncluding(tc.slice, tc.marker)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("RemoveElementsBeforeIncluding() = %v, want %v", actual, tc.expected)
			}
		})
	}
}
