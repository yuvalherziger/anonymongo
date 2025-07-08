package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"

	"github.com/elliotchance/orderedmap/v3"
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

func TestHashName(t *testing.T) {
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

			actualHash := HashName(tc.field)

			if actualHash != tc.expectedHash {
				t.Errorf("HashName() hash = %q, want %q", actualHash, tc.expectedHash)
			}

			if !reflect.DeepEqual(RedactedFieldMapping, tc.expectedMap) {
				t.Errorf("HashName() map = %v, want %v", RedactedFieldMapping, tc.expectedMap)
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

func TestMarshalOrdered(t *testing.T) {
	testCases := []struct {
		name      string
		input     OrderedMap
		expected  string
		expectErr bool
	}{
		{
			name:      "Empty map",
			input:     orderedmap.NewOrderedMap[string, any](),
			expected:  "{}",
			expectErr: false,
		},
		{
			name: "Simple map with sorted keys",
			input: func() OrderedMap {
				om := orderedmap.NewOrderedMap[string, any]()
				om.Set("a", 1)
				om.Set("b", "two")
				return om
			}(),
			expected:  `{"a":1,"b":"two"}`,
			expectErr: false,
		},
		{
			name: "Simple map with unsorted keys",
			input: func() OrderedMap {
				om := orderedmap.NewOrderedMap[string, any]()
				om.Set("b", "two")
				om.Set("a", 1)
				return om
			}(),
			expected:  `{"b":"two","a":1}`,
			expectErr: false,
		},
		{
			name: "Nested map",
			input: func() OrderedMap {
				om := orderedmap.NewOrderedMap[string, any]()
				nested := orderedmap.NewOrderedMap[string, any]()
				nested.Set("y", "z")
				nested.Set("x", 1)
				om.Set("c", 3)
				om.Set("a", nested)
				return om
			}(),
			expected:  `{"c":3,"a":{"y":"z","x":1}}`,
			expectErr: false,
		},
		{
			name: "Map with various data types",
			input: func() OrderedMap {
				om := orderedmap.NewOrderedMap[string, any]()
				om.Set("s", "hello")
				om.Set("n", 123.45)
				om.Set("b", true)
				om.Set("i", -5)
				om.Set("null", nil)
				return om
			}(),
			expected:  `{"s":"hello","n":123.45,"b":true,"i":-5,"null":null}`,
			expectErr: false,
		},
		{
			name: "Unsupported type",
			input: func() OrderedMap {
				om := orderedmap.NewOrderedMap[string, any]()
				om.Set("f", func() {})
				return om
			}(),
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := MarshalOrdered(tc.input)

			if (err != nil) != tc.expectErr {
				t.Errorf("MarshalOrdered() error = %v, wantErr %v", err, tc.expectErr)
				return
			}

			if !tc.expectErr && string(actual) != tc.expected {
				t.Errorf("MarshalOrdered() got = %q, want %q", actual, tc.expected)
			}
		})
	}
}
