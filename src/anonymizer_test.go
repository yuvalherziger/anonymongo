package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// Split path by dots, but allow escaping with backslash
func splitPath(path string) []string {
	var parts []string
	var current string
	escaped := false
	for _, r := range path {
		switch {
		case escaped:
			current += string(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '.':
			parts = append(parts, current)
			current = ""
		default:
			current += string(r)
		}
	}
	parts = append(parts, current)
	return parts
}

// Updated getJSONPath to use OrderedMap
func getJSONPath(m interface{}, path string) interface{} {
	parts := splitPath(path)
	var v interface{} = m
	for _, p := range parts {
		switch vv := v.(type) {
		case OrderedMap:
			val, _ := vv.Get(p)
			v = val
		case map[string]interface{}:
			v = vv[p]
		case []OrderedMap:
			// Try to parse p as an index
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(vv) {
				return nil
			}
			v = vv[idx]
		case []any:
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(vv) {
				return nil
			}
			v = vv[idx]
		default:
			return nil
		}
	}
	return v
}

// Helper function to get type information for debugging
func getTypeInfo(v interface{}) string {
	if v == nil {
		return "nil"
	}
	return fmt.Sprintf("%T: %v", v, v)
}

// Helper function to compare values more robustly
func valuesEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Handle numeric type conversions
	switch av := a.(type) {
	case float64:
		switch bv := b.(type) {
		case float64:
			return av == bv
		case int:
			return av == float64(bv)
		case int64:
			return av == float64(bv)
		case json.Number:
			if bf, err := bv.Float64(); err == nil {
				return av == bf
			}
		}
	case int:
		switch bv := b.(type) {
		case int:
			return av == bv
		case float64:
			return float64(av) == bv
		case json.Number:
			if bf, err := bv.Float64(); err == nil {
				return float64(av) == bf
			}
		}
	case json.Number:
		if af, err := av.Float64(); err == nil {
			switch bv := b.(type) {
			case float64:
				return af == bv
			case int:
				return af == float64(bv)
			case json.Number:
				if bf, err := bv.Float64(); err == nil {
					return af == bf
				}
			}
		}
	}

	// For slices and arrays, handle numeric type conversions within slices
	if reflect.TypeOf(a).Kind() == reflect.Slice {
		if reflect.TypeOf(b).Kind() == reflect.Slice {
			// Convert both slices to comparable format
			aSlice := reflect.ValueOf(a)
			bSlice := reflect.ValueOf(b)

			if aSlice.Len() != bSlice.Len() {
				return false
			}

			for i := 0; i < aSlice.Len(); i++ {
				aElem := aSlice.Index(i).Interface()
				bElem := bSlice.Index(i).Interface()

				// Convert numeric elements to float64 for comparison
				var aFloat, bFloat float64
				var aOk, bOk bool

				switch v := aElem.(type) {
				case float64:
					aFloat = v
					aOk = true
				case int:
					aFloat = float64(v)
					aOk = true
				case json.Number:
					if f, err := v.Float64(); err == nil {
						aFloat = f
						aOk = true
					}
				}

				switch v := bElem.(type) {
				case float64:
					bFloat = v
					bOk = true
				case int:
					bFloat = float64(v)
					bOk = true
				case json.Number:
					if f, err := v.Float64(); err == nil {
						bFloat = f
						bOk = true
					}
				}

				// If both are numeric, compare as floats
				if aOk && bOk {
					if aFloat != bFloat {
						return false
					}
				} else {
					// Otherwise use reflect.DeepEqual
					if !reflect.DeepEqual(aElem, bElem) {
						return false
					}
				}
			}
			return true
		}
	}

	// Default comparison
	return reflect.DeepEqual(a, b)
}

func TestRedactMongoLog_Parameterized(t *testing.T) {
	cases := AnonymizerTestParams()

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			tc.Options()
			data, err := os.ReadFile(filepath.Join("../test_fixtures", tc.InputFile))
			if err != nil {
				t.Fatalf("failed to read test log file: %v", err)
			}
			entry, err := RedactMongoLog(string(data))
			if err != nil {
				t.Fatalf("RedactMongoLog failed: %v", err)
			}
			// attrBytes, _ := MarshalOrdered(entry.Attr)
			// var attrMap OrderedMap
			// attrMap, _ = UnmarshalOrdered(attrBytes)
			for path, want := range tc.ExpectedPaths {
				gotVal, _ := entry.Get("attr")
				got := getJSONPath(gotVal, path)
				if !valuesEqual(got, want) {
					t.Errorf("expected %s to be %s, got %s", path, getTypeInfo(want), getTypeInfo(got))
				}
			}
		})
	}
}
