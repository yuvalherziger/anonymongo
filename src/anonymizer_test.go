package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Test case definition for parameterized redactr tests
type RedactTestCase struct {
	Name          string
	InputFile     string
	Options       func()
	ExpectedPaths map[string]interface{} // JSON path -> expected value
}

// Example option sets
func setOptionsRedactedStrings() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(false)
	SetRedactBooleans(false)
	SetRedactIPs(false)
}
func setOptionsRedactedAll() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(true)
	SetRedactBooleans(true)
	SetRedactIPs(true)
}
func setOptionsRedactedIPs() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(false)
	SetRedactBooleans(false)
	SetRedactIPs(true)
}

func getJSONPath(m map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	var v interface{} = m
	for _, p := range parts {
		switch vv := v.(type) {
		case map[string]interface{}:
			v = vv[p]
		case []interface{}:
			idx, err := strconv.Atoi(p)
			if err == nil && idx < len(vv) {
				v = vv[idx]
			} else {
				return nil
			}
		default:
			return nil
		}
	}
	return v
}

func TestRedactMongoLog_Parameterized(t *testing.T) {
	cases := []RedactTestCase{
		{
			Name:      "Simple find",
			InputFile: "test_data/simple_find.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.filter.foo": "REDACTED",
				"command.filter.bar": "REDACTED",
			},
		},
		{
			Name:      "find with $expr",
			InputFile: "test_data/find_with_expr.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.filter.$expr.$and.0.$eq.1": "REDACTED",
				"command.filter.$expr.$and.1.$eq.1": "REDACTED",
			},
		},
		{
			Name:      "Simple aggregation with a match stage",
			InputFile: "test_data/simple_aggregation.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.status":              "REDACTED",
				"command.pipeline.0.$match.createdAt.$lt.$date": "REDACTED",
			},
		},
		{
			Name:      "Complex aggregation",
			InputFile: "test_data/complex_aggregation.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.$expr.$and.0.$ne.1":                     "REDACTED",
				"command.pipeline.0.$match.$expr.$and.1.$lt.1.$date":               "REDACTED",
				"command.pipeline.1.$lookup.pipeline.0.$match.organizationId.$oid": "000000000000000000000000",
				"command.pipeline.2.$project.numericStatus.$cond.if.$eq.1":         "REDACTED",
				"command.pipeline.2.$project.numericStatus.$cond.then":             float64(0),
				"command.pipeline.2.$project.numericStatus.$cond.else":             float64(0),
			},
		},
		{
			Name:      "Simple connection accepted network log with IP redaction",
			InputFile: "test_data/connection_accepted.json",
			Options:   setOptionsRedactedIPs,
			ExpectedPaths: map[string]interface{}{
				"remote": "255.255.255.255:65535",
			},
		},
		{
			Name:      "Simple update statement with query and multiple update docs",
			InputFile: "test_data/updates.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.updates.0.q._id.$oid":       "000000000000000000000000",
				"command.updates.0.u.$set.timestamp": float64(0),
				"command.updates.0.u.$set.foo":       "REDACTED",
				"command.updates.0.u.$set.bar":       false,
			},
		},
		{
			Name:      "InsertsRedacted",
			InputFile: "test_data/inserts.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.documents.0.foo":                           "REDACTED",
				"command.documents.0.bar":                           false,
				"command.documents.0.timestamp.$date":               "REDACTED",
				"command.documents.0.val_arr.0":                     "REDACTED",
				"command.documents.0.emb_doc_arr.0.foo":             "REDACTED",
				"command.documents.0.emb_doc_arr.0.bar":             false,
				"command.documents.0.emb_doc_arr.0.timestamp.$date": "REDACTED",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			tc.Options()
			data, err := os.ReadFile(tc.InputFile)
			if err != nil {
				t.Fatalf("failed to read test log file: %v", err)
			}
			entry, err := RedactMongoLog(string(data))
			if err != nil {
				t.Fatalf("RedactMongoLog failed: %v", err)
			}
			// Marshal Attr back to JSON for path extraction
			attrBytes, _ := json.Marshal(entry.Attr)
			var attrMap map[string]interface{}
			_ = json.Unmarshal(attrBytes, &attrMap)
			for path, want := range tc.ExpectedPaths {
				got := getJSONPath(attrMap, path)
				if got != want {
					t.Errorf("expected %s to be %v, got %v", path, want, got)
				}
			}
		})
	}
}
