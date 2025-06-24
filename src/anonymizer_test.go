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

// Test case definition for parameterized redactr tests
type RedactTestCase struct {
	Name          string
	InputFile     string
	Options       func()
	ExpectedPaths map[string]interface{}
}

// Example option sets
func setOptionsRedactedStrings() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(false)
	SetRedactBooleans(false)
	SetRedactIPs(false)
	SetEagerRedactionPaths([]string{})
}

func setOptionsRedactedStringsWithEagerRedaction() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(false)
	SetRedactBooleans(false)
	SetRedactIPs(false)
	SetEagerRedactionPaths([]string{
		"my_db.my_coll",
	})
}

func setOptionsRedactedAllWithOverride() {
	SetRedactedString("<VALUE REDACTED>")
	SetRedactNumbers(true)
	SetRedactBooleans(true)
	SetRedactIPs(true)
	SetEagerRedactionPaths([]string{})
}

func setOptionsRedactedAll() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(true)
	SetRedactBooleans(true)
	SetRedactIPs(true)
	SetEagerRedactionPaths([]string{})
}

func setOptionsRedactedIPs() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(false)
	SetRedactBooleans(false)
	SetRedactIPs(true)
	SetEagerRedactionPaths([]string{})
}

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

// Updated getJSONPath to use splitPath
func getJSONPath(m map[string]interface{}, path string) interface{} {
	parts := splitPath(path)
	var v interface{} = m
	for _, p := range parts {
		switch vv := v.(type) {
		case map[string]interface{}:
			v = vv[p]
		case []interface{}:
			// Try to parse p as an index
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
	cases := []RedactTestCase{
		{
			Name:      "Simple find",
			InputFile: "simple_find.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.filter.foo": "REDACTED",
				"command.filter.bar": "REDACTED",
			},
		},
		{
			Name:      "find with $expr",
			InputFile: "find_with_expr.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.filter.$expr.$and.0.$eq.1": "REDACTED",
				"command.filter.$expr.$and.1.$eq.1": "REDACTED",
			},
		},
		{
			Name:      "Simple aggregation with a match stage",
			InputFile: "simple_aggregation.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.status":              "REDACTED",
				"command.pipeline.0.$match.createdAt.$lt.$date": "1970-01-01T00:00:00.000Z",
			},
		},
		{
			Name:      "Complex aggregation",
			InputFile: "complex_aggregation.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.$expr.$and.0.$ne.1":                     "REDACTED",
				"command.pipeline.0.$match.$expr.$and.1.$lt.1.$date":               "1970-01-01T00:00:00.000Z",
				"command.pipeline.1.$lookup.pipeline.0.$match.organizationId.$oid": "000000000000000000000000",
				"command.pipeline.2.$project.numericStatus.$cond.if.$eq.1":         "REDACTED",
				"command.pipeline.2.$project.numericStatus.$cond.then":             float64(0),
				"command.pipeline.2.$project.numericStatus.$cond.else":             float64(0),
			},
		},
		{
			Name:      "Simple connection accepted network log with IP redaction",
			InputFile: "connection_accepted.json",
			Options:   setOptionsRedactedIPs,
			ExpectedPaths: map[string]interface{}{
				"remote": "255.255.255.255:65535",
			},
		},
		{
			Name:      "Simple update statement with query and multiple update docs",
			InputFile: "updates.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.updates.0.q._id.$oid":       "000000000000000000000000",
				"command.updates.0.u.$set.timestamp": float64(0),
				"command.updates.0.u.$set.foo":       "REDACTED",
				"command.updates.0.u.$set.bar":       false,
			},
		},
		{
			Name:      "Inserts redacted",
			InputFile: "inserts.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.documents.0.foo":                           "REDACTED",
				"command.documents.0.bar":                           false,
				"command.documents.0.timestamp.$date":               "1970-01-01T00:00:00.000Z",
				"command.documents.0.val_arr.0":                     "REDACTED",
				"command.documents.0.emb_doc_arr.0.foo":             "REDACTED",
				"command.documents.0.emb_doc_arr.0.bar":             false,
				"command.documents.0.emb_doc_arr.0.timestamp.$date": "1970-01-01T00:00:00.000Z",
			},
		},
		{
			Name:      "No-op log stays unchanges",
			InputFile: "asio_log.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"hostAndPort":             "atlas-okh9ti-shard-00-01.y13gh.mongodb.net:27017",
				"dnsResolutionTimeMillis": float64(7),
				"tcpConnectionTimeMillis": float64(2043),
				"tlsHandshakeTimeMillis":  float64(11),
				"authTimeMillis":          float64(0),
				"hookTime":                nil,
				"totalTimeMillis":         float64(2061),
			},
		},
		{
			Name:      "Update with nested logical query",
			InputFile: "update_with_nested_logical_query.json",
			Options:   setOptionsRedactedAllWithOverride,
			ExpectedPaths: map[string]interface{}{
				"command.query.$and.0.name":                 "<VALUE REDACTED>",
				"command.query.$and.0.active.$ne":           false,
				"command.query.$and.1.$or.0.cAt.$lte.$date": "1970-01-01T00:00:00.000Z",
				"command.query.$and.1.$or.1.uAt.$lte.$date": "1970-01-01T00:00:00.000Z",
				"command.update.$set.uAt.$date":             "1970-01-01T00:00:00.000Z",
			},
		},
		{
			Name:      "Simple find with an $in operator",
			InputFile: "in_operator.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.filter.foo.$in.0": "REDACTED",
				"command.filter.foo.$in.1": "REDACTED",
			},
		},
		{
			Name:      "Simple find with an $elemMatch operator",
			InputFile: "elemMatch_operator.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.filter.transactions.$elemMatch.merchantId": float64(0),
				"command.filter.transactions.$elemMatch.location":   "REDACTED",
			},
		},
		{
			Name:      "find with getMore",
			InputFile: "getMore.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"originatingCommand.filter.foo":                                 "REDACTED",
				"originatingCommand.filter.bar":                                 "REDACTED",
				"originatingCommand.filter.$or.0.status.$nin.0":                 "REDACTED",
				"originatingCommand.filter.$or.0.status.$nin.1":                 "REDACTED",
				"originatingCommand.filter.$or.0.status.$nin.2":                 "REDACTED",
				"originatingCommand.filter.$or.1.status":                        "REDACTED",
				"originatingCommand.filter.$or.1.nested\\.stringAttribute":      "REDACTED",
				"originatingCommand.filter.$or.1.nested\\.numericAttribute.$ne": float64(0),
			},
		},
		{
			Name:      "aggregate with getMore",
			InputFile: "getMore_aggregate.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"originatingCommand.pipeline.0.$match.str1":           "REDACTED",
				"originatingCommand.pipeline.0.$match.str2":           "REDACTED",
				"originatingCommand.pipeline.0.$match.cAt.$gte.$date": "1970-01-01T00:00:00.000Z",
				"originatingCommand.pipeline.0.$match.cAt.$lte.$date": "1970-01-01T00:00:00.000Z",
				"originatingCommand.pipeline.1.$lookup.from":          "other_coll",
				"originatingCommand.pipeline.2.$project.other_docs":   float64(0),
			},
		},
		{
			Name:      "Simple find with eager redaction",
			InputFile: "simple_find.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.filter.foo": nil,
				"command.filter.bar": nil,
				fmt.Sprintf("command.filter.%s", HashFieldName("foo")): "REDACTED",
				fmt.Sprintf("command.filter.%s", HashFieldName("bar")): "REDACTED",
			},
		},
		{
			Name:      "Simple aggregation with a match stage and eager redaction",
			InputFile: "simple_aggregation.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.status":                                                nil,
				"command.pipeline.0.$match.createdAt.$lt.$date":                                   nil,
				fmt.Sprintf("command.pipeline.0.$match.%s", HashFieldName("status")):              "REDACTED",
				fmt.Sprintf("command.pipeline.0.$match.%s.$lt.$date", HashFieldName("createdAt")): "1970-01-01T00:00:00.000Z",
			},
		},
		{
			Name:      "find with $expr and eager redaction",
			InputFile: "find_with_expr.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.filter.$expr.$and.0.$eq.0":                  HashFieldName("foo"),
				"command.filter.$expr.$and.0.$eq.1":                  "REDACTED",
				"command.filter.$expr.$and.1.$eq.0":                  HashFieldName("bar"),
				"command.filter.$expr.$and.1.$eq.1":                  "REDACTED",
				"command.sort._id":                                   nil,
				fmt.Sprintf("command.sort.%s", HashFieldName("_id")): float64(-1),
				// We should also hash field names in the plan summary indiscriminately:
				"planSummary": fmt.Sprintf("IXSCAN { %s: 1, %s: 1, %s: -1 }", HashFieldName("foo"), HashFieldName("bar"), HashFieldName("_id")),
			},
		},
		{
			Name:      "Complex aggregation with eager redaction",
			InputFile: "complex_aggregation.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.$expr.$and.0.$ne.0":                                                       HashFieldName("status"),
				"command.pipeline.0.$match.$expr.$and.0.$ne.1":                                                       "REDACTED",
				"command.pipeline.0.$match.$expr.$and.1.$lt.1.$date":                                                 "1970-01-01T00:00:00.000Z",
				"command.pipeline.0.$match.$expr.$and.1.$lt.0":                                                       HashFieldName("createdAt"),
				fmt.Sprintf("command.pipeline.1.$lookup.pipeline.0.$match.%s.$oid", HashFieldName("organizationId")): "000000000000000000000000",
				// We have to hash field names in the pipeline stages too now:
				fmt.Sprintf("command.pipeline.1.$lookup.pipeline.1.$project.%s", HashFieldName("_id")):       float64(0),
				fmt.Sprintf("command.pipeline.1.$lookup.pipeline.1.$project.%s", HashFieldName("name")):      float64(1),
				fmt.Sprintf("command.pipeline.1.$lookup.pipeline.1.$project.%s", HashFieldName("createdAt")): float64(1),
				fmt.Sprintf("command.pipeline.2.$project.%s.$cond.if.$eq.1", HashFieldName("numericStatus")): "REDACTED",
				fmt.Sprintf("command.pipeline.2.$project.%s.$cond.then", HashFieldName("numericStatus")):     float64(-1),
				fmt.Sprintf("command.pipeline.2.$project.%s.$cond.else", HashFieldName("numericStatus")):     float64(1),
			},
		},
		{
			Name:      "Aggregation stages edge cases",
			InputFile: "aggregation_stages_edge_cases.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$bucket.boundaries":            []float64{float64(1840), float64(1850), float64(1860), float64(1870), float64(1880)},
				"command.pipeline.0.$bucket.groupBy":               "$year_born",
				"command.pipeline.0.$bucket.default":               "REDACTED",
				"command.pipeline.0.$bucket.output.count.$sum":     float64(1),
				"command.pipeline.1.$count":                        "totalArtists",
				"command.pipeline.2.$densify.field":                "timestamp",
				"command.pipeline.2.$densify.range.step":           float64(1),
				"command.pipeline.2.$densify.range.bounds.0.$date": "1970-01-01T00:00:00.000Z",
				"command.pipeline.2.$densify.range.bounds.1.$date": "1970-01-01T00:00:00.000Z",
				"command.pipeline.3.$facet.meta.0.$count":          "total",
				"command.pipeline.3.$facet.docs.0.$limit":          float64(10),
				"command.pipeline.3.$facet.docs.1.$skip":           float64(0),
			},
		},
		{
			Name:      "Aggregation stages edge cases with eager redaction",
			InputFile: "aggregation_stages_edge_cases.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$bucket.groupBy": HashFieldName("$year_born"),
				"command.pipeline.1.$count":          HashFieldName("totalArtists"),
				"command.pipeline.2.$densify.field":  HashFieldName("timestamp"),
			},
		},
		{
			Name:      "Simple search",
			InputFile: "simple_search.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$search.index":      "default",
				"command.pipeline.0.$search.text.query": "REDACTED",
				"command.pipeline.0.$search.text.path":  "title",
			},
		},
		{
			Name:      "Search with compound operators",
			InputFile: "search_with_compound_operators.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$search.compound.should.0.text.path":                    "type",
				"command.pipeline.0.$search.compound.should.0.text.query":                   "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.0.text.path":    "category",
				"command.pipeline.0.$search.compound.should.1.compound.must.0.text.query":   "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.1.equals.value": true,
				"command.pipeline.0.$search.compound.should.1.compound.must.1.equals.path":  "in_stock",
			},
		},
		{
			Name:      "Search with compound operators with eager redaction",
			InputFile: "search_with_compound_operators.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$search.compound.should.0.text.path":                    HashFieldName("type"),
				"command.pipeline.0.$search.compound.should.0.text.query":                   "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.0.text.path":    HashFieldName("category"),
				"command.pipeline.0.$search.compound.should.1.compound.must.0.text.query":   "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.1.equals.value": true,
				"command.pipeline.0.$search.compound.should.1.compound.must.1.equals.path":  HashFieldName("in_stock"),
			},
		},
	}

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
			attrBytes, _ := json.Marshal(entry.Attr)
			var attrMap map[string]interface{}
			_ = json.Unmarshal(attrBytes, &attrMap)
			for path, want := range tc.ExpectedPaths {
				got := getJSONPath(attrMap, path)
				if !valuesEqual(got, want) {
					t.Errorf("expected %s to be %s, got %s", path, getTypeInfo(want), getTypeInfo(got))
				}
			}
		})
	}
}
