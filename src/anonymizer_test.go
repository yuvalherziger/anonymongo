package main

import (
	"os"
	"testing"
)

func TestAnonymizeMongoLog_SimpleFindFilterRedacted(t *testing.T) {
	// Read the sample log JSON file
	data, err := os.ReadFile("test_data/simple_find.json")
	if err != nil {
		t.Fatalf("failed to read test log file: %v", err)
	}

	// Set anonymization options
	SetAnonymizedString("REDACTED")
	SetAnonymizeNumbers(false)
	SetAnonymizeBooleans(false)
	SetAnonymizeIPs(false)

	// Anonymize the log entry
	entry, err := AnonymizeMongoLog(string(data))
	if err != nil {
		t.Fatalf("AnonymizeMongoLog failed: %v", err)
	}

	// Assert that Attr is of type *SlowQueryAttr
	attr, ok := entry.Attr.(*SlowQueryAttr)
	if !ok {
		t.Fatalf("expected Attr to be *SlowQueryAttr, got %T", entry.Attr)
	}

	// Check that the filter fields are redacted
	cmd := attr.Command
	filter, ok := cmd["filter"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected filter to be a map[string]interface{}")
	}

	for k, v := range filter {
		strVal, ok := v.(string)
		if !ok {
			t.Errorf("expected filter value for key %q to be string, got %T", k, v)
		}
		if strVal != "REDACTED" {
			t.Errorf("expected filter value for key %q to be REDACTED, got %q", k, strVal)
		}
	}

	// Optionally, check that other fields are not redacted
	if cmd["find"] != "my_coll" {
		t.Errorf("expected find to be 'my_coll', got %v", cmd["find"])
	}
}

func TestAnonymizeMongoLog_SimpleAggregationPipelineRedacted(t *testing.T) {
	// Read the sample aggregation log JSON file
	data, err := os.ReadFile("test_data/simple_aggregation.json")
	if err != nil {
		t.Fatalf("failed to read test log file: %v", err)
	}

	// Set anonymization options
	SetAnonymizedString("REDACTED")
	SetAnonymizeNumbers(false)
	SetAnonymizeBooleans(false)
	SetAnonymizeIPs(false)

	// Anonymize the log entry
	entry, err := AnonymizeMongoLog(string(data))
	if err != nil {
		t.Fatalf("AnonymizeMongoLog failed: %v", err)
	}

	// Assert that Attr is of type *SlowQueryAttr
	attr, ok := entry.Attr.(*SlowQueryAttr)
	if !ok {
		t.Fatalf("expected Attr to be *SlowQueryAttr, got %T", entry.Attr)
	}

	// Check that the pipeline $match fields are redacted
	cmd := attr.Command
	pipeline, ok := cmd["pipeline"].([]interface{})
	if !ok {
		t.Fatalf("expected pipeline to be a []interface{}")
	}

	foundMatch := false
	for _, stage := range pipeline {
		stageMap, ok := stage.(map[string]interface{})
		if !ok {
			continue
		}
		match, ok := stageMap["$match"].(map[string]interface{})
		if !ok {
			continue
		}
		foundMatch = true

		// Check "status"
		if status, ok := match["status"]; ok {
			strVal, ok := status.(string)
			if !ok {
				t.Errorf("expected status to be string, got %T", status)
			}
			if strVal != "REDACTED" {
				t.Errorf("expected status to be REDACTED, got %q", strVal)
			}
		} else {
			t.Errorf("expected $match to contain 'status'")
		}

		// Check "createdAt"
		if createdAt, ok := match["createdAt"]; ok {
			createdAtMap, ok := createdAt.(map[string]interface{})
			if !ok {
				t.Errorf("expected createdAt to be map[string]interface{}, got %T", createdAt)
			} else {
				lt, ok := createdAtMap["$lt"]
				if !ok {
					t.Errorf("expected createdAt to contain $lt")
				} else {
					ltMap, ok := lt.(map[string]interface{})
					if !ok {
						t.Errorf("expected createdAt.$lt to be map[string]interface{}, got %T", lt)
					} else {
						dateVal, ok := ltMap["$date"]
						if !ok {
							t.Errorf("expected createdAt.$lt to contain $date")
						} else {
							if dateVal != "REDACTED" {
								t.Errorf("expected createdAt.$lt.$date to be REDACTED, got %v", dateVal)
							}
						}
					}
				}
			}
		} else {
			t.Errorf("expected $match to contain 'createdAt'")
		}
	}

	if !foundMatch {
		t.Errorf("did not find $match stage in pipeline")
	}
}

func TestAnonymizeMongoLog_ConnectionAcceptedRemoteIPRedacted(t *testing.T) {
	// Read the sample connection_accepted log JSON file
	data, err := os.ReadFile("test_data/connection_accepted.json")
	if err != nil {
		t.Fatalf("failed to read test log file: %v", err)
	}

	// Set anonymization options
	SetAnonymizedString("REDACTED")
	SetAnonymizeNumbers(false)
	SetAnonymizeBooleans(false)
	SetAnonymizeIPs(true)

	// Anonymize the log entry
	entry, err := AnonymizeMongoLog(string(data))
	if err != nil {
		t.Fatalf("AnonymizeMongoLog failed: %v", err)
	}

	// Assert that Attr is of the expected struct type (e.g., ConnectionAcceptedAttr)
	attr, ok := entry.Attr.(*NetworkAttr)
	if !ok {
		t.Fatalf("expected Attr to be *ConnectionAcceptedAttr, got %T", entry.Attr)
	}

	if attr.Remote != "255.255.255.255:65535" {
		t.Errorf("expected attr.Remote to be '255.255.255.255:65535', got %q", attr.Remote)
	}
}

func TestAnonymizeMongoLog_UpdatesRedacted(t *testing.T) {
	// Read the sample updates log JSON file
	data, err := os.ReadFile("test_data/updates.json")
	if err != nil {
		t.Fatalf("failed to read test log file: %v", err)
	}

	// Set anonymization options
	SetAnonymizedString("REDACTED")
	SetAnonymizeNumbers(true)
	SetAnonymizeBooleans(true)
	SetAnonymizeIPs(false)

	// Anonymize the log entry
	entry, err := AnonymizeMongoLog(string(data))
	if err != nil {
		t.Fatalf("AnonymizeMongoLog failed: %v", err)
	}

	// Assert that Attr is of type *SlowQueryAttr
	attr, ok := entry.Attr.(*SlowQueryAttr)
	if !ok {
		t.Fatalf("expected Attr to be *SlowQueryAttr, got %T", entry.Attr)
	}

	cmd := attr.Command
	updates, ok := cmd["updates"].([]interface{})
	if !ok {
		t.Fatalf("expected command.updates to be []interface{}, got %T", cmd["updates"])
	}
	if len(updates) == 0 {
		t.Fatalf("expected at least one update in command.updates")
	}

	update, ok := updates[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected updates[0] to be map[string]interface{}, got %T", updates[0])
	}

	// Check q._id.$oid
	q, ok := update["q"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected updates[0].q to be map[string]interface{}, got %T", update["q"])
	}
	_id, ok := q["_id"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected updates[0].q._id to be map[string]interface{}, got %T", q["_id"])
	}
	oid, ok := _id["$oid"].(string)
	if !ok {
		t.Fatalf("expected updates[0].q._id.$oid to be string, got %T", _id["$oid"])
	}
	if oid != "000000000000000000000000" {
		t.Errorf("expected updates[0].q._id.$oid to be 000000000000000000000000, got %q", oid)
	}

	// Check u.$set fields
	u, ok := update["u"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected updates[0].u to be map[string]interface{}, got %T", update["u"])
	}
	set, ok := u["$set"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected updates[0].u.$set to be map[string]interface{}, got %T", u["$set"])
	}

	// timestamp (number)
	if set["timestamp"] != 0 {
		t.Errorf("expected updates[0].u.$set.timestamp to be 0, got %v", set["timestamp"])
	}
	// foo (string)
	if set["foo"] != "REDACTED" {
		t.Errorf("expected updates[0].u.$set.foo to be REDACTED, got %v", set["foo"])
	}
	// bar (boolean)
	if set["bar"] != false {
		t.Errorf("expected updates[0].u.$set.bar to be false, got %v", set["bar"])
	}
}

func TestAnonymizeMongoLog_InsertsRedacted(t *testing.T) {
	// Read the sample inserts log JSON file
	data, err := os.ReadFile("test_data/inserts.json")
	if err != nil {
		t.Fatalf("failed to read test log file: %v", err)
	}

	// Set anonymization options
	SetAnonymizedString("REDACTED")
	SetAnonymizeNumbers(true)
	SetAnonymizeBooleans(true)
	SetAnonymizeIPs(false)

	// Anonymize the log entry
	entry, err := AnonymizeMongoLog(string(data))
	if err != nil {
		t.Fatalf("AnonymizeMongoLog failed: %v", err)
	}

	// Assert that Attr is of type *SlowQueryAttr
	attr, ok := entry.Attr.(*SlowQueryAttr)
	if !ok {
		t.Fatalf("expected Attr to be *SlowQueryAttr, got %T", entry.Attr)
	}

	cmd := attr.Command
	docs, ok := cmd["documents"].([]interface{})
	if !ok {
		t.Fatalf("expected command.documents to be []interface{}, got %T", cmd["documents"])
	}
	if len(docs) == 0 {
		t.Fatalf("expected at least one document in command.documents")
	}

	for i, docRaw := range docs {
		doc, ok := docRaw.(map[string]interface{})
		if !ok {
			t.Errorf("expected document %d to be map[string]interface{}, got %T", i, docRaw)
			continue
		}

		// "foo" is redacted to "REDACTED"
		if foo, ok := doc["foo"]; ok {
			if foo != "REDACTED" {
				t.Errorf("expected doc[%d].foo to be REDACTED, got %v", i, foo)
			}
		}

		// "bar" is redacted to false
		if bar, ok := doc["bar"]; ok {
			if bar != false {
				t.Errorf("expected doc[%d].bar to be false, got %v", i, bar)
			}
		}

		// "timestamp.$date" is redacted to "REDACTED"
		if ts, ok := doc["timestamp"].(map[string]interface{}); ok {
			if date, ok := ts["$date"]; ok {
				if date != "REDACTED" {
					t.Errorf("expected doc[%d].timestamp.$date to be REDACTED, got %v", i, date)
				}
			}
		}

		// "val_arr" values are redacted to "REDACTED"
		if valArr, ok := doc["val_arr"].([]interface{}); ok {
			for j, v := range valArr {
				if v != "REDACTED" {
					t.Errorf("expected doc[%d].val_arr[%d] to be REDACTED, got %v", i, j, v)
				}
			}
		}

		// "emb_doc_arr[].foo", "emb_doc_arr[].bar", "emb_doc_arr[].timestamp.$date"
		if embArr, ok := doc["emb_doc_arr"].([]interface{}); ok {
			for j, embRaw := range embArr {
				emb, ok := embRaw.(map[string]interface{})
				if !ok {
					t.Errorf("expected doc[%d].emb_doc_arr[%d] to be map[string]interface{}, got %T", i, j, embRaw)
					continue
				}
				// "foo"
				if foo, ok := emb["foo"]; ok {
					if foo != "REDACTED" {
						t.Errorf("expected doc[%d].emb_doc_arr[%d].foo to be REDACTED, got %v", i, j, foo)
					}
				}
				// "bar"
				if bar, ok := emb["bar"]; ok {
					if bar != false {
						t.Errorf("expected doc[%d].emb_doc_arr[%d].bar to be false, got %v", i, j, bar)
					}
				}
				// "timestamp.$date"
				if ts, ok := emb["timestamp"].(map[string]interface{}); ok {
					if date, ok := ts["$date"]; ok {
						if date != "REDACTED" {
							t.Errorf("expected doc[%d].emb_doc_arr[%d].timestamp.$date to be REDACTED, got %v", i, j, date)
						}
					}
				}
			}
		}
	}
}

func TestAnonymizeMongoLog_FindWithExprRedacted(t *testing.T) {
	// Read the sample log JSON file with $expr
	data, err := os.ReadFile("test_data/find_with_expr.json")
	if err != nil {
		t.Fatalf("failed to read test log file: %v", err)
	}

	// Set anonymization options
	SetAnonymizedString("REDACTED")
	SetAnonymizeNumbers(false)
	SetAnonymizeBooleans(false)
	SetAnonymizeIPs(false)

	// Anonymize the log entry
	entry, err := AnonymizeMongoLog(string(data))
	if err != nil {
		t.Fatalf("AnonymizeMongoLog failed: %v", err)
	}

	// Assert that Attr is of type *SlowQueryAttr
	attr, ok := entry.Attr.(*SlowQueryAttr)
	if !ok {
		t.Fatalf("expected Attr to be *SlowQueryAttr, got %T", entry.Attr)
	}

	// Navigate to filter.$expr.$and
	cmd := attr.Command
	filter, ok := cmd["filter"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected filter to be a map[string]interface{}")
	}
	expr, ok := filter["$expr"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected filter.$expr to be a map[string]interface{}")
	}
	andArr, ok := expr["$and"].([]interface{})
	if !ok || len(andArr) != 2 {
		t.Fatalf("expected filter.$expr.$and to be a []interface{} of length 2")
	}

	// $and[0].$eq
	and0, ok := andArr[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected filter.$expr.$and[0] to be a map[string]interface{}")
	}
	eq0, ok := and0["$eq"].([]interface{})
	if !ok || len(eq0) != 2 {
		t.Fatalf("expected filter.$expr.$and[0].$eq to be a []interface{} of length 2")
	}

	// $and[1].$eq
	and1, ok := andArr[1].(map[string]interface{})
	if !ok {
		t.Fatalf("expected filter.$expr.$and[1] to be a map[string]interface{}")
	}
	eq1, ok := and1["$eq"].([]interface{})
	if !ok || len(eq1) != 2 {
		t.Fatalf("expected filter.$expr.$and[1].$eq to be a []interface{} of length 2")
	}

	// 1. $expr.$and[0].$eq[1] is redacted to "REDACTED"
	if eq0[1] != "REDACTED" {
		t.Errorf("expected filter.$expr.$and[0].$eq[1] to be REDACTED, got %v", eq0[1])
	}
	// 2. $expr.$and[1].$eq[1] is redacted to "REDACTED"
	if eq1[1] != "REDACTED" {
		t.Errorf("expected filter.$expr.$and[1].$eq[1] to be REDACTED, got %v", eq1[1])
	}
	// 3. $expr.$and[0].$eq[0] remains equal to "$foo"
	if eq0[0] != "$foo" {
		t.Errorf("expected filter.$expr.$and[0].$eq[0] to be \"$foo\", got %v", eq0[0])
	}
	// 4. $expr.$and[1].$eq[0] remains equal to "$bar"
	if eq1[0] != "$bar" {
		t.Errorf("expected filter.$expr.$and[1].$eq[0] to be \"$bar\", got %v", eq1[0])
	}
}
