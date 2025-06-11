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
