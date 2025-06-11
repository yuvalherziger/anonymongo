package main

import (
	"encoding/json"
)

// LogEntry is a generic MongoDB log entry with dynamic Attr.
type LogEntry struct {
	T       interface{}     `json:"t"`
	S       string          `json:"s"`
	C       string          `json:"c"`
	ID      int             `json:"id"`
	Ctx     string          `json:"ctx"`
	Msg     string          `json:"msg"`
	Attr    Attr            `json:"attr"`
	RawAttr json.RawMessage `json:"-"`
}

// Attr is an interface for different attr types.
type Attr interface {
	Redact()
}

type UnknownAttr struct {
	Raw json.RawMessage `json:"-"`
}

func (a *UnknownAttr) Redact() {}

func (a *UnknownAttr) MarshalJSON() ([]byte, error) {
	if a.Raw == nil {
		return []byte("{}"), nil
	}
	return a.Raw, nil
}

// NetworkAttr for NETWORK logs.
type NetworkAttr struct {
	Remote          string      `json:"remote"`
	UUID            interface{} `json:"uuid"`
	ConnectionID    int         `json:"connectionId"`
	ConnectionCount int         `json:"connectionCount"`
}

func (a *NetworkAttr) Redact() {
	if redactIPs && a.Remote != "" {
		a.Remote = "255.255.255.255:65535"
	}
}

// SlowQueryAttr for COMMAND Slow query logs.
type SlowQueryAttr struct {
	Type           string                 `json:"type"`
	Ns             string                 `json:"ns"`
	Command        map[string]interface{} `json:"command"` // Use map for flexibility, or define a struct for strict typing
	PlanSummary    string                 `json:"planSummary"`
	KeysExamined   int                    `json:"keysExamined"`
	DocsExamined   int                    `json:"docsExamined"`
	NumYields      int                    `json:"numYields"`
	QueryHash      string                 `json:"queryHash"`
	PlanCacheKey   string                 `json:"planCacheKey"`
	QueryFramework string                 `json:"queryFramework"`
	Reslen         int                    `json:"reslen"`
	Locks          map[string]interface{} `json:"locks"`
	ReadConcern    map[string]interface{} `json:"readConcern"`
	Storage        map[string]interface{} `json:"storage"`
	CpuNanos       int64                  `json:"cpuNanos"`
	Remote         string                 `json:"remote"`
	Protocol       string                 `json:"protocol"`
	DurationMillis int                    `json:"durationMillis"`
}

type AccessLogAuthSuccessAttr struct {
	Client          string                 `json:"client"`
	IsSpeculative   bool                   `json:"isSpeculative"`
	IsClusterMember bool                   `json:"isClusterMember"`
	Mechanism       string                 `json:"mechanism"`
	User            string                 `json:"user"`
	Db              string                 `json:"db"`
	Result          int                    `json:"result"`
	Metrics         map[string]interface{} `json:"metrics"`
	ExtraInfo       map[string]interface{} `json:"extraInfo"`
}

func (a *AccessLogAuthSuccessAttr) Redact() {
	if a.Client != "" && redactIPs {
		a.Client = "255.255.255.255:65535"
	}
}

func (a *SlowQueryAttr) Redact() {
	if redactIPs {
		a.Remote = "255.255.255.255:65535"
	}

	if cmd, ok := a.Command["query"].(map[string]interface{}); ok {
		redactQueryValues(cmd)
	}

	if cmd, ok := a.Command["update"].(map[string]interface{}); ok {
		redactQueryValues(cmd)
	}

	if updates, ok := a.Command["updates"].([]interface{}); ok {
		for _, update := range updates {
			if updateMap, ok := update.(map[string]interface{}); ok {
				redactQueryValues(updateMap)
			}
		}
	}

	if cmd, ok := a.Command["filter"].(map[string]interface{}); ok {
		redactQueryValues(cmd)
	}

	// Redact $match filters in aggregation pipelines (recursively)
	if pipeline, ok := a.Command["pipeline"].([]interface{}); ok {
		for _, stage := range pipeline {
			redactPipelineStage(stage)
		}
	}

	// Redact "documents" in insert commands
	if _, isInsert := a.Command["insert"]; isInsert {
		if docs, ok := a.Command["documents"].([]interface{}); ok {
			for _, doc := range docs {
				if docMap, ok := doc.(map[string]interface{}); ok {
					redactQueryValues(docMap)
				}
			}
		}
	}
}

// Recursively redact all values in a pipeline stage, not just $match
func redactPipelineStage(stage interface{}) {
	switch s := stage.(type) {
	case map[string]interface{}:
		redactQueryValues(s)
		for _, v := range s {
			redactPipelineStage(v)
		}
	case []interface{}:
		for _, item := range s {
			redactPipelineStage(item)
		}
	}
}

// Recursively redact all leaf values in the query object, except nulls
func redactQueryValues(obj map[string]interface{}) {
	for k, v := range obj {
		switch val := v.(type) {
		case map[string]interface{}:
			redactQueryValues(val)
		case []interface{}:
			for i, item := range val {
				switch itemTyped := item.(type) {
				case map[string]interface{}:
					redactQueryValues(itemTyped)
				case []interface{}:
					redactArrayValues(itemTyped)
					val[i] = itemTyped
				default:
					if item != nil {
						// If it's a string starting with "$", don't redact
						if str, ok := item.(string); ok && len(str) > 0 && str[0] == '$' {
							val[i] = item
						} else {
							val[i] = redactedValue(item)
						}
					}
				}
			}
			obj[k] = val
		default:
			// Only replace if not nil (null in JSON)
			if v != nil {
				// If it's a string starting with "$", don't redact
				if str, ok := v.(string); ok && len(str) > 0 && str[0] == '$' {
					obj[k] = v
				} else {
					obj[k] = redactedValue(v)
				}
			}
		}
	}
}

// Helper to recursively redact arrays of values
func redactArrayValues(arr []interface{}) {
	for i, item := range arr {
		switch itemTyped := item.(type) {
		case map[string]interface{}:
			redactQueryValues(itemTyped)
		case []interface{}:
			redactArrayValues(itemTyped)
			arr[i] = itemTyped
		default:
			if item != nil {
				// If it's a string starting with "$", don't redact
				if str, ok := item.(string); ok && len(str) > 0 && str[0] == '$' {
					arr[i] = item
				} else {
					arr[i] = redactedValue(item)
				}
			}
		}
	}
}

var redactedString = "REDACTED"
var redactNumbers = false
var redactBooleans = false
var redactIPs = false

func SetRedactedString(s string) {
	redactedString = s
}

func SetRedactNumbers(b bool) {
	redactNumbers = b
}

func SetRedactBooleans(b bool) {
	redactBooleans = b
}

func SetRedactIPs(b bool) {
	redactIPs = b
}

// Return a generic redacted value based on the type
func redactedValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		// Check if it's a 24-character hex string (MongoDB ObjectID)
		if len(val) == 24 {
			isHex := true
			for i := 0; i < 24; i++ {
				c := val[i]
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					isHex = false
					break
				}
			}
			if isHex {
				return "000000000000000000000000"
			}
		}
		return redactedString
	case float64:
		if redactNumbers {
			return 0
		}
		return v
	case int:
		if redactNumbers {
			return 0
		}
		return v
	case int64:
		if redactNumbers {
			return 0
		}
		return v
	case bool:
		if redactBooleans {
			return false
		}
		return v
	default:
		return redactedString
	}
}

func (l *LogEntry) UnmarshalJSON(data []byte) error {
	type Alias LogEntry
	aux := &struct {
		Attr json.RawMessage `json:"attr"`
		*Alias
	}{
		Alias: (*Alias)(l),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil
	}

	l.RawAttr = aux.Attr

	switch {
	case aux.C == "NETWORK":
		var attr NetworkAttr
		if err := json.Unmarshal(aux.Attr, &attr); err != nil {
			var attr UnknownAttr
			attr.Raw = aux.Attr
			l.Attr = &attr
		}
		l.Attr = &attr
	case aux.C == "ACCESS" && aux.Msg == "Successfully authenticated":
		var attr AccessLogAuthSuccessAttr
		if err := json.Unmarshal(aux.Attr, &attr); err != nil {
			var attr UnknownAttr
			attr.Raw = aux.Attr
			l.Attr = &attr
		}
		l.Attr = &attr
	case aux.C == "COMMAND" && aux.Msg == "Slow query":
		var attr SlowQueryAttr
		if err := json.Unmarshal(aux.Attr, &attr); err != nil {
			var attr UnknownAttr
			attr.Raw = aux.Attr
			l.Attr = &attr
		}
		l.Attr = &attr
	default:
		var attr UnknownAttr
		attr.Raw = aux.Attr
		l.Attr = &attr
	}
	return nil
}

// RedactMongoLog takes a JSON string, redacts remote, and returns the modified object.
func RedactMongoLog(jsonStr string) (*LogEntry, error) {
	var entry LogEntry
	if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
		return nil, err
	}
	if entry.Attr != nil {
		entry.Attr.Redact()
	}
	return &entry, nil
}
