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
	Anonymize()
}

type UnknownAttr struct {
	Raw json.RawMessage `json:"-"`
}

func (a *UnknownAttr) Anonymize() {}

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

func (a *NetworkAttr) Anonymize() {
	if anonymizeIPs && a.Remote != "" {
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

func (a *AccessLogAuthSuccessAttr) Anonymize() {
	if a.Client != "" && anonymizeIPs {
		a.Client = "255.255.255.255:65535"
	}
}

func (a *SlowQueryAttr) Anonymize() {
	if anonymizeIPs {
		a.Remote = "255.255.255.255:65535"
	}

	// Anonymize "query" inside "command" if present
	if cmd, ok := a.Command["query"].(map[string]interface{}); ok {
		anonymizeQueryValues(cmd)
	}

	if cmd, ok := a.Command["update"].(map[string]interface{}); ok {
		anonymizeQueryValues(cmd)
	}

	// Anonymize $match filters in aggregation pipelines (recursively)
	if pipeline, ok := a.Command["pipeline"].([]interface{}); ok {
		for _, stage := range pipeline {
			anonymizeMatchStages(stage)
		}
	}

	// Anonymize "documents" in insert commands
	if _, isInsert := a.Command["insert"]; isInsert {
		if docs, ok := a.Command["documents"].([]interface{}); ok {
			for _, doc := range docs {
				if docMap, ok := doc.(map[string]interface{}); ok {
					anonymizeQueryValues(docMap)
				}
			}
		}
	}
}

// Recursively anonymize all $match stages in a pipeline stage
func anonymizeMatchStages(stage interface{}) {
	switch s := stage.(type) {
	case map[string]interface{}:
		for k, v := range s {
			if k == "$match" {
				if matchMap, ok := v.(map[string]interface{}); ok {
					anonymizeQueryValues(matchMap)
				}
			} else {
				anonymizeMatchStages(v)
			}
		}
	case []interface{}:
		for _, item := range s {
			anonymizeMatchStages(item)
		}
	}
}

// Recursively anonymize all leaf values in the query object, except nulls
func anonymizeQueryValues(obj map[string]interface{}) {
	for k, v := range obj {
		switch val := v.(type) {
		case map[string]interface{}:
			anonymizeQueryValues(val)
		case []interface{}:
			for _, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					anonymizeQueryValues(m)
				}
			}
		default:
			// Only replace if not nil (null in JSON)
			if v != nil {
				obj[k] = anonymizedValue(v)
			}
		}
	}
}

var anonymizedString = "REDACTED"
var anonymizeNumbers = false
var anonymizeBooleans = false
var anonymizeIPs = false

func SetAnonymizedString(s string) {
	anonymizedString = s
}

func SetAnonymizeNumbers(b bool) {
	anonymizeNumbers = b
}

func SetAnonymizeBooleans(b bool) {
	anonymizeBooleans = b
}

func SetAnonymizeIPs(b bool) {
	anonymizeIPs = b
}

// Return a generic anonymized value based on the type
func anonymizedValue(v interface{}) interface{} {
	switch v.(type) {
	case string:
		return anonymizedString
	case float64:
		if anonymizeNumbers {
			return 0
		}
		return v
	case int:
		if anonymizeNumbers {
			return 0
		}
		return v
	case int64:
		if anonymizeNumbers {
			return 0
		}
		return v
	case bool:
		if anonymizeBooleans {
			return false
		}
		return v
	default:
		return anonymizedString
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

// AnonymizeMongoLog takes a JSON string, anonymizes remote, and returns the modified object.
func AnonymizeMongoLog(jsonStr string) (*LogEntry, error) {
	var entry LogEntry
	if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
		return nil, err
	}
	if entry.Attr != nil {
		entry.Attr.Anonymize()
	}
	return &entry, nil
}
