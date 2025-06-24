package main

import (
	"encoding/json"
	"strings"
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
	Type               string                 `json:"type"`
	Ns                 string                 `json:"ns"`
	Command            map[string]interface{} `json:"command"`
	OriginatingCommand map[string]interface{} `json:"originatingCommand"`
	PlanSummary        string                 `json:"planSummary"`
	KeysExamined       int                    `json:"keysExamined"`
	DocsExamined       int                    `json:"docsExamined"`
	NumYields          int                    `json:"numYields"`
	QueryHash          string                 `json:"queryHash"`
	PlanCacheKey       string                 `json:"planCacheKey"`
	QueryFramework     string                 `json:"queryFramework"`
	Reslen             int                    `json:"reslen"`
	Locks              map[string]interface{} `json:"locks"`
	ReadConcern        map[string]interface{} `json:"readConcern"`
	Storage            map[string]interface{} `json:"storage"`
	CpuNanos           int64                  `json:"cpuNanos"`
	Remote             string                 `json:"remote"`
	Protocol           string                 `json:"protocol"`
	DurationMillis     int                    `json:"durationMillis"`
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

	shouldEagerRedact := false
	for _, path := range eagerRedactionPaths {
		if strings.HasPrefix(path, a.Ns) {
			shouldEagerRedact = true
			break
		}
	}

	// Use the new redactFieldNames-aware functions
	if cmd, ok := a.Command["query"].(map[string]interface{}); ok {
		a.Command["query"] = redactQueryValues(cmd, shouldEagerRedact)
	}

	if cmd, ok := a.OriginatingCommand["query"].(map[string]interface{}); ok {
		a.OriginatingCommand["query"] = redactQueryValues(cmd, shouldEagerRedact)
	}

	if cmd, ok := a.Command["update"].(map[string]interface{}); ok {
		a.Command["update"] = redactQueryValues(cmd, shouldEagerRedact)
	}

	if cmd, ok := a.OriginatingCommand["update"].(map[string]interface{}); ok {
		a.OriginatingCommand["update"] = redactQueryValues(cmd, shouldEagerRedact)
	}

	if updates, ok := a.Command["updates"].([]interface{}); ok {
		a.Command["updates"] = redactArrayValues(updates, shouldEagerRedact)
	}

	if updates, ok := a.OriginatingCommand["updates"].([]interface{}); ok {
		a.OriginatingCommand["updates"] = redactArrayValues(updates, shouldEagerRedact)
	}

	if cmd, ok := a.Command["filter"].(map[string]interface{}); ok {
		a.Command["filter"] = redactQueryValues(cmd, shouldEagerRedact)
	}

	if cmd, ok := a.Command["sort"].(map[string]interface{}); ok {
		a.Command["sort"] = redactQueryValues(cmd, shouldEagerRedact)
	}

	// We want to ensure the field names aren't leaked if eager redaction is configured:
	if shouldEagerRedact {
		a.PlanSummary = redactFieldNamesFromPlanSummary(a.PlanSummary)
	}

	if cmd, ok := a.OriginatingCommand["filter"].(map[string]interface{}); ok {
		a.OriginatingCommand["filter"] = redactQueryValues(cmd, shouldEagerRedact)
	}

	if pipeline, ok := a.Command["pipeline"].([]interface{}); ok {
		newPipeline := make([]interface{}, len(pipeline))
		for i, stage := range pipeline {
			inSearchStage := isSearchStage(stage)
			newPipeline[i] = redactPipelineStage(stage, shouldEagerRedact, false, inSearchStage)
		}
		a.Command["pipeline"] = newPipeline
	}

	if pipeline, ok := a.OriginatingCommand["pipeline"].([]interface{}); ok {
		newPipeline := make([]interface{}, len(pipeline))
		for i, stage := range pipeline {
			inSearchStage := isSearchStage(stage)
			newPipeline[i] = redactPipelineStage(stage, shouldEagerRedact, false, inSearchStage)
		}
		a.OriginatingCommand["pipeline"] = newPipeline
	}

	// Redact "documents" in insert commands
	if _, isInsert := a.Command["insert"]; isInsert {
		if docs, ok := a.Command["documents"].([]interface{}); ok {
			a.Command["documents"] = redactArrayValues(docs, shouldEagerRedact)
		}
	}

	if _, isInsert := a.OriginatingCommand["insert"]; isInsert {
		if docs, ok := a.OriginatingCommand["documents"].([]interface{}); ok {
			a.OriginatingCommand["documents"] = redactArrayValues(docs, shouldEagerRedact)
		}
	}
}

func redactFieldNamesFromPlanSummary(planSummary string) string {
	if planSummary == "COLLSCAN" {
		return planSummary
	}
	result := planSummary
	fieldNames := ParsePlanSummary(planSummary)
	for _, fieldName := range fieldNames {
		hashed := HashFieldName(fieldName)
		result = strings.ReplaceAll(result, fieldName, hashed)
	}
	return result
}

func getOperatorType(parts []string, operatorMap map[string]interface{}) any {

	var current any = operatorMap
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		val, exists := m[part]
		if !exists {
			return nil
		}
		current = val
	}
	if opType, isOpType := current.(OperatorType); isOpType {
		return opType
	}
	return nil
}

// TODO: Problem: we have to be aware of where we are in the hierarcy at all times, but also check top-level operators
func redactPipelineStage(stage interface{}, redactFieldNames bool, atRoot bool, inSearchStage bool) interface{} {
	var operatorMap map[string]interface{}
	if inSearchStage {
		operatorMap = SearchAggregationOperators
	} else {
		operatorMap = CoreOperators
	}

	switch s := stage.(type) {
	case map[string]interface{}:
		newMap := make(map[string]interface{}, len(s))
		for k, v := range s {
			redactedKey := k
			opMeta, isOp := operatorMap[k]
			if redactFieldNames && (!isOp || (isOp && opMeta == nil)) {
				redactedKey = HashFieldName(k)
			}
			switch meta := opMeta.(type) {
			case OperatorType:
				switch meta {
				case FieldName:
					if redactFieldNames {
						switch vTyped := v.(type) {
						case string:
							// Only hash if not at root
							if atRoot {
								newMap[redactedKey] = vTyped
							} else if _, isOp := operatorMap[vTyped]; isOp {
								newMap[redactedKey] = vTyped
							} else {
								newMap[redactedKey] = HashFieldName(vTyped)
							}
						case map[string]interface{}:
							newMap[redactedKey] = redactPipelineStage(vTyped, redactFieldNames, false, inSearchStage)
						case []interface{}:
							newMap[redactedKey] = redactArrayValues(vTyped, redactFieldNames)
						default:
							newMap[redactedKey] = redactScalarValue(v)
						}
					} else {
						newMap[redactedKey] = v
					}
					continue
				case Exempt:
					newMap[redactedKey] = v
					continue
				case Pipeline:
					if arr, ok := v.([]interface{}); ok {
						newMap[redactedKey] = redactArrayValues(arr, redactFieldNames)
					} else {
						newMap[redactedKey] = v
					}
					continue
				case OperatorArray:
					if arr, ok := v.([]interface{}); ok {
						redactedArr := make([]interface{}, len(arr))
						for i, elem := range arr {
							// Use atRoot=true so operator map is correct for search operator arrays
							redactedArr[i] = redactPipelineStage(elem, redactFieldNames, true, inSearchStage)
						}
						newMap[redactedKey] = redactedArr
					} else {
						newMap[redactedKey] = v
					}
					continue
				}
			case map[string]interface{}:
				if subMap, ok := v.(map[string]interface{}); ok {
					newSubMap := make(map[string]interface{}, len(subMap))
					for subK, subV := range subMap {
						subMeta, subFound := meta[subK]
						if subFound {
							switch subMetaTyped := subMeta.(type) {
							case OperatorType:
								switch subMetaTyped {
								case FieldName:
									if redactFieldNames {
										switch subVTyped := subV.(type) {
										case string:
											// Only hash if not at root
											if _, isOp := operatorMap[subVTyped]; isOp {
												newSubMap[subK] = subVTyped
											} else {
												newSubMap[subK] = HashFieldName(subVTyped)
											}
										case map[string]interface{}:
											newSubMap[subK] = redactPipelineStage(subVTyped, redactFieldNames, false, inSearchStage)
										case []interface{}:
											newSubMap[subK] = redactArrayValues(subVTyped, redactFieldNames)
										default:
											newSubMap[subK] = redactScalarValue(subV)
										}
									} else {
										newSubMap[subK] = subV
									}
									continue
								case Exempt:
									newSubMap[subK] = subV
									continue
								case OperatorArray:
									if arr, ok := subV.([]interface{}); ok {
										redactedArr := make([]interface{}, len(arr))
										for i, elem := range arr {
											// Use atRoot=true so operator map is correct for search operator arrays
											redactedArr[i] = redactPipelineStage(elem, redactFieldNames, true, inSearchStage)
										}
										newSubMap[subK] = redactedArr
									} else {
										newSubMap[subK] = subV
									}
									continue
								case Pipeline:
									if arr, ok := subV.([]interface{}); ok {
										newSubMap[subK] = redactArrayValues(arr, redactFieldNames)
									} else {
										newSubMap[subK] = subV
									}
									continue
								}
							default:
								// Redact as usual below
							}
						}
						redactedSubK := subK
						if redactFieldNames && (!subFound || (subFound && meta[subK] == nil)) {
							redactedSubK = HashFieldName(subK)
						}
						switch subVTyped := subV.(type) {
						case map[string]interface{}:
							newSubMap[redactedSubK] = redactPipelineStage(subVTyped, redactFieldNames, atRoot, inSearchStage)
						case []interface{}:
							newSubMap[redactedSubK] = redactArrayValues(subVTyped, redactFieldNames)
						default:
							// Remove the redundant check here since it's handled above
							newSubMap[redactedSubK] = redactScalarValue(subV)
						}
					}
					newMap[redactedKey] = newSubMap
					continue
				}
			}

			// PATCH: skip redaction for $-prefixed strings if not eager (top-level fallback)
			if str, ok := v.(string); ok && len(str) > 0 && str[0] == '$' && !redactFieldNames {
				newMap[redactedKey] = v
				continue
			}

			switch vTyped := v.(type) {
			case map[string]interface{}:
				newMap[redactedKey] = redactPipelineStage(vTyped, redactFieldNames, atRoot, inSearchStage)
			case []interface{}:
				newMap[redactedKey] = redactArrayValues(vTyped, redactFieldNames)
			default:
				newMap[redactedKey] = redactScalarValue(v)
			}
		}
		return newMap
	case []interface{}:
		return redactArrayValues(s, redactFieldNames)
	default:
		return stage
	}
}

func redactQueryValues(obj map[string]interface{}, redactFieldNames bool) map[string]interface{} {
	newObj := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		redactedKey := k
		// In redactQueryValues, for keys:
		if redactFieldNames {
			if _, isOp := CoreOperators[k]; !isOp {
				redactedKey = HashFieldName(k)
			}
		}
		switch val := v.(type) {
		case map[string]interface{}:
			newObj[redactedKey] = redactQueryValues(val, redactFieldNames)
		case []interface{}:
			newObj[redactedKey] = redactArrayValuesWithKey(k, val, redactFieldNames)
		default:
			// In redactQueryValues, for string values:
			if v != nil {
				if str, ok := v.(string); ok && len(str) > 0 && str[0] == '$' {
					isOp := false
					if _, ok := CoreOperators[str]; ok {
						isOp = true
					}
					if redactFieldNames && !isOp {
						newObj[redactedKey] = HashFieldName(str)
					} else {
						newObj[redactedKey] = v
					}
				} else {
					newObj[redactedKey] = redactScalarValueWithKey(k, v)
				}
			}
		}
	}
	return newObj
}

// Helper to recursively redact arrays of values, passing the parent key
func redactArrayValuesWithKey(parentKey string, arr []interface{}, redactFieldNames bool) []interface{} {
	for i, item := range arr {
		switch itemTyped := item.(type) {
		case map[string]interface{}:
			arr[i] = redactQueryValues(itemTyped, redactFieldNames)
		case []interface{}:
			arr[i] = redactArrayValuesWithKey(parentKey, itemTyped, redactFieldNames)
		default:
			if item != nil {
				if str, ok := item.(string); ok && len(str) > 0 && str[0] == '$' {
					isOp := false
					if _, ok := CoreOperators[str]; ok {
						isOp = true
					}
					if redactFieldNames && !isOp {
						arr[i] = HashFieldName(str)
					} else {
						arr[i] = item
					}
				} else {
					arr[i] = redactScalarValueWithKey(parentKey, item)
				}
			}
		}
	}
	return arr
}

// Update redactArrayValues to call redactArrayValuesWithKey with empty key for top-level
func redactArrayValues(arr []interface{}, redactFieldNames bool) []interface{} {
	return redactArrayValuesWithKey("", arr, redactFieldNames)
}

var redactedString = "REDACTED"
var redactNumbers = false
var redactBooleans = false
var redactIPs = false
var eagerRedactionPaths []string
var RedactedFieldMapping = map[string]string{}

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

func SetEagerRedactionPaths(paths []string) {
	eagerRedactionPaths = paths
}

// Return a generic redacted value based on the type, optionally aware of the key
func redactScalarValueWithKey(key string, v interface{}) interface{} {
	switch key {
	case "$date":
		return "1970-01-01T00:00:00.000Z"
	case "$oid":
		return "000000000000000000000000"
	}
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

// Optionally, keep the original redactScalarValue for legacy use
func redactScalarValue(v interface{}) interface{} {
	return redactScalarValueWithKey("", v)
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

// Helper to check if a pipeline stage is a $search, $searchMeta, or $vectorSearch stage
func isSearchStage(stage interface{}) bool {
	if m, ok := stage.(map[string]interface{}); ok {
		for k := range m {
			if k == "$search" || k == "$searchMeta" || k == "$vectorSearch" {
				return true
			}
		}
	}
	return false
}
