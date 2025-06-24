package main

import (
	"encoding/json"
	"strings"
)

// --- Core Data Structures ---

// LogEntry represents a generic MongoDB log entry.
// The UnmarshalJSON custom logic handles the dynamic 'attr' field.
type LogEntry struct {
	T    interface{} `json:"t"`
	S    string      `json:"s"`
	C    string      `json:"c"`
	ID   int         `json:"id"`
	Ctx  string      `json:"ctx"`
	Msg  string      `json:"msg"`
	Attr Attr        `json:"attr"`
}

// Attr is the interface for all specific attribute types.
type Attr interface {
	Redact()
}

// UnknownAttr is a fallback for unhandled or failed-to-parse attribute structures.
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

// --- Attribute-Specific Structures ---

// NetworkAttr for 'NETWORK' component logs.
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

// AccessLogAuthSuccessAttr for successful authentication 'ACCESS' logs.
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
	if redactIPs && a.Client != "" {
		a.Client = "255.255.255.255:65535"
	}
}

// SlowQueryAttr for 'COMMAND' slow query logs.
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

// --- Unmarshaling Logic ---

// UnmarshalJSON provides custom logic for parsing a LogEntry and dynamically
// determining the concrete type of the 'Attr' field. This version carefully
// preserves the original's behavior where a failed unmarshal of a known type
// results in a zero-value struct of that type, not an UnknownAttr.
func (l *LogEntry) UnmarshalJSON(data []byte) error {
	type Alias LogEntry
	aux := &struct {
		Attr json.RawMessage `json:"attr"`
		*Alias
	}{
		Alias: (*Alias)(l),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil // Tolerate malformed log lines, matching original behavior.
	}

	switch {
	case aux.C == "NETWORK":
		var attr NetworkAttr
		_ = json.Unmarshal(aux.Attr, &attr) // Error is ignored to replicate original logic
		l.Attr = &attr
	case aux.C == "ACCESS" && aux.Msg == "Successfully authenticated":
		var attr AccessLogAuthSuccessAttr
		_ = json.Unmarshal(aux.Attr, &attr) // Error is ignored
		l.Attr = &attr
	case aux.C == "COMMAND" && aux.Msg == "Slow query":
		var attr SlowQueryAttr
		_ = json.Unmarshal(aux.Attr, &attr) // Error is ignored
		l.Attr = &attr
	default:
		// Only for truly unknown logs is UnknownAttr used.
		var attr UnknownAttr
		attr.Raw = aux.Attr
		l.Attr = &attr
	}
	return nil
}

// --- Redaction Logic ---

// Global configuration for redaction behavior.
var (
	redactedString       = "REDACTED"
	redactNumbers        = false
	redactBooleans       = false
	redactIPs            = false
	eagerRedactionPaths  []string
	RedactedFieldMapping = map[string]string{}
)

// Configuration setters.
func SetRedactedString(s string)            { redactedString = s }
func SetRedactNumbers(b bool)               { redactNumbers = b }
func SetRedactBooleans(b bool)              { redactBooleans = b }
func SetRedactIPs(b bool)                   { redactIPs = b }
func SetEagerRedactionPaths(paths []string) { eagerRedactionPaths = paths }

// RedactMongoLog is the public function to process a raw JSON log string.
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

// Redact performs redaction on the SlowQueryAttr fields.
func (a *SlowQueryAttr) Redact() {
	if redactIPs {
		a.Remote = "255.255.255.255:65535"
	}

	shouldEagerRedact := false
	for _, path := range eagerRedactionPaths {
		if strings.HasPrefix(a.Ns, path) {
			shouldEagerRedact = true
			break
		}
	}

	// Redact both command documents using a helper to avoid duplication.
	redactCommand(a.Command, shouldEagerRedact)
	redactCommand(a.OriginatingCommand, shouldEagerRedact)

	if shouldEagerRedact {
		a.PlanSummary = redactFieldNamesFromPlanSummary(a.PlanSummary)
	}
}

// redactCommand centralizes the redaction logic for a command document.
func redactCommand(cmd map[string]interface{}, shouldEagerRedact bool) {
	if cmd == nil {
		return
	}

	// Redact various query-like fields
	if query, ok := cmd["query"].(map[string]interface{}); ok {
		cmd["query"] = redactQueryValues(query, shouldEagerRedact)
	}
	if filter, ok := cmd["filter"].(map[string]interface{}); ok {
		cmd["filter"] = redactQueryValues(filter, shouldEagerRedact)
	}
	if sort, ok := cmd["sort"].(map[string]interface{}); ok {
		cmd["sort"] = redactQueryValues(sort, shouldEagerRedact)
	}

	// Redact update-related fields
	if update, ok := cmd["update"].(map[string]interface{}); ok {
		cmd["update"] = redactQueryValues(update, shouldEagerRedact)
	}
	if updates, ok := cmd["updates"].([]interface{}); ok {
		cmd["updates"] = redactArrayValues(updates, shouldEagerRedact)
	}

	// Redact insert documents
	if _, isInsert := cmd["insert"]; isInsert {
		if docs, ok := cmd["documents"].([]interface{}); ok {
			cmd["documents"] = redactArrayValues(docs, shouldEagerRedact)
		}
	}

	// Redact pipeline stages
	if pipeline, ok := cmd["pipeline"].([]interface{}); ok {
		newPipeline := make([]interface{}, len(pipeline))
		for i, stage := range pipeline {
			inSearchStage := isSearchStage(stage)
			newPipeline[i] = redactPipelineStage(stage, shouldEagerRedact, []string{}, inSearchStage)
		}
		cmd["pipeline"] = newPipeline
	}
}

// --- Redaction Helpers (Copied from original and preserved for logical integrity) ---
// The following functions are highly complex and have been preserved from the original
// file to ensure that all logical edge cases are handled identically.

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

func traverseMapPath(path []string, operatorMap map[string]interface{}) (interface{}, bool) {
	var current any = operatorMap
	for _, part := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		val, exists := m[part]
		if !exists {
			return nil, false
		}
		current = val
	}
	if current != nil {
		return current, true
	}
	return nil, false
}

func getOp(keyPath []string, isSearchStage bool) (interface{}, bool) {
	if !isSearchStage {
		coreOpMeta, isCoreOp := CoreOperators[keyPath[len(keyPath)-1]]
		if isCoreOp {
			return coreOpMeta, true
		}
		aggOpMeta, isAggOp := traverseMapPath(keyPath, AggregationOperators)
		if isAggOp {
			return aggOpMeta, true
		}
	} else {
		searchOpMeta, isSearchOp := traverseMapPath(keyPath, SearchAggregationOperators)
		if isSearchOp {
			return searchOpMeta, true
		}
		coreSearchOpMeta, isCoreSearchOp := SearchOperators[keyPath[len(keyPath)-1]]
		if isCoreSearchOp {
			return coreSearchOpMeta, true
		}
	}
	return nil, false
}

func redactPipelineStage(stage interface{}, redactFieldNames bool, keyPath []string, inSearchStage bool) interface{} {
	switch s := stage.(type) {
	case map[string]interface{}:
		newMap := make(map[string]interface{}, len(s))
		for k, v := range s {
			redactedKey := k
			newKeyPath := append(keyPath, k)
			opMeta, isOp := getOp(newKeyPath, inSearchStage)
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
							if len(keyPath) > 0 {
								newMap[redactedKey] = vTyped
								//} else if _, isOp := operatorMap[vTyped]; isOp {
							} else if _, isOp := getOp([]string{vTyped}, inSearchStage); isOp {
								newMap[redactedKey] = vTyped
							} else {
								newMap[redactedKey] = HashFieldName(vTyped)
							}
						case map[string]interface{}:
							newMap[redactedKey] = redactPipelineStage(vTyped, redactFieldNames, newKeyPath, inSearchStage)
						case []interface{}:
							newMap[redactedKey] = redactArrayValues(vTyped, redactFieldNames)
						default:
							newMap[redactedKey] = redactScalarValue(k, v)
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
							redactedArr[i] = redactPipelineStage(elem, redactFieldNames, newKeyPath, inSearchStage)
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
											// if _, isOp := operatorMap[subVTyped]; isOp {
											if _, isOp := getOp([]string{subVTyped}, inSearchStage); isOp {
												newSubMap[subK] = subVTyped
											} else {
												newSubMap[subK] = HashFieldName(subVTyped)
											}
										case map[string]interface{}:
											newSubMap[subK] = redactPipelineStage(subVTyped, redactFieldNames, append(newKeyPath, subK), inSearchStage)
										case []interface{}:
											newSubMap[subK] = redactArrayValues(subVTyped, redactFieldNames)
										default:
											newSubMap[subK] = redactScalarValue(k, subV)
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
											redactedArr[i] = redactPipelineStage(elem, redactFieldNames, newKeyPath, inSearchStage)
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
							}
						}
						redactedSubK := subK
						if redactFieldNames && (!subFound || (subFound && meta[subK] == nil)) {
							redactedSubK = HashFieldName(subK)
						}
						switch subVTyped := subV.(type) {
						case map[string]interface{}:
							newSubMap[redactedSubK] = redactPipelineStage(subVTyped, redactFieldNames, append(newKeyPath, subK), inSearchStage)
						case []interface{}:
							newSubMap[redactedSubK] = redactArrayValues(subVTyped, redactFieldNames)
						default:
							newSubMap[redactedSubK] = redactScalarValue(k, subV)
						}
					}
					newMap[redactedKey] = newSubMap
					continue
				}
			}

			if str, ok := v.(string); ok && len(str) > 0 && str[0] == '$' && !redactFieldNames {
				newMap[redactedKey] = v
				continue
			}

			switch vTyped := v.(type) {
			case map[string]interface{}:
				newMap[redactedKey] = redactPipelineStage(vTyped, redactFieldNames, newKeyPath, inSearchStage)
			case []interface{}:
				newMap[redactedKey] = redactArrayValues(vTyped, redactFieldNames)
			default:
				newMap[redactedKey] = redactScalarValue(k, v)
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
					newObj[redactedKey] = redactScalarValue(k, v)
				}
			}
		}
	}
	return newObj
}

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
					arr[i] = redactScalarValue(parentKey, item)
				}
			}
		}
	}
	return arr
}

func redactArrayValues(arr []interface{}, redactFieldNames bool) []interface{} {
	return redactArrayValuesWithKey("", arr, redactFieldNames)
}

func redactScalarValue(key string, v interface{}) interface{} {
	switch key {
	case "$date":
		return "1970-01-01T00:00:00.000Z"
	case "$oid":
		return "000000000000000000000000"
	}
	switch v.(type) {
	case string:
		return redactedString
	case float64, int, int64:
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
