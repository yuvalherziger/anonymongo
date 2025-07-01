package main

import (
	"encoding/json"
	"strings"
)

type LogEntry struct {
	T         interface{}            `json:"t"`
	S         string                 `json:"s"`
	C         string                 `json:"c"`
	ID        int                    `json:"id"`
	Ctx       string                 `json:"ctx"`
	Svc       string                 `json:"svc"`
	Msg       string                 `json:"msg"`
	Attr      map[string]interface{} `json:"attr"`
	Tags      []string               `json:"tags"`
	Truncated map[string]interface{} `json:"truncated"`
	Size      map[string]interface{} `json:"size"`
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

	// Unmarshal attr as a generic map
	if aux.Attr != nil {
		var attr map[string]interface{}
		_ = json.Unmarshal(aux.Attr, &attr)
		l.Attr = attr
	} else {
		l.Attr = nil
	}
	return nil
}

var (
	redactedString       = "REDACTED"
	redactNumbers        = false
	redactBooleans       = false
	redactIPs            = false
	eagerRedactionPaths  []string
	RedactedFieldMapping = map[string]string{}
)

func SetRedactedString(s string)            { redactedString = s }
func SetRedactNumbers(b bool)               { redactNumbers = b }
func SetRedactBooleans(b bool)              { redactBooleans = b }
func SetRedactIPs(b bool)                   { redactIPs = b }
func SetEagerRedactionPaths(paths []string) { eagerRedactionPaths = paths }

func RedactMongoLog(jsonStr string) (*LogEntry, error) {
	var entry LogEntry
	if err := json.Unmarshal([]byte(jsonStr), &entry); err != nil {
		return nil, err
	}
	if redactIPs {
		if _, ok := entry.Attr["remote"].(string); ok {
			entry.Attr["remote"] = "255.255.255.255:65535"
		}
	}

	if entry.C == "COMMAND" || entry.Msg == "Slow query" {
		shouldEagerRedact := false
		for _, path := range eagerRedactionPaths {
			s, _ := entry.Attr["ns"].(string)

			if strings.HasPrefix(s, path) {
				shouldEagerRedact = true
				break
			}
		}
		originatingCommand, ocOk := entry.Attr["originatingCommand"].(map[string]interface{})
		if ocOk {
			redactCommand(originatingCommand, shouldEagerRedact)
			entry.Attr["originatingCommand"] = originatingCommand
		}

		command, ok := entry.Attr["command"].(map[string]interface{})
		if !ok {
			return &entry, nil
		}
		redactCommand(command, shouldEagerRedact)
		entry.Attr["command"] = command
		if shouldEagerRedact {
			planSummary, psOk := entry.Attr["planSummary"].(string)
			if psOk {
				entry.Attr["planSummary"] = redactFieldNamesFromPlanSummary(planSummary)
			}
		}
	}
	return &entry, nil
}

func redactCommand(cmd map[string]interface{}, shouldEagerRedact bool) {
	if cmd == nil {
		return
	}

	if query, ok := cmd["query"].(map[string]interface{}); ok {
		cmd["query"] = redactQueryValues(query, shouldEagerRedact, false, nil)
	}
	if filter, ok := cmd["filter"].(map[string]interface{}); ok {
		cmd["filter"] = redactQueryValues(filter, shouldEagerRedact, false, nil)
	}
	if sort, ok := cmd["sort"].(map[string]interface{}); ok {
		cmd["sort"] = redactQueryValues(sort, shouldEagerRedact, false, nil)
	}

	if update, ok := cmd["update"].(map[string]interface{}); ok {
		cmd["update"] = redactQueryValues(update, shouldEagerRedact, false, nil)
	}
	if updates, ok := cmd["updates"].([]interface{}); ok {
		cmd["updates"] = redactArrayValues(updates, shouldEagerRedact, false)
	}

	if update, ok := cmd["q"].(map[string]interface{}); ok {
		cmd["q"] = redactQueryValues(update, shouldEagerRedact, false, nil)
	}
	
	if update, ok := cmd["u"].(map[string]interface{}); ok {
		cmd["u"] = redactQueryValues(update, shouldEagerRedact, false, nil)
	}

	if _, isInsert := cmd["insert"]; isInsert {
		if docs, ok := cmd["documents"].([]interface{}); ok {
			cmd["documents"] = redactArrayValues(docs, shouldEagerRedact, false)
		}
	}

	if pipeline, ok := cmd["pipeline"].([]interface{}); ok {
		newPipeline := make([]interface{}, len(pipeline))
		for i, stage := range pipeline {
			inSearchStage := isInSearchStage(stage)
			newPipeline[i] = redactPipelineStage(stage, shouldEagerRedact, []string{}, inSearchStage)
		}
		cmd["pipeline"] = newPipeline
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

func traverseMapPath(path []string, operatorMap map[string]interface{}, isSearchStage bool) (interface{}, bool) {
	var current any = operatorMap
	isOpMap := false
	cutOffPart := ""
	for i, part := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		val, exists := m[part]
		if !exists {
			return nil, false
		}
		current = val
		if len(path) > i+1 && current == OperatorArray {
			if isSearchStage {
				return traverseMapPath(path[i+1:], SearchOperators, true)
			} else {
				return traverseMapPath(path[i+1:], CoreOperators, false)
			}

		}
		if current == OperatorMap {
			isOpMap = true
			cutOffPart = part
			break
		}
	}
	if isOpMap {
		opVal := OperatorMapDefs[cutOffPart]
		withoutArbitraryKey := RemoveElementAfter(path, cutOffPart)
		newPath := RemoveElementsBeforeIncluding(withoutArbitraryKey, cutOffPart)
		if len(newPath) < len(path) {
			if opValMap, ok := opVal.(map[string]interface{}); ok {
				return traverseMapPath(newPath, opValMap, isSearchStage)
			}
		}
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
		aggOpMeta, isAggOp := traverseMapPath(keyPath, AggregationOperators, false)
		if isAggOp {
			return aggOpMeta, true
		}
	} else {
		searchOpMeta, isSearchOp := traverseMapPath(keyPath, SearchAggregationOperators, true)
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
							} else if _, isOp := getOp([]string{vTyped}, inSearchStage); isOp {
								newMap[redactedKey] = vTyped
							} else {
								newMap[redactedKey] = HashFieldName(vTyped)
							}
						case map[string]interface{}:
							newMap[redactedKey] = redactPipelineStage(vTyped, redactFieldNames, newKeyPath, inSearchStage)
						case []interface{}:
							newMap[redactedKey] = redactArrayValues(vTyped, redactFieldNames, inSearchStage)
						default:
							newMap[redactedKey] = redactScalarValue([]string{k}, v, inSearchStage)
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
						newMap[redactedKey] = redactArrayValues(arr, redactFieldNames, inSearchStage)
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
											if _, isOp := getOp([]string{subVTyped}, inSearchStage); isOp {
												newSubMap[subK] = subVTyped
											} else {
												newSubMap[subK] = HashFieldName(subVTyped)
											}
										case map[string]interface{}:
											newSubMap[subK] = redactPipelineStage(subVTyped, redactFieldNames, append(newKeyPath, subK), inSearchStage)
										case []interface{}:
											newSubMap[subK] = redactArrayValues(subVTyped, redactFieldNames, inSearchStage)
										default:
											newSubMap[subK] = redactScalarValue([]string{k}, subV, inSearchStage)
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
										newSubMap[subK] = redactArrayValues(arr, redactFieldNames, inSearchStage)
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
							newSubMap[redactedSubK] = redactArrayValues(subVTyped, redactFieldNames, inSearchStage)
						default:
							newSubMap[redactedSubK] = redactScalarValue([]string{k}, subV, inSearchStage)
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
				newMap[redactedKey] = redactArrayValues(vTyped, redactFieldNames, inSearchStage)
			default:
				// TODO: scalar values must also look at complex paths recursively?
				newMap[redactedKey] = redactScalarValue(newKeyPath, v, inSearchStage)
			}
		}
		return newMap
	case []interface{}:
		return redactArrayValues(s, redactFieldNames, inSearchStage)
	default:
		return stage
	}
}

func redactQueryValues(obj map[string]interface{}, redactFieldNames bool, isSearchStage bool, parentCoreOp interface{}) map[string]interface{} {
	newObj := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		redactedKey := k
		var isOp bool
		var coreOp interface{}
		if parentCoreOp != nil {
			if parentMap, ok := parentCoreOp.(map[string]interface{}); ok {
				coreOp, isOp = parentMap[k]
			} else {
				coreOp, isOp = CoreOperators[k]
			}
		} else {
			coreOp, isOp = CoreOperators[k]
		}

		if redactFieldNames {
			if !isOp {
				redactedKey = HashFieldName(k)
			}
		}
		switch val := v.(type) {
		case map[string]interface{}:
			newObj[redactedKey] = redactQueryValues(val, redactFieldNames, isSearchStage, coreOp)
		case []interface{}:
			newObj[redactedKey] = redactArrayValuesWithKey(k, val, redactFieldNames, isSearchStage)
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
					if coreOp != Exempt {
						newObj[redactedKey] = redactScalarValue([]string{k}, v, isSearchStage)
					} else {
						newObj[redactedKey] = v
					}
				}
			}
		}
	}
	return newObj
}

func redactArrayValuesWithKey(parentKey string, arr []interface{}, redactFieldNames bool, isSearchStage bool) []interface{} {
	for i, item := range arr {
		switch itemTyped := item.(type) {
		case map[string]interface{}:
			arr[i] = redactQueryValues(itemTyped, redactFieldNames, isSearchStage, nil)
		case []interface{}:
			arr[i] = redactArrayValuesWithKey(parentKey, itemTyped, redactFieldNames, isSearchStage)
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
					arr[i] = redactScalarValue([]string{parentKey}, item, isSearchStage)
				}
			}
		}
	}
	return arr
}

func redactArrayValues(arr []interface{}, redactFieldNames bool, isSearchStage bool) []interface{} {
	return redactArrayValuesWithKey("", arr, redactFieldNames, isSearchStage)
}

func redactScalarValue(keyPath []string, v interface{}, isSearchStage bool) interface{} {
	key := ""
	if len(keyPath) == 0 {
		key = ""
	} else {
		op, isOp := getOp(keyPath, isSearchStage)
		if !isOp {
			key = keyPath[len(keyPath)-1]
		} else {
			if op == Exempt {
				return v
			}
		}

	}
	key = keyPath[len(keyPath)-1]
	switch key {
	case "$date":
		return "1970-01-01T00:00:00.000Z"
	case "$oid":
		return "000000000000000000000000"
	}

	switch v.(type) {
	case string:
		str := v.(string)
		if IsEmail(str) {
			return "redacted@redacted.com"
		}
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

func isInSearchStage(stage interface{}) bool {
	if m, ok := stage.(map[string]interface{}); ok {
		for k := range m {
			if k == "$search" || k == "$searchMeta" || k == "$vectorSearch" {
				return true
			}
		}
	}
	return false
}
