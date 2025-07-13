package main

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/elliotchance/orderedmap/v3"
)

var (
	redactedString       = RedactedString
	redactNumbers        = false
	redactBooleans       = false
	redactIPs            = false
	eagerRedactionPaths  []string
	RedactedFieldMapping = map[string]string{}
	shouldEncrypt        = false
	encryptionKey        []byte
	redactNamespaces     = false
	redactedFieldsRegexp *regexp.Regexp
)

func SetRedactedString(s string)            { redactedString = s }
func SetRedactNumbers(b bool)               { redactNumbers = b }
func SetRedactBooleans(b bool)              { redactBooleans = b }
func SetRedactIPs(b bool)                   { redactIPs = b }
func SetEagerRedactionPaths(paths []string) { eagerRedactionPaths = paths }
func SetEncryptionKey(key []byte)           { encryptionKey = key }
func SetShouldEncrypt(b bool)               { shouldEncrypt = b }
func SetRedactNamespaces(b bool)            { redactNamespaces = b }
func SetRedactedFieldsRegexp(re string) {
	if re == "" {
		redactedFieldsRegexp = nil
	} else {
		var err error
		redactedFieldsRegexp, err = regexp.Compile(re)
		if err != nil {
			panic("Invalid regular expression for redacted fields: " + re)
		}
	}
}

func RedactMongoLog(jsonStr string) (*orderedmap.OrderedMap[string, any], error) {
	entry, err := UnmarshalOrdered([]byte(jsonStr))
	if err != nil {
		return nil, err
	}
	if redactIPs {
		if remote, ok := entry.Get("attr"); ok {
			if attrMap, ok := remote.(*orderedmap.OrderedMap[string, any]); ok {
				if remoteVal, ok := attrMap.Get("remote"); ok {
					if _, ok := remoteVal.(string); ok {
						attrMap.Set("remote", "255.255.255.255:65535")
					}
				}
			}
		}
	}

	attrVal, hasAttr := entry.Get("attr")
	if !hasAttr || attrVal == nil {
		return entry, nil
	}
	attr, ok := attrVal.(*orderedmap.OrderedMap[string, any])
	if !ok {
		return entry, nil
	}

	cVal, _ := entry.Get("c")
	msgVal, _ := entry.Get("msg")
	c, _ := cVal.(string)
	msg, _ := msgVal.(string)
	if c == "COMMAND" || msg == "Slow query" || c == "QUERY" {
		shouldEagerRedact := false
		for _, path := range eagerRedactionPaths {
			s, _ := attr.Get("ns")
			ns, _ := s.(string)
			if strings.HasPrefix(ns, path) {
				shouldEagerRedact = true
				break
			}
		}
		originatingCommand, ocOk := attr.Get("originatingCommand")
		if ocOk {
			if ocMap, ok := originatingCommand.(*orderedmap.OrderedMap[string, any]); ok {
				redactCommand(ocMap, shouldEagerRedact)
				if redactNamespaces {
					redactNamespace(ocMap)
				}
				attr.Set("originatingCommand", ocMap)
			}
		}
		cmd, cmdOk := attr.Get("cmd")
		if cmdOk {
			if cmdMap, ok := cmd.(*orderedmap.OrderedMap[string, any]); ok {
				redactCommand(cmdMap, shouldEagerRedact)
				if redactNamespaces {
					redactNamespace(cmdMap)
				}
				attr.Set("cmd", cmdMap)
			}
		}
		command, ok := attr.Get("command")
		if !ok {
			return entry, nil
		}
		if cmdMap, ok := command.(*orderedmap.OrderedMap[string, any]); ok {
			redactCommand(cmdMap, shouldEagerRedact)
			if redactNamespaces {
				redactNamespace(cmdMap)
			}
			attr.Set("command", cmdMap)
		}
		if shouldEagerRedact {
			planSummary, psOk := attr.Get("planSummary")
			if psOk {
				if psStr, ok := planSummary.(string); ok {
					attr.Set("planSummary", redactFieldNamesFromPlanSummary(psStr))
				}
			}
		}
	}

	if redactNamespaces {
		ns, ok := attr.Get("ns")
		if ok {
			if nsStr, ok := ns.(string); ok {
				redactedNs := HashName(nsStr)
				attr.Set("ns", redactedNs)
			}
		}
	}

	return entry, nil
}

func redactNamespace(cmd *orderedmap.OrderedMap[string, any]) {
	searchedFields := []string{"ns", "aggregate", "insert", "find", "update", "collection", "delete", "$db", "count", "findAndModify", "findOneAndDelete", "replace", "findOneAndReplace", "findOneAndUpdate", "getIndexes", "countDocuments"}
	for _, field := range searchedFields {
		if value, ok := cmd.Get(field); ok {
			if valueStr, ok := value.(string); ok {
				redactedValue := HashName(valueStr)
				cmd.Set(field, redactedValue)
			}
		}
	}
}

func redactCommand(cmd *orderedmap.OrderedMap[string, any], shouldEagerRedact bool) {
	if cmd == nil {
		return
	}
	if query, ok := cmd.Get("query"); ok {
		if queryMap, ok := query.(*orderedmap.OrderedMap[string, any]); ok {
			cmd.Set("query", redactQueryValues(queryMap, shouldEagerRedact, false, nil, []string{}))
		}
	}
	if filter, ok := cmd.Get("filter"); ok {
		if filterMap, ok := filter.(*orderedmap.OrderedMap[string, any]); ok {
			cmd.Set("filter", redactQueryValues(filterMap, shouldEagerRedact, false, nil, []string{}))
		}
	}
	if sort, ok := cmd.Get("sort"); ok {
		if sortMap, ok := sort.(*orderedmap.OrderedMap[string, any]); ok {
			cmd.Set("sort", redactQueryValues(sortMap, shouldEagerRedact, false, nil, []string{}))
		}
	}
	if update, ok := cmd.Get("update"); ok {
		if updateMap, ok := update.(*orderedmap.OrderedMap[string, any]); ok {
			cmd.Set("update", redactQueryValues(updateMap, shouldEagerRedact, false, nil, []string{}))
		}
	}
	if updates, ok := cmd.Get("updates"); ok {
		if updatesArr, ok := updates.([]any); ok {
			cmd.Set("updates", redactArrayValues(updatesArr, shouldEagerRedact, false, false, []string{}))
		}
	}
	if update, ok := cmd.Get("q"); ok {
		if updateMap, ok := update.(*orderedmap.OrderedMap[string, any]); ok {
			cmd.Set("q", redactQueryValues(updateMap, shouldEagerRedact, false, nil, []string{}))
		}
	}
	if update, ok := cmd.Get("u"); ok {
		if updateMap, ok := update.(*orderedmap.OrderedMap[string, any]); ok {
			cmd.Set("u", redactQueryValues(updateMap, shouldEagerRedact, false, nil, []string{}))
		}
	}
	if _, isInsert := cmd.Get("insert"); isInsert {
		if docs, ok := cmd.Get("documents"); ok {
			if docsArr, ok := docs.([]any); ok {
				cmd.Set("documents", redactArrayValues(docsArr, shouldEagerRedact, false, false, []string{}))
			}
		}
	}
	if pipeline, ok := cmd.Get("pipeline"); ok {
		if pipelineArr, ok := pipeline.([]any); ok {
			newPipeline := make([]any, len(pipelineArr))
			for i, stage := range pipelineArr {
				inSearchStage := isInSearchStage(stage)
				newPipeline[i] = redactPipelineStage(stage, shouldEagerRedact, []string{}, inSearchStage)
			}
			cmd.Set("pipeline", newPipeline)
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
		hashed := HashName(fieldName)
		result = strings.ReplaceAll(result, fieldName, hashed)
	}
	return result
}

func traverseMapPath(path []string, operatorMap *orderedmap.OrderedMap[string, any], isSearchStage bool) (interface{}, bool) {
	var current any = operatorMap
	isOpMap := false
	cutOffPart := ""
	for i, part := range path {
		m, ok := current.(*orderedmap.OrderedMap[string, any])
		if !ok {
			return nil, false
		}
		val, exists := m.Get(part)
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
		opVal, _ := OperatorMapDefs.Get(cutOffPart)
		withoutArbitraryKey := RemoveElementAfter(path, cutOffPart)
		newPath := RemoveElementsBeforeIncluding(withoutArbitraryKey, cutOffPart)
		if len(newPath) < len(path) {
			if opValMap, ok := opVal.(*orderedmap.OrderedMap[string, any]); ok {
				return traverseMapPath(newPath, opValMap, isSearchStage)
			}
		}
	}
	if current != nil {
		return current, true
	}
	return nil, false
}

func augmentOp(op *orderedmap.OrderedMap[string, any], v *orderedmap.OrderedMap[string, any]) orderedmap.OrderedMap[string, any] {
	if redactedFieldsRegexp == nil {
		return *op
	}
	augmentedOp := orderedmap.NewOrderedMap[string, any]()
	convertRedactableToExempt := false
	// iterate through the op keys, and check whether any of them is a FieldName:
	for el := op.Front(); el != nil; el = el.Next() {
		if el.Value == FieldName {
			val, _ := v.Get(el.Key)
			fieldName, _ := val.(string)
			if fieldName != "" && !redactedFieldsRegexp.MatchString(fieldName) {
				convertRedactableToExempt = true
			}
		}
		augmentedOp.Set(el.Key, el.Value)
	}

	if convertRedactableToExempt {
		for el := augmentedOp.Front(); el != nil; el = el.Next() {
			if el.Value == Redactable {
				augmentedOp.Set(el.Key, Exempt)
			}
		}
	}
	return *augmentedOp
}

func getOp(keyPath []string, isSearchStage bool) (interface{}, bool) {
	if isSearchStage {
		searchOpMeta, isSearchOp := traverseMapPath(keyPath, SearchAggregationOperators, true)
		if isSearchOp {
			return searchOpMeta, true
		}
		coreSearchOpMeta, isCoreSearchOp := SearchOperators.Get(keyPath[len(keyPath)-1])
		if isCoreSearchOp {
			return coreSearchOpMeta, true
		}
	} else {
		coreOpMeta, isCoreOp := CoreOperators.Get(keyPath[len(keyPath)-1])
		if isCoreOp {
			return coreOpMeta, true
		}
		aggOpMeta, isAggOp := traverseMapPath(keyPath, AggregationOperators, false)
		if isAggOp {
			return aggOpMeta, true
		}
	}
	return nil, false
}

func redactPipelineStage(stage interface{}, redactFieldNames bool, keyPath []string, inSearchStage bool) interface{} {
	switch s := stage.(type) {
	case *orderedmap.OrderedMap[string, any]:
		newMap := orderedmap.NewOrderedMap[string, any]()
		for el := s.Front(); el != nil; el = el.Next() {
			k := el.Key
			v := el.Value
			redactedKey := k
			newKeyPath := append(keyPath, k)
			opMeta, isOp := getOp(newKeyPath, inSearchStage)
			if redactFieldNames && (!isOp || (isOp && opMeta == nil)) {
				redactedKey = HashName(k)
			}
			if isOp && inSearchStage && opMeta != nil {
				if opMap, ok := opMeta.(*orderedmap.OrderedMap[string, any]); ok {
					if vMap, ok := v.(*orderedmap.OrderedMap[string, any]); ok {
						augmentedOpMeta := augmentOp(opMap, vMap)
						opMeta = &augmentedOpMeta
					}
				}
			}
			switch meta := opMeta.(type) {
			case OperatorType:
				switch meta {
				case FieldName:
					if redactFieldNames {
						switch vTyped := v.(type) {
						case string:
							if len(keyPath) > 0 {
								newMap.Set(redactedKey, vTyped)
							} else if _, isOp := getOp([]string{vTyped}, inSearchStage); isOp {
								newMap.Set(redactedKey, vTyped)
							} else {
								newMap.Set(redactedKey, HashName(vTyped))
							}
						case *orderedmap.OrderedMap[string, any]:
							newMap.Set(redactedKey, redactPipelineStage(vTyped, redactFieldNames, newKeyPath, inSearchStage))
						case []any:
							isSelectivelyRedactable := isRedactableFieldPatternInArray(vTyped)
							newMap.Set(redactedKey, redactArrayValues(vTyped, redactFieldNames, inSearchStage, isSelectivelyRedactable, newKeyPath))
						default:
							newMap.Set(redactedKey, redactScalarValue([]string{k}, v, inSearchStage, false))
						}
					} else {
						newMap.Set(redactedKey, v)
					}
					continue
				case Namespace:
					if redactNamespaces {
						switch vTyped := v.(type) {
						case string:
							newMap.Set(redactedKey, HashName(vTyped))
						default:
							newMap.Set(redactedKey, v)
						}
					} else {
						newMap.Set(redactedKey, v)
					}
					continue
				case Exempt:
					newMap.Set(redactedKey, v)
					continue
				case Pipeline:
					if arr, ok := v.([]any); ok {
						isSelectivelyRedactable := isRedactableFieldPatternInArray(arr)
						newMap.Set(redactedKey, redactArrayValues(arr, redactFieldNames, inSearchStage, isSelectivelyRedactable, newKeyPath))
					} else {
						newMap.Set(redactedKey, v)
					}
					continue
				case OperatorArray:
					if arr, ok := v.([]any); ok {
						redactedArr := make([]any, len(arr))
						for i, elem := range arr {
							redactedArr[i] = redactPipelineStage(elem, redactFieldNames, newKeyPath, inSearchStage)
						}
						newMap.Set(redactedKey, redactedArr)
					} else {
						newMap.Set(redactedKey, v)
					}
					continue
				}
			case *orderedmap.OrderedMap[string, any]:
				if subMap, ok := v.(*orderedmap.OrderedMap[string, any]); ok {
					newSubMap := orderedmap.NewOrderedMap[string, any]()
					for subEl := subMap.Front(); subEl != nil; subEl = subEl.Next() {
						subK := subEl.Key
						subV := subEl.Value
						subMeta, subFound := meta.Get(subK)
						if subFound {
							switch subMetaTyped := subMeta.(type) {
							case OperatorType:
								switch subMetaTyped {
								case FieldName:
									if redactFieldNames {
										switch subVTyped := subV.(type) {
										case string:
											if _, isOp := getOp([]string{subVTyped}, inSearchStage); isOp {
												newSubMap.Set(subK, subVTyped)
											} else {
												newSubMap.Set(subK, HashName(subVTyped))
											}
										case *orderedmap.OrderedMap[string, any]:
											newSubMap.Set(subK, redactPipelineStage(subVTyped, redactFieldNames, append(newKeyPath, subK), inSearchStage))
										case []any:
											isSelectivelyRedactable := isRedactableFieldPatternInArray(subVTyped)
											newSubMap.Set(subK, redactArrayValues(subVTyped, redactFieldNames, inSearchStage, isSelectivelyRedactable, append(newKeyPath, subK)))
										default:
											newSubMap.Set(subK, redactScalarValue([]string{k}, subV, inSearchStage, false))
										}
									} else {
										newSubMap.Set(subK, subV)
									}
									continue
								case Namespace:
									if redactNamespaces {
										switch subVTyped := subV.(type) {
										case string:
											newSubMap.Set(subK, HashName(subVTyped))
										default:
											newSubMap.Set(subK, subV)
										}
									} else {
										newSubMap.Set(subK, subV)
									}
									continue
								case Exempt:
									newSubMap.Set(subK, subV)
									continue
								case OperatorArray:
									if arr, ok := subV.([]any); ok {
										redactedArr := make([]any, len(arr))
										for i, elem := range arr {
											redactedArr[i] = redactPipelineStage(elem, redactFieldNames, newKeyPath, inSearchStage)
										}
										newSubMap.Set(subK, redactedArr)
									} else {
										newSubMap.Set(subK, subV)
									}
									continue
								case Pipeline:
									if arr, ok := subV.([]any); ok {
										isSelectivelyRedactable := isRedactableFieldPatternInArray(arr)
										newSubMap.Set(subK, redactArrayValues(arr, redactFieldNames, inSearchStage, isSelectivelyRedactable, newKeyPath))
									} else {
										newSubMap.Set(subK, subV)
									}
									continue
								}
							default:
							}
						}
						redactedSubK := subK
						metaVal, metaOk := meta.Get(subK)
						if redactFieldNames && (!subFound || (subFound && metaVal == nil && metaOk)) {
							redactedSubK = HashName(subK)
						}
						switch subVTyped := subV.(type) {
						case *orderedmap.OrderedMap[string, any]:
							newSubMap.Set(redactedSubK, redactPipelineStage(subVTyped, redactFieldNames, append(newKeyPath, subK), inSearchStage))
						case []any:
							isSelectivelyRedactable := isRedactableFieldPatternInArray(subVTyped)
							newSubMap.Set(redactedSubK, redactArrayValues(subVTyped, redactFieldNames, inSearchStage, isSelectivelyRedactable, append(newKeyPath, subK)))
						default:
							newSubMap.Set(redactedSubK, redactScalarValue([]string{k}, subV, inSearchStage, false))
						}
					}
					newMap.Set(redactedKey, newSubMap)
					continue
				}
			}
			if str, ok := v.(string); ok && len(str) > 0 && str[0] == '$' && !redactFieldNames {
				newMap.Set(redactedKey, v)
				continue
			}
			switch vTyped := v.(type) {
			case *orderedmap.OrderedMap[string, any]:
				newMap.Set(redactedKey, redactPipelineStage(vTyped, redactFieldNames, newKeyPath, inSearchStage))
			case []any:
				isSelectivelyRedactable := isRedactableFieldPatternInArray(vTyped)
				newMap.Set(redactedKey, redactArrayValues(vTyped, redactFieldNames, inSearchStage, isSelectivelyRedactable, newKeyPath))
			default:
				newMap.Set(redactedKey, redactScalarValue(newKeyPath, v, inSearchStage, false))
			}
		}
		return newMap
	case []any:
		isSelectivelyRedactable := isRedactableFieldPatternInArray(s)
		return redactArrayValues(s, redactFieldNames, inSearchStage, isSelectivelyRedactable, keyPath)
	default:
		return stage
	}
}

func redactQueryValues(obj *orderedmap.OrderedMap[string, any], redactFieldNames bool, isSearchStage bool, parentCoreOp interface{}, keyPath []string) *orderedmap.OrderedMap[string, any] {
	newObj := orderedmap.NewOrderedMap[string, any]()
	for el := obj.Front(); el != nil; el = el.Next() {
		k := el.Key
		v := el.Value
		redactedKey := k
		newKeyPath := append(keyPath, k)
		var isOp bool
		var coreOp interface{}
		if parentCoreOp != nil {
			if parentMap, ok := parentCoreOp.(*orderedmap.OrderedMap[string, any]); ok {
				coreOp, isOp = parentMap.Get(k)
			} else {
				coreOp, isOp = CoreOperators.Get(k)
			}
		} else {
			coreOp, isOp = CoreOperators.Get(k)
		}
		if redactFieldNames {
			if !isOp {
				redactedKey = HashName(k)
			}
		}
		switch val := v.(type) {
		case *orderedmap.OrderedMap[string, any]:
			newObj.Set(redactedKey, redactQueryValues(val, redactFieldNames, isSearchStage, coreOp, newKeyPath))
		case []any:
			isSelectivelyRedactable := isRedactableFieldPatternInArray(val)
			newObj.Set(redactedKey, redactArrayValuesWithKey(k, val, redactFieldNames, isSearchStage, isSelectivelyRedactable, newKeyPath))
		default:
			if v != nil {
				if str, ok := v.(string); ok && len(str) > 0 && str[0] == '$' {
					isOp := false
					if _, ok := CoreOperators.Get(str); ok {
						isOp = true
					}
					if redactFieldNames && !isOp {
						newObj.Set(redactedKey, HashName(str))
					} else {
						newObj.Set(redactedKey, v)
					}
				} else {
					if coreOp != Exempt {
						newObj.Set(redactedKey, redactScalarValue(newKeyPath, v, isSearchStage, false))
					} else {
						newObj.Set(redactedKey, v)
					}
				}
			}
		}
	}
	return newObj
}

func isRedactableFieldPatternInArray(arr []any) bool {
	if redactedFieldsRegexp == nil {
		return false
	}
	for _, item := range arr {
		// check if the item is a string, then strip of a leading dollar sign and matches the redactedFieldsRegexp
		if str, ok := item.(string); ok && len(str) > 0 && str[0] == '$' {
			if redactedFieldsRegexp != nil && redactedFieldsRegexp.MatchString(strings.TrimPrefix(str, "$")) {
				return true
			}
		}
	}
	return false
}

func redactArrayValuesWithKey(parentKey string, arr []any, redactFieldNames bool, isSearchStage bool, isSelectivelyRedactable bool, keyPath []string) []any {
	for i, item := range arr {
		switch itemTyped := item.(type) {
		case *orderedmap.OrderedMap[string, any]:
			arr[i] = redactQueryValues(itemTyped, redactFieldNames, isSearchStage, nil, keyPath)
		case []any:
			arr[i] = redactArrayValuesWithKey(parentKey, itemTyped, redactFieldNames, isSearchStage, isSelectivelyRedactable, keyPath)
		default:
			if item != nil {
				if str, ok := item.(string); ok && len(str) > 0 && str[0] == '$' {
					isOp := false
					if _, ok := CoreOperators.Get(str); ok {
						isOp = true
					}
					if redactFieldNames && !isOp {
						arr[i] = HashName(str)
					} else {
						arr[i] = item
					}
				} else {
					arr[i] = redactScalarValue([]string{parentKey}, item, isSearchStage, isSelectivelyRedactable)
				}
			}
		}
	}
	return arr
}

func redactArrayValues(arr []any, redactFieldNames bool, isSearchStage bool, isSelectivelyRedactable bool, keyPath []string) []any {
	return redactArrayValuesWithKey("", arr, redactFieldNames, isSearchStage, isSelectivelyRedactable, keyPath)
}

func redactString(s string, nonEncryptedValue string) string {
	if shouldEncrypt && encryptionKey != nil {
		encrypted, err := Encrypt([]byte(s), encryptionKey)
		if err != nil {
			return s // Fallback to original if encryption fails
		}
		return base64.StdEncoding.EncodeToString(encrypted)
	}
	return nonEncryptedValue
}

func reMatchesAnyKeyInPath(keyPath *[]string, pattern *regexp.Regexp) bool {
	if keyPath == nil || pattern == nil {
		return false
	}
	for _, key := range *keyPath {
		if pattern.MatchString(key) {
			return true
		}
	}
	return false
}

func redactScalarValue(keyPath []string, v interface{}, isSearchStage bool, isSelectivelyRedactable bool) interface{} {
	closestParentKey := ""
	if len(keyPath) == 0 {
		closestParentKey = ""
	} else {
		op, isOp := getOp(keyPath, isSearchStage)
		if !isOp {
			closestParentKey = keyPath[len(keyPath)-1]
		} else {
			if op == Exempt {
				return v
			}
		}
	}
	returnPlain := !isSearchStage &&
		redactedFieldsRegexp != nil &&
		!isSelectivelyRedactable &&
		!reMatchesAnyKeyInPath(&keyPath, redactedFieldsRegexp)
	if returnPlain {
		return v
	}
	closestParentKey = keyPath[len(keyPath)-1]
	switch closestParentKey {
	case "$date":
		return redactString(v.(string), RedactedISODate)
	case "$oid":
		return redactString(v.(string), "000000000000000000000000")
	}
	switch v.(type) {
	case string:
		str := v.(string)
		if IsEmail(str) {
			return redactString(v.(string), "redacted@redacted.com")
		}
		return redactString(v.(string), redactedString)
	case float64, int, int64, json.Number:
		if redactNumbers {
			return RedactedNumber
		}
		return v
	case bool:
		if redactBooleans {
			return RedactedBoolean
		}
		return v
	default:
		return redactedString
	}
}

func isInSearchStage(stage interface{}) bool {
	if m, ok := stage.(*orderedmap.OrderedMap[string, any]); ok {
		for el := m.Front(); el != nil; el = el.Next() {
			k := el.Key
			if k == "$search" || k == "$searchMeta" || k == "$vectorSearch" {
				return true
			}
		}
	}
	return false
}
