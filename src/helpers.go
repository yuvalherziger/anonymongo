package main

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

func ParsePlanSummary(planSummary string) []string {
	re := regexp.MustCompile(`IXSCAN\s*\{([^}]+)\}`)
	allMatches := re.FindAllStringSubmatch(planSummary, -1)
	fieldSet := make(map[string]struct{})

	for _, match := range allMatches {
		if len(match) > 1 {
			indexContent := match[1]
			potentialFields := strings.Split(indexContent, ",")
			for _, pf := range potentialFields {
				keyValPair := strings.SplitN(pf, ":", 2)
				if len(keyValPair) > 0 {
					key := strings.TrimSpace(keyValPair[0])

					if key != "" {
						subFields := strings.Split(key, ".")
						for _, sf := range subFields {
							fieldSet[sf] = struct{}{}
						}
					}
				}
			}
		}
	}

	if len(fieldSet) == 0 {
		return []string{}
	}

	fields := make([]string, 0, len(fieldSet))
	for field := range fieldSet {
		fields = append(fields, field)
	}

	sort.Strings(fields)
	return fields
}

// HashFieldName returns a consistent hash for a field name.
func HashFieldName(field string) string {
	trimmed := strings.TrimLeft(field, "$")
	parts := strings.Split(trimmed, ".")
	hashedParts := make([]string, len(parts))
	for i, part := range parts {
		h := sha256.Sum256([]byte(part))
		hashed := fmt.Sprintf("%s_%x", redactedString, h[:8])
		RedactedFieldMapping[part] = hashed
		hashedParts[i] = hashed
	}
	return strings.Join(hashedParts, ".")
}

func RemoveElementAfter(slice []string, marker string) []string {
	for i, v := range slice {
		if v == marker && i+1 < len(slice) {
			return append(slice[:i+1], slice[i+2:]...)
		}
	}
	return slice
}

func RemoveElementsBeforeIncluding(slice []string, marker string) []string {
	for i, v := range slice {
		if v == marker && i+1 < len(slice) {
			return slice[i+1:]
		}
	}
	return []string{}
}

func IsEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}
