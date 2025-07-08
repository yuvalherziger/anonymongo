package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"

	"github.com/elliotchance/orderedmap/v3"

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

// HashName returns a consistent hash for a field name.
func HashName(field string) string {
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
func UnmarshalOrdered(data []byte) (*orderedmap.OrderedMap[string, any], error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	val, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	return val.(*orderedmap.OrderedMap[string, any]), nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}

	switch tok := tok.(type) {
	case json.Delim:
		switch tok {
		case '{':
			m := orderedmap.NewOrderedMap[string, any]()
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key := keyToken.(string)
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				m.Set(key, val)
			}
			_, _ = dec.Token() // consume '}'
			return m, nil
		case '[':
			var arr []any
			for dec.More() {
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			_, _ = dec.Token() // consume ']'
			return arr, nil
		}
	default:
		return tok, nil
	}
	return nil, io.ErrUnexpectedEOF
}

func MarshalOrdered(m *orderedmap.OrderedMap[string, any]) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for el, i := m.Front(), 0; el != nil; el, i = el.Next(), i+1 {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyBytes, err := json.Marshal(el.Key)
		if err != nil {
			return nil, err
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')

		switch v := el.Value.(type) {
		case *orderedmap.OrderedMap[string, any]:
			valBytes, err := MarshalOrdered(v)
			if err != nil {
				return nil, err
			}
			buf.Write(valBytes)
		case []any:
			// Handle arrays of maps
			buf.WriteByte('[')
			for j, item := range v {
				if j > 0 {
					buf.WriteByte(',')
				}
				switch vv := item.(type) {
				case *orderedmap.OrderedMap[string, any]:
					valBytes, err := MarshalOrdered(vv)
					if err != nil {
						return nil, err
					}
					buf.Write(valBytes)
				default:
					valBytes, err := json.Marshal(vv)
					if err != nil {
						return nil, err
					}
					buf.Write(valBytes)
				}
			}
			buf.WriteByte(']')
		default:
			valBytes, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			buf.Write(valBytes)
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir() // Ensure it's a file, not a directory
}
