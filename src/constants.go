// Constants for the application:
package main

import "encoding/json"

const (
	RedactedISODate = "1970-01-01T00:00:00.000Z"
	RedactedString  = "REDACTED"
	RedactedNumber  = json.Number(rune(0))
	RedactedBoolean = false
)
