package main

const (
	RedactedISODate  = "1970-01-01T00:00:00.000Z"
	RedactedString   = "REDACTED"
	RedactedNumber   = float64(0)
	RedactedBoolean  = false
	RedactedObjectId = "000000000000000000000000"
	RedactedUUID     = "AAAAAAAAAAAAAAAAAAA="
)

var (
	TopLevelSearchOperators = []string{"$search", "$searchMeta", "$vectorSearch", "$rankFusion"}
)
