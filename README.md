# anonymongo

[![Tests](https://github.com/yuvalherziger/anonymongo/actions/workflows/test.yml/badge.svg)](https://github.com/yuvalherziger/anonymongo/actions/workflows/test.yml)
[![Build](https://github.com/yuvalherziger/anonymongo/actions/workflows/release.yml/badge.svg)](https://github.com/yuvalherziger/anonymongo/actions/workflows/release.yml)

Anonymize MongoDB log files before sharing them, and preserve value types and formats.

## Installation

### Homebrew

To be added

### Release download

To be added

### Build from source

To be added

## Usage

tl;dr: `anonymongo --help`

```
Anonymize MongoDB log files by replacing sensitive information with generic placeholders

Usage:
  anonymongo <JSON file or gzipped MongoDB log file> [flags] 

Flags:
  -b, --anonymizeBooleans    Anonymize boolean values to false
  -i, --anonymizeIPs         Anonymize IP addresses to 255.255.255.255
  -n, --anonymizeNumbers     Anonymize numeric values to 0
  -h, --help                 help for anonymongo
  -o, --outputFile string    Write output to file instead of stdout
  -r, --replacement string   Replacement string for anonymized values (default "REDACTED")
```

Examples:


```shell
# Redact logs and gzipped logs straight to standard output:
anonymongo mongod.log
# Redact and write the results to a file
anonymongo mongod.log -o mongod.redacted.log
# Redact booleans to constant `false`
anonymongo mongod.log -b
# Redact numeric values to constant `0`
anonymongo mongod.log -n
# Redact network locations to constant `255.255.255.255:65535`
anonymongo mongod.log -i
# Change the default redaction replacement string
anonymongo mongod.log -r "some other redaction placehoder"
```

## Tests

Every new refactoring case must be covered by a test to ensure the expected results are yielded and no
regression is introducesd. The source code contains a single unit test: [./src/anonymizer_test.go](./src/anonymizer_test.go).
It's a parameterized unit test, where each test is a go struct with the following information:

* Test name (e.g., "$expr reduction inside $lookup stage")
* Input file: a relative path to a JSON text file input containing a single log entry
* Options: a preset function to determine the conditions for the test (e.g., flags, overrides, etc.)
* A mapping of JSON paths and their expected post-redaction values.

Below is an example of such element you can append to the parameterized cases:

```go
{
  Name:          "$expr reduction inside $lookup stage",
  InputFile:     "test_data/expr_in_lookup_pipeline.json",
  Options:       setOptionsRedactedStrings,
  ExpectedPaths: map[string]interface{}{
    "command.pipeline.1.$lookup.pipeline.0.$match.$expr.$eq.1": "000000000000000000000000",
  },
}
```

Run the tests the following way:

```shell
go test -v ./src/
```

The `-v` (verbose) flag will help you troubleshoot test failures. Every commit pushed upstream will trigger the unit tests.

##  Disclaimer

This software is not supported by MongoDB, Inc. under any of their commercial support subscriptions or otherwise.
Any usage of anonymongo is at your own risk. Bug reports, feature requests, and questions can be posted in the
[Issues section](https://github.com/yuvalherziger/anonymongo/issues) of this repository.
