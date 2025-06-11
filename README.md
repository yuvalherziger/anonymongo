# anonymongo

[![Tests](https://github.com/yuvalherziger/anonymongo/actions/workflows/test.yml/badge.svg)](https://github.com/yuvalherziger/anonymongo/actions/workflows/test.yml)
[![Build](https://github.com/yuvalherziger/anonymongo/actions/workflows/publish.yml/badge.svg)](https://github.com/yuvalherziger/anonymongo/actions/workflows/publish.yml)

Anonymize MongoDB log files before sharing them, and preserve value types and formats.

## Installation

To be added.

## Usage

Redact logs straight to standard output:

```shell
anonymongo mongod.log
```

Redact and write the results to a file:

```shell
anonymongo mongod.log -o mongod.redacted.log
```

Redact booleans to constant `false`:

```shell
anonymongo mongod.log -b
```

Redact numeric values to constant `0`:

```shell
anonymongo mongod.log -n
```

Redact network locations to constant `255.255.255.255:65535`:

```shell
anonymongo mongod.log -i
```

Change the default redaction replacement string:

```shell
anonymongo mongod.log -r "N/A"
```
