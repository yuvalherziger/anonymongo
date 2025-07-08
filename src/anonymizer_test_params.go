package main

import "fmt"

type RedactTestCase struct {
	Name          string
	InputFile     string
	Options       func()
	ExpectedPaths map[string]interface{}
}

func AnonymizerTestParams() []RedactTestCase {
	return []RedactTestCase{
		{
			Name:      "Simple find",
			InputFile: "simple_find.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.filter.foo": "REDACTED",
				"command.filter.bar": "REDACTED",
				"nreturned":          float64(1),
			},
		},
		{
			Name:      "find with $expr",
			InputFile: "find_with_expr.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.filter.$expr.$and.0.$eq.1": "REDACTED",
				"command.filter.$expr.$and.1.$eq.1": "REDACTED",
			},
		},
		{
			Name:      "Simple aggregation with a match stage",
			InputFile: "simple_aggregation.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.status":              "REDACTED",
				"command.pipeline.0.$match.createdAt.$lt.$date": "1970-01-01T00:00:00.000Z",
			},
		},
		{
			Name:      "Complex aggregation",
			InputFile: "complex_aggregation.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.$expr.$and.0.$ne.1":                     "REDACTED",
				"command.pipeline.0.$match.$expr.$and.1.$lt.1.$date":               "1970-01-01T00:00:00.000Z",
				"command.pipeline.1.$lookup.pipeline.0.$match.organizationId.$oid": "000000000000000000000000",
				"command.pipeline.2.$project.numericStatus.$cond.if.$eq.1":         "REDACTED",
				"command.pipeline.2.$project.numericStatus.$cond.then":             float64(0),
				"command.pipeline.2.$project.numericStatus.$cond.else":             float64(0),
			},
		},
		{
			Name:      "Simple connection accepted network log with IP redaction",
			InputFile: "connection_accepted.json",
			Options:   setOptionsRedactedIPs,
			ExpectedPaths: map[string]interface{}{
				"remote": "255.255.255.255:65535",
			},
		},
		{
			Name:      "Simple update statement with query and multiple update docs",
			InputFile: "updates.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.updates.0.q._id.$oid":       "000000000000000000000000",
				"command.updates.0.u.$set.timestamp": float64(0),
				"command.updates.0.u.$set.foo":       "REDACTED",
				"command.updates.0.u.$set.bar":       false,
			},
		},
		{
			Name:      "Simple update one statement",
			InputFile: "updateOne.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.q._id.$in.0": "REDACTED",
				"command.u.$set.foo":  float64(0),
				"command.u.$set.bar":  "REDACTED",
			},
		},
		{
			Name:      "Simple update one statement - eager redaction",
			InputFile: "updateOne.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				fmt.Sprintf("command.q.%s.$in.0", HashName("_id")): "REDACTED",
				fmt.Sprintf("command.u.$set.%s", HashName("bar")):  "REDACTED",
			},
		},
		{
			Name:      "Inserts redacted",
			InputFile: "inserts.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.documents.0.foo":                           "REDACTED",
				"command.documents.0.bar":                           false,
				"command.documents.0.timestamp.$date":               "1970-01-01T00:00:00.000Z",
				"command.documents.0.val_arr.0":                     "REDACTED",
				"command.documents.0.emb_doc_arr.0.foo":             "REDACTED",
				"command.documents.0.emb_doc_arr.0.bar":             false,
				"command.documents.0.emb_doc_arr.0.timestamp.$date": "1970-01-01T00:00:00.000Z",
			},
		},
		{
			Name:      "No-op log stays unchanges",
			InputFile: "asio_log.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"hostAndPort":             "atlas-okh9ti-shard-00-01.y13gh.mongodb.net:27017",
				"dnsResolutionTimeMillis": float64(7),
				"tcpConnectionTimeMillis": float64(2043),
				"tlsHandshakeTimeMillis":  float64(11),
				"authTimeMillis":          float64(0),
				"hookTime":                nil,
				"totalTimeMillis":         float64(2061),
			},
		},
		{
			Name:      "Update with nested logical query",
			InputFile: "update_with_nested_logical_query.json",
			Options:   setOptionsRedactedAllWithOverride,
			ExpectedPaths: map[string]interface{}{
				"command.query.$and.0.name":                 "<VALUE REDACTED>",
				"command.query.$and.0.active.$ne":           false,
				"command.query.$and.1.$or.0.cAt.$lte.$date": "1970-01-01T00:00:00.000Z",
				"command.query.$and.1.$or.1.uAt.$lte.$date": "1970-01-01T00:00:00.000Z",
				"command.update.$set.uAt.$date":             "1970-01-01T00:00:00.000Z",
			},
		},
		{
			Name:      "Simple find with an $in operator",
			InputFile: "in_operator.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.filter.foo.$in.0": "REDACTED",
				"command.filter.foo.$in.1": "REDACTED",
			},
		},
		{
			Name:      "Simple find with an $elemMatch operator",
			InputFile: "elemMatch_operator.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.filter.transactions.$elemMatch.merchantId": float64(0),
				"command.filter.transactions.$elemMatch.location":   "REDACTED",
			},
		},
		{
			Name:      "find with getMore",
			InputFile: "getMore.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"originatingCommand.filter.foo":                                 "REDACTED",
				"originatingCommand.filter.bar":                                 "REDACTED",
				"originatingCommand.filter.$or.0.status.$nin.0":                 "REDACTED",
				"originatingCommand.filter.$or.0.status.$nin.1":                 "REDACTED",
				"originatingCommand.filter.$or.0.status.$nin.2":                 "REDACTED",
				"originatingCommand.filter.$or.1.status":                        "REDACTED",
				"originatingCommand.filter.$or.1.nested\\.stringAttribute":      "REDACTED",
				"originatingCommand.filter.$or.1.nested\\.numericAttribute.$ne": float64(0),
			},
		},
		{
			Name:      "aggregate with getMore",
			InputFile: "getMore_aggregate.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"originatingCommand.pipeline.0.$match.str1":           "REDACTED",
				"originatingCommand.pipeline.0.$match.str2":           "REDACTED",
				"originatingCommand.pipeline.0.$match.cAt.$gte.$date": "1970-01-01T00:00:00.000Z",
				"originatingCommand.pipeline.0.$match.cAt.$lte.$date": "1970-01-01T00:00:00.000Z",
				"originatingCommand.pipeline.1.$lookup.from":          "other_coll",
				"originatingCommand.pipeline.2.$project.other_docs":   float64(0),
			},
		},
		{
			Name:      "Simple find with eager redaction",
			InputFile: "simple_find.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.filter.foo":                              nil,
				"command.filter.bar":                              nil,
				fmt.Sprintf("command.filter.%s", HashName("foo")): "REDACTED",
				fmt.Sprintf("command.filter.%s", HashName("bar")): "REDACTED",
			},
		},
		{
			Name:      "Simple aggregation with a match stage and eager redaction",
			InputFile: "simple_aggregation.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.status":                                           nil,
				"command.pipeline.0.$match.createdAt.$lt.$date":                              nil,
				fmt.Sprintf("command.pipeline.0.$match.%s", HashName("status")):              "REDACTED",
				fmt.Sprintf("command.pipeline.0.$match.%s.$lt.$date", HashName("createdAt")): "1970-01-01T00:00:00.000Z",
			},
		},
		{
			Name:      "find with $expr and eager redaction",
			InputFile: "find_with_expr.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.filter.$expr.$and.0.$eq.0":             HashName("foo"),
				"command.filter.$expr.$and.0.$eq.1":             "REDACTED",
				"command.filter.$expr.$and.1.$eq.0":             HashName("bar"),
				"command.filter.$expr.$and.1.$eq.1":             "REDACTED",
				"command.sort._id":                              nil,
				fmt.Sprintf("command.sort.%s", HashName("_id")): float64(-1),
				// We should also hash field names in the plan summary indiscriminately:
				"planSummary": fmt.Sprintf("IXSCAN { %s: 1, %s: 1, %s: -1 }", HashName("foo"), HashName("bar"), HashName("_id")),
			},
		},
		{
			Name:      "Complex aggregation with eager redaction",
			InputFile: "complex_aggregation.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$match.$expr.$and.0.$ne.0":                                                  HashName("status"),
				"command.pipeline.0.$match.$expr.$and.0.$ne.1":                                                  "REDACTED",
				"command.pipeline.0.$match.$expr.$and.1.$lt.1.$date":                                            "1970-01-01T00:00:00.000Z",
				"command.pipeline.0.$match.$expr.$and.1.$lt.0":                                                  HashName("createdAt"),
				fmt.Sprintf("command.pipeline.1.$lookup.pipeline.0.$match.%s.$oid", HashName("organizationId")): "000000000000000000000000",
				// We have to hash field names in the pipeline stages too now:
				fmt.Sprintf("command.pipeline.1.$lookup.pipeline.1.$project.%s", HashName("_id")):       float64(0),
				fmt.Sprintf("command.pipeline.1.$lookup.pipeline.1.$project.%s", HashName("name")):      float64(1),
				fmt.Sprintf("command.pipeline.1.$lookup.pipeline.1.$project.%s", HashName("createdAt")): float64(1),
				fmt.Sprintf("command.pipeline.2.$project.%s.$cond.if.$eq.1", HashName("numericStatus")): "REDACTED",
				fmt.Sprintf("command.pipeline.2.$project.%s.$cond.then", HashName("numericStatus")):     float64(-1),
				fmt.Sprintf("command.pipeline.2.$project.%s.$cond.else", HashName("numericStatus")):     float64(1),
			},
		},
		{
			Name:      "Aggregation stages edge cases",
			InputFile: "aggregation_stages_edge_cases.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$bucket.boundaries":            []float64{float64(1840), float64(1850), float64(1860), float64(1870), float64(1880)},
				"command.pipeline.0.$bucket.groupBy":               "$year_born",
				"command.pipeline.0.$bucket.default":               "REDACTED",
				"command.pipeline.0.$bucket.output.count.$sum":     float64(1),
				"command.pipeline.1.$count":                        "totalArtists",
				"command.pipeline.2.$densify.field":                "timestamp",
				"command.pipeline.2.$densify.range.step":           float64(1),
				"command.pipeline.2.$densify.range.bounds.0.$date": "1970-01-01T00:00:00.000Z",
				"command.pipeline.2.$densify.range.bounds.1.$date": "1970-01-01T00:00:00.000Z",
				"command.pipeline.3.$facet.meta.0.$count":          "total",
				"command.pipeline.3.$facet.docs.0.$limit":          float64(10),
				"command.pipeline.3.$facet.docs.1.$skip":           float64(0),
			},
		},
		{
			Name:      "Aggregation stages edge cases with eager redaction",
			InputFile: "aggregation_stages_edge_cases.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$bucket.groupBy": HashName("$year_born"),
				"command.pipeline.1.$count":          HashName("totalArtists"),
				"command.pipeline.2.$densify.field":  HashName("timestamp"),
			},
		},
		{
			Name:      "Simple search",
			InputFile: "simple_search.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$search.index":      "default",
				"command.pipeline.0.$search.text.query": "REDACTED",
				"command.pipeline.0.$search.text.path":  "title",
			},
		},
		{
			Name:      "Search with compound operators",
			InputFile: "search_with_compound_operators.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$search.compound.should.0.text.path":                                                              "type",
				"command.pipeline.0.$search.compound.should.0.text.query":                                                             "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.0.text.path":                                              "category",
				"command.pipeline.0.$search.compound.should.1.compound.must.0.text.query":                                             "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.1.equals.value":                                           true,
				"command.pipeline.0.$search.compound.should.1.compound.must.1.equals.path":                                            "in_stock",
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.path":                                  "items",
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.operator.compound.must.0.text.query":   "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.operator.compound.must.0.text.path":    "items.tags",
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.operator.compound.should.0.text.query": "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.operator.compound.should.0.text.path":  "items.name",
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.score.embedded.aggregate":              "mean",
				"command.pipeline.0.$search.compound.should.2.exists.path":                                                            "quantities.lemons",
				"command.pipeline.0.$search.compound.should.3.geoShape.relation":                                                      "disjoint",
				"command.pipeline.0.$search.compound.should.3.geoShape.geometry.type":                                                 "Polygon",
				"command.pipeline.0.$search.compound.should.3.geoShape.path":                                                          "address.location",
				"command.pipeline.0.$search.compound.minimumShouldMatch":                                                              float64(1),
			},
		},
		{
			Name:      "Search with compound operators with eager redaction",
			InputFile: "search_with_compound_operators.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$search.compound.should.0.text.path":                                                              HashName("type"),
				"command.pipeline.0.$search.compound.should.0.text.query":                                                             "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.0.text.path":                                              HashName("category"),
				"command.pipeline.0.$search.compound.should.1.compound.must.0.text.query":                                             "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.1.equals.value":                                           true,
				"command.pipeline.0.$search.compound.should.1.compound.must.1.equals.path":                                            HashName("in_stock"),
				"command.pipeline.0.$search.compound.minimumShouldMatch":                                                              float64(1),
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.path":                                  HashName("items"),
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.operator.compound.must.0.text.query":   "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.operator.compound.must.0.text.path":    HashName("items.tags"),
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.operator.compound.should.0.text.query": "REDACTED",
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.operator.compound.should.0.text.path":  HashName("items.name"),
				"command.pipeline.0.$search.compound.should.1.compound.must.2.embeddedDocument.score.embedded.aggregate":              "mean",
				"command.pipeline.0.$search.compound.should.2.exists.path":                                                            HashName("quantities.lemons"),
				"command.pipeline.0.$search.compound.should.3.geoShape.relation":                                                      "disjoint",
				"command.pipeline.0.$search.compound.should.3.geoShape.geometry.type":                                                 "Polygon",
				"command.pipeline.0.$search.compound.should.3.geoShape.path":                                                          HashName("address.location"),
			},
		},
		{
			Name:      "Search Meta - facets",
			InputFile: "search_meta_facets.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$searchMeta.facet.operator.range.gte.$date":   "1970-01-01T00:00:00.000Z",
				"command.pipeline.0.$searchMeta.facet.operator.range.lte.$date":   "1970-01-01T00:00:00.000Z",
				"command.pipeline.0.$searchMeta.facet.facets.directorsFacet.type": "string",
				"command.pipeline.0.$searchMeta.facet.facets.directorsFacet.path": "directors",
				"command.pipeline.0.$searchMeta.facet.facets.yearFacet.type":      "number",
				"command.pipeline.0.$searchMeta.facet.facets.yearFacet.path":      "year",
			},
		},
		{
			Name:      "Search Meta - facets with eager redaction",
			InputFile: "search_meta_facets.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				fmt.Sprintf("command.pipeline.0.$searchMeta.facet.facets.%s.type", HashName("yearFacet")): "number",
				fmt.Sprintf("command.pipeline.0.$searchMeta.facet.facets.%s.path", HashName("yearFacet")): "year",
			},
		},
		{
			Name:      "Vector search",
			InputFile: "vector_search.json",
			Options:   setOptionsRedactedAll,
			ExpectedPaths: map[string]interface{}{
				"command.pipeline.0.$vectorSearch.index":         "vector_index",
				"command.pipeline.0.$vectorSearch.path":          "plot_embedding",
				"command.pipeline.0.$vectorSearch.queryVector.0": float64(0),
				"command.pipeline.0.$vectorSearch.numCandidates": float64(150),
				"command.pipeline.0.$vectorSearch.limit":         float64(10),
			},
		},
		{
			Name:      "Find with binary data",
			InputFile: "find_with_binary_data.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.filter.uuid.$binary.subType": "04",
				"command.filter.uuid.$binary.base64":  "REDACTED",
				"planningTimeMicros":                  float64(43226),
				"keysExamined":                        float64(1),
				"docsExamined":                        float64(1),
				"hasSortStage":                        false,
				"fromPlanCache":                       true,
			},
		},
		{
			Name:      "Find with binary data and eager redaction",
			InputFile: "find_with_binary_data.json",
			Options:   setOptionsRedactedStringsWithEagerRedaction,
			ExpectedPaths: map[string]interface{}{
				fmt.Sprintf("command.filter.%s.$binary.subType", HashName("uuid")): "04",
				fmt.Sprintf("command.filter.%s.$binary.base64", HashName("uuid")):  "REDACTED",
				"planningTimeMicros": float64(43226),
				"keysExamined":       float64(1),
				"docsExamined":       float64(1),
				"hasSortStage":       false,
				"fromPlanCache":      true,
			},
		},
		{
			Name:      "Find with email addresses",
			InputFile: "find_with_emails.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"command.filter.$or.0.username": "redacted@redacted.com",
				"command.filter.$or.1.username": "redacted@redacted.com",
				"command.filter.$or.2.username": "redacted@redacted.com",
				"command.filter.$or.3.username": "redacted@redacted.com",
			},
		},
		{
			Name:      "Error query",
			InputFile: "error-query.json",
			Options:   setOptionsRedactedStrings,
			ExpectedPaths: map[string]interface{}{
				"cmd.pipeline.0.$match.foo": "REDACTED",
			},
		},
		{
			Name:      "Simple find with namespace redaction",
			InputFile: "simple_find.json",
			Options:   setOptionsRedactedStringsAndNamespaces,
			ExpectedPaths: map[string]interface{}{
				"command.filter.foo": "REDACTED",
				"command.filter.bar": "REDACTED",
				"nreturned":          float64(1),
				"ns":                 HashName("my_db.my_coll"),
			},
		},
		{
			Name:      "Simple aggregation with namespace redaction",
			InputFile: "simple_aggregation.json",
			Options:   setOptionsRedactedStringsAndNamespaces,
			ExpectedPaths: map[string]interface{}{
				"ns":                               HashName("my_db.my_coll"),
				"command.$db":                      HashName("my_db"),
				"command.aggregate":                HashName("my_coll"),
				"command.pipeline.0.$match.status": "REDACTED",
				"command.pipeline.0.$match.createdAt.$lt.$date": "1970-01-01T00:00:00.000Z",
			},
		},
		{
			Name:      "Lookup aggregation with namespace redaction",
			InputFile: "complex_aggregation.json",
			Options:   setOptionsRedactedStringsAndNamespaces,
			ExpectedPaths: map[string]interface{}{
				"command.$db":       HashName("my_db"),
				"command.aggregate": HashName("my_coll"),
				"ns":                HashName("my_db.my_coll"),
				"command.pipeline.0.$match.$expr.$and.0.$ne.1":                     "REDACTED",
				"command.pipeline.0.$match.$expr.$and.1.$lt.1.$date":               "1970-01-01T00:00:00.000Z",
				"command.pipeline.1.$lookup.pipeline.0.$match.organizationId.$oid": "000000000000000000000000",
				"command.pipeline.1.$lookup.from":                                  HashName("another_coll"),
				"command.pipeline.2.$project.numericStatus.$cond.if.$eq.1":         "REDACTED",
			},
		},
		{
			Name:      "Find and modify with namespace redaction",
			InputFile: "find_and_modify.json",
			Options:   setOptionsRedactedStringsAndNamespaces,
			ExpectedPaths: map[string]interface{}{
				"command.$db":                           HashName("my_db"),
				"command.findAndModify":                 HashName("my_coll"),
				"ns":                                    HashName("my_db.my_coll"),
				"command.update.$set.updatedAt.$date":   "1970-01-01T00:00:00.000Z",
				"command.update.$set.updatedBy.$oid":    "000000000000000000000000",
				"command.update.$set.status":            "REDACTED",
				"command.update.$addToSet.tags.$each.0": "REDACTED",
				"command.update.$addToSet.tags.$each.1": "REDACTED",
				"command.update.$addToSet.tags.$each.2": "REDACTED",
			},
		},
	}
}

func setOptionsRedactedStrings() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(false)
	SetRedactBooleans(false)
	SetRedactIPs(false)
	SetEagerRedactionPaths([]string{})
	SetRedactNamespaces(false)
}

func setOptionsRedactedStringsAndNamespaces() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(false)
	SetRedactBooleans(false)
	SetRedactIPs(false)
	SetEagerRedactionPaths([]string{})
	SetRedactNamespaces(true)
}

func setOptionsRedactedStringsWithEagerRedaction() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(false)
	SetRedactBooleans(false)
	SetRedactIPs(false)
	SetEagerRedactionPaths([]string{
		"my_db.my_coll",
	})
	SetRedactNamespaces(false)
}

func setOptionsRedactedAllWithOverride() {
	SetRedactedString("<VALUE REDACTED>")
	SetRedactNumbers(true)
	SetRedactBooleans(true)
	SetRedactIPs(true)
	SetEagerRedactionPaths([]string{})
	SetRedactNamespaces(false)
}

func setOptionsRedactedAll() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(true)
	SetRedactBooleans(true)
	SetRedactIPs(true)
	SetEagerRedactionPaths([]string{})
	SetRedactNamespaces(false)
}

func setOptionsRedactedIPs() {
	SetRedactedString("REDACTED")
	SetRedactNumbers(false)
	SetRedactBooleans(false)
	SetRedactIPs(true)
	SetEagerRedactionPaths([]string{})
	SetRedactNamespaces(false)
}
