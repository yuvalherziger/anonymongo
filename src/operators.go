package main

type OperatorType int

const (
	Pipeline      OperatorType = iota
	Exempt        OperatorType = iota
	Redactable    OperatorType = iota
	FieldName     OperatorType = iota
	OperatorArray OperatorType = iota
	OperatorMap   OperatorType = iota
)

var AggregationOperators = map[string]interface{}{
	"$addFields": Redactable,
	"$bucket": map[string]interface{}{
		"boundaries": Redactable,
		"default":    Redactable,
		"output":     Redactable,
		"groupBy":    FieldName,
	},
	"$bucketAuto": map[string]interface{}{
		"granularity": Redactable,
		"output":      Redactable,
		"buckets":     Redactable,
		"groupBy":     Redactable,
	},
	"$changeStream": map[string]interface{}{
		"allChangesForCluster":     Redactable,
		"fullDocument":             Redactable,
		"fullDocumentBeforeChange": Redactable,
		"resumeAfter":              Redactable,
		"showExpandedEvents":       Redactable,
		"startAfter":               Redactable,
		"startAtOperationTime":     Redactable,
	},
	"$changeStreamSplitLargeEvent": Redactable,
	"$collStats": map[string]interface{}{
		"latencyStats":   Redactable,
		"storageStats":   Redactable,
		"count":          Redactable,
		"queryExecStats": Redactable,
	},
	"$count": FieldName,
	"$currentOp": map[string]interface{}{
		"allUsers":        Redactable,
		"idleConnections": Redactable,
		"idleCursors":     Redactable,
		"idleSessions":    Redactable,
		"localOps":        Redactable,
	},
	"$densify": map[string]interface{}{
		"field":             FieldName,
		"partitionByFields": Redactable,
		"range": map[string]interface{}{
			"step":   Exempt,
			"units":  Exempt,
			"bounds": Redactable,
		},
	},
	"$documents": Redactable,
	"$facet":     Pipeline,
	"$fill": map[string]interface{}{
		"partitionByFields": FieldName,
		"partitionBy":       Redactable,
		"sortBy":            FieldName,
		"output":            Redactable,
	},
	"$geoNear": map[string]interface{}{
		"distanceField":      FieldName,
		"distanceMultiplier": Redactable,
		"includeLocs":        Redactable,
		"key":                Redactable,
		"maxDistance":        Redactable,
		"minDistance":        Redactable,
		"near":               Redactable,
		"query":              Redactable,
		"spherical":          Redactable,
	},
	"$graphLookup": map[string]interface{}{
		"from":                    Exempt,
		"startWith":               Redactable,
		"connectFromField":        FieldName,
		"connectToField":          FieldName,
		"as":                      Redactable,
		"maxDepth":                Redactable,
		"depthField":              FieldName,
		"restrictSearchWithMatch": Redactable,
	},
	"$group":      Redactable,
	"$indexStats": Redactable,
	"$limit":      Exempt,
	"$listLocalSessions": map[string]interface{}{
		"users":    Redactable,
		"allUsers": Redactable,
	},
	"$listSampledQueries": map[string]interface{}{"namespace": nil},
	"$listSearchIndexes": map[string]interface{}{
		"id":   Redactable,
		"name": Redactable,
	},
	"$listSessions": map[string]interface{}{
		"users":    Redactable,
		"allUsers": Redactable,
	},
	"$lookup": map[string]interface{}{
		"from":         Exempt,
		"localField":   Redactable,
		"foreignField": Redactable,
		"let":          Redactable,
		"pipeline":     Pipeline,
		"as":           Exempt,
	},
	"$match": Redactable,
	"$merge": map[string]interface{}{
		"into":           Exempt,
		"on":             Redactable,
		"let":            Redactable,
		"whenMatched":    Exempt,
		"whenNotMatched": Exempt,
	},
	"$out": map[string]interface{}{
		"db":         Exempt,
		"coll":       Exempt,
		"timeseries": Exempt,
	},
	"$planCacheStats": Exempt,
	"$project":        Redactable,
	"$querySettings":  Exempt,
	"$queryStats":     Exempt,
	"$redact":         Redactable,
	"$replaceRoot":    map[string]interface{}{"newRoot": FieldName},
	"$replaceWith":    Redactable,
	"$sample":         Exempt,
	"$set":            Redactable,
	"$setWindowFields": map[string]interface{}{
		"partitionBy": Redactable,
		"sortBy":      FieldName,
		"output":      Redactable,
		"window":      Redactable,
	},
	"$shardedDataDistribution": Exempt,
	"$skip":                    Exempt,
	"$sort":                    Redactable,
	"$sortByCount":             FieldName,
	"$unionWith": map[string]interface{}{
		"coll":     Exempt,
		"pipeline": Pipeline,
	},
	"$unset":  FieldName,
	"$unwind": FieldName,
}

var CoreOperators = func() map[string]interface{} {
	var coreOperators = map[string]interface{}{
		"$eq":            Redactable,
		"$gt":            Redactable,
		"$gte":           Redactable,
		"$in":            Redactable,
		"$lt":            Redactable,
		"$lte":           Redactable,
		"$ne":            Redactable,
		"$nin":           Redactable,
		"$and":           OperatorArray,
		"$not":           Redactable,
		"$nor":           Redactable,
		"$or":            OperatorArray,
		"$exists":        Redactable,
		"$type":          Redactable,
		"$expr":          Redactable,
		"$jsonSchema":    Redactable,
		"$mod":           Redactable,
		"$regex":         Redactable,
		"$text":          Redactable,
		"$where":         Redactable,
		"$geoIntersects": Redactable,
		"$geoWithin":     Redactable,
		"$near":          Redactable,
		"$nearSphere":    Redactable,
		"$all":           Redactable,
		"$elemMatch":     Redactable,
		"$size":          Redactable,
		"$bitsAllClear":  Redactable,
		"$bitsAllSet":    Redactable,
		"$bitsAnyClear":  Redactable,
		"$bitsAnySet":    Redactable,
		"$meta":          Redactable,
		"$slice":         Redactable,
		"$rand":          Redactable,
		"$natural":       Redactable,
		"$currentDate":   Redactable,
		"$inc":           Redactable,
		"$min":           Redactable,
		"$max":           Redactable,
		"$mul":           Redactable,
		"$rename":        Redactable,
		"$setOnInsert":   Redactable,
		"$addToSet":      Redactable,
		"$pop":           Redactable,
		"$pull":          Redactable,
		"$push":          Redactable,
		"$pullAll":       Redactable,
		"$each":          Redactable,
		"$position":      Redactable,
		"$bit":           Redactable,
		"$abs":           Redactable,
		"$add":           Redactable,
		"$ceil":          Redactable,
		"$divide":        Redactable,
		"$exp":           Redactable,
		"$floor":         Redactable,
		"$ln":            Redactable,
		"$log":           Redactable,
		"$log10":         Redactable,
		"$multiply":      Redactable,
		"$pow":           Redactable,
		"$round":         Redactable,
		"$sqrt":          Redactable,
		"$subtract":      Redactable,
		"$trunc":         Redactable,
		"$arrayElemAt":   Redactable,
		"$arrayToObject": Redactable,
		"$concatArrays":  Redactable,
		"$filter":        Redactable,
		"$firstN":        Redactable,
		"$indexOfArray":  Redactable,
		"$isArray":       Redactable,
		"$lastN":         Redactable,
		"$map":           Redactable,
		"$maxN":          Redactable,
		"$minN":          Redactable,
		"$objectToArray": Redactable,
		"$range":         Redactable,
		"$reduce":        Redactable,
		"$reverseArray":  Redactable,
		"$sortArray":     Redactable,
		"$zip":           Redactable,
		"$cmp":           Redactable,
		"$oid":           Redactable,
		"$date":          Redactable,
		"$cond": map[string]interface{}{
			"if":   Redactable,
			"then": Redactable,
			"else": Redactable,
		},
		"if":   Redactable,
		"then": Redactable,
		"else": Redactable,
	}
	mergeMaps(coreOperators, AggregationOperators)
	return coreOperators
}()

var OperatorMapDefs = map[string]interface{}{
	"facets": map[string]interface{}{
		"numBuckets": Exempt,
		"type":       Exempt,
		"path":       FieldName,
	},
}

var geoJSON = map[string]interface{}{
	"type":        Exempt,
	"coordinates": Redactable,
}

func mergeMaps(dst, src map[string]interface{}) {
	for k, v := range src {
		dst[k] = v
	}
}

var SearchOperators = map[string]interface{}{
	"autocomplete": map[string]interface{}{
		"query":      Redactable,
		"path":       FieldName,
		"tokenOrder": Exempt,
		"fuzzy":      Exempt,
		"score":      Exempt,
	},
	"compound": map[string]interface{}{
		"must":               OperatorArray,
		"mustNot":            OperatorArray,
		"should":             OperatorArray,
		"filter":             Redactable,
		"score":              Exempt,
		"minimumShouldMatch": Exempt,
	},
	"embeddedDocument": map[string]interface{}{
		"path":     FieldName,
		"operator": Redactable,
		"score":    Exempt,
	},
	"equals": map[string]interface{}{
		"path":  FieldName,
		"value": Redactable,
		"score": Exempt,
	},
	"exists": map[string]interface{}{
		"path":  FieldName,
		"score": Exempt,
	},
	"facet": map[string]interface{}{
		"operator": Redactable,
		"facets":   OperatorMap,
	},
	"geoShape": map[string]interface{}{
		"path":     FieldName,
		"relation": Exempt,
		"geometry": geoJSON,
		"score":    Exempt,
	},
	"geoWithin": map[string]interface{}{
		"path": FieldName,
		"box": map[string]interface{}{
			"bottomLeft": geoJSON,
			"topRight":   geoJSON,
		},
		"circle": map[string]interface{}{
			"center": geoJSON,
			"radius": Redactable,
		},
		"geometry": geoJSON,
		"score":    Exempt,
	},
	"in": map[string]interface{}{
		"path":  FieldName,
		"score": Exempt,
		"value": Redactable,
	},
	"moreLikeThis": map[string]interface{}{
		"like":  Redactable,
		"score": Exempt,
	},
	"near": map[string]interface{}{
		"path":   FieldName,
		"origin": Redactable,
		"pivot":  Redactable,
		"score":  Exempt,
	},
	"phrase": map[string]interface{}{
		"query":    Redactable,
		"path":     FieldName,
		"score":    Exempt,
		"slop":     Exempt,
		"synonyms": Redactable,
	},
	"queryString": map[string]interface{}{
		"defaultPath": FieldName,
		"query":       Redactable,
	},
	"range": map[string]interface{}{
		"path":  FieldName,
		"gte":   Redactable,
		"gt":    Redactable,
		"lte":   Redactable,
		"lt":    Redactable,
		"score": Exempt,
	},
	"regex": map[string]interface{}{
		"query":              Redactable,
		"path":               FieldName,
		"allowAnalyzedField": Exempt,
		"score":              Exempt,
	},
	"span": map[string]interface{}{
		"term": map[string]interface{}{
			"path":  FieldName,
			"query": Redactable,
		},
		"contains": map[string]interface{}{
			"spanToReturn": Exempt,
			"little":       Redactable,
			"big":          Redactable,
			"score":        Exempt,
		},
		"first": map[string]interface{}{
			"endPositionLte": Redactable,
			"operator":       Redactable,
			"score":          Exempt,
		},
		"near": map[string]interface{}{
			"clauses": Redactable,
			"slop":    Redactable,
			"inOrder": Exempt,
			"score":   Exempt,
		},
		"or": map[string]interface{}{
			"clauses": Redactable,
			"score":   Exempt,
		},
		"subtract": map[string]interface{}{
			"include": Redactable,
			"exclude": Redactable,
			"score":   Exempt,
		},
	},
	"text": map[string]interface{}{
		"query":         Redactable,
		"path":          FieldName,
		"fuzzy":         Exempt,
		"matchCriteria": Exempt,
		"score":         Exempt,
		"synonyms":      Redactable,
	},
	"wildcard": map[string]interface{}{
		"query":              Redactable,
		"path":               FieldName,
		"allowAnalyzedField": Exempt,
		"score":              Exempt,
	},
	"numBuckets": Exempt,
}

var SearchAggregationOperators = func() map[string]interface{} {
	agg := map[string]interface{}{}
	search := map[string]interface{}{
		"index": Exempt,
		"highlight": map[string]interface{}{
			"path":              FieldName,
			"maxCharsToExamine": Exempt,
			"maxNumPassages":    Exempt,
		},
		"concurrent": Exempt,
		"count": map[string]interface{}{
			"type":      Exempt,
			"threshold": Exempt,
		},
		"searchAfter":        Redactable,
		"searchBefore":       Redactable,
		"scoreDetails":       Exempt,
		"sort":               FieldName,
		"returnStoredSource": Exempt,
		"tracking":           map[string]interface{}{},
	}
	vectorSearch := map[string]interface{}{
		"exact":         Exempt,
		"filter":        Redactable,
		"index":         Exempt,
		"limit":         Exempt,
		"numCandidates": Exempt,
		"path":          FieldName,
		"queryVector":   Redactable,
	}
	mergeMaps(search, SearchOperators)
	agg["$search"] = search
	agg["$searchMeta"] = search
	agg["$vectorSearch"] = vectorSearch
	return agg
}()
