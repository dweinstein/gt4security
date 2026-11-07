"
Rows-only window strategy backed by the on-disk modified_id.csv cache.

Applies to scope=#window with needFullRecords=false. Triggers {{gtMethod:Gt4SecurityOsvFeedClient>>#downloadModifiedIds}} (conditional-GET revalidated) and scans the cached file locally, filtering by timestamp >= since and optionally by ecosystem membership. Returns an OrderedCollection of row Dictionaries with keys timestamp / ecosystem / id.

Cost:
- 1 KB when the cache is revalidatable (304 handshake)
- ~42 MB when not cached (full CSV download)

For cold-cache 1-30 day windows the {{gtClass:Gt4SecurityStreamWindowStrategy}} is usually cheaper.
"
Class {
	#name : 'Gt4SecurityCachedCsvWindowStrategy',
	#superclass : 'Gt4SecurityFeedStrategy',
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'examples' }
Gt4SecurityCachedCsvWindowStrategy class >> exampleApplicableOnlyForRowsWindow [
	<gtExample>
	| client ctx s |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	s := self new.
	self assert: (s canExecute: (Gt4SecurityFeedQuery windowSince: Date today - 7 days inEcosystem: 'npm') inContext: ctx).
	self assert: (s canExecute: (Gt4SecurityFeedQuery hydratedWindowSince: Date today - 1 days inEcosystem: 'Pub') inContext: ctx) not.
	self assert: (s canExecute: (Gt4SecurityFeedQuery fullEcosystem: 'Pub') inContext: ctx) not.
	^ s
]

{ #category : 'examples' }
Gt4SecurityCachedCsvWindowStrategy class >> exampleCostDropsWhenCacheIsAvailable [
	<gtExample>
	| s q warmClient coldClient warmCtx coldCtx |
	s := self new.
	q := Gt4SecurityFeedQuery windowSince: Date today - 30 days inEcosystem: 'npm'.
	warmClient := Gt4SecurityOsvFeedClient new.
	"warmClient default cache path may or may not exist; just build a context off it."
	warmCtx := Gt4SecurityFeedContext for: warmClient.
	coldClient := Gt4SecurityOsvFeedClient new.
	coldClient cacheDirectory: (FileLocator temp asFileReference / ('gt4sec-cached-ex-cold-' , UUID new asString)).
	coldCtx := Gt4SecurityFeedContext for: coldClient.
	self assert: (s costFor: q inContext: coldCtx) > 10000000.
	warmCtx isCsvCacheAvailable ifTrue: [
		self assert: (s costFor: q inContext: warmCtx) < 10000 ].
	^ { 'cold' -> (s costFor: q inContext: coldCtx). 'warm?' -> (s costFor: q inContext: warmCtx) }
]

{ #category : 'protocol' }
Gt4SecurityCachedCsvWindowStrategy >> canExecute: aQuery inContext: aContext [
	"Rows-only window queries. We CAN execute even with empty cache — we just pay a full
	41 MB download up front — but the selector will prefer StreamWindow in that case via cost."
	^ aQuery scope = #window and: [ aQuery needFullRecords not ]
]

{ #category : 'cost' }
Gt4SecurityCachedCsvWindowStrategy >> costFor: aQuery inContext: aContext [
	"Revalidate (304 handshake) if cache is available; otherwise charge the full-CSV download."
	^ aContext isCsvCacheAvailable
		ifTrue: [ Gt4SecurityFeedCostModel revalidateHandshakeBytes ]
		ifFalse: [ Gt4SecurityFeedCostModel modifiedIdsFullBytes ]
]

{ #category : 'accessing' }
Gt4SecurityCachedCsvWindowStrategy >> description [
	^ 'cached modified_id.csv + local scan'
]

{ #category : 'executing' }
Gt4SecurityCachedCsvWindowStrategy >> doExecute: aQuery on: aClient inContext: aContext [
	"Triggers downloadModifiedIds (which conditional-GETs the cache), then scans it locally.
	Delegates to the short-circuiting modifiedIdsSince:ecosystems: so the scan stops at the
	cutoff and rejects non-matching ecosystems before parsing.
	Returns OrderedCollection of row dictionaries (keys: timestamp, ecosystem, id)."
	| cutoff ecoSet |
	cutoff := aClient isoDateStringFor: aQuery since.
	ecoSet := aQuery ecosystems ifNotNil: [ :e | e asSet ].
	^ aClient modifiedIdsSince: cutoff ecosystems: ecoSet
]

{ #category : 'ranking' }
Gt4SecurityCachedCsvWindowStrategy >> tiebreakPriority [
	"Prefer this over streaming when both revalidate to the same handshake cost — cached scan
	is faster once the CSV is on disk."
	^ 40
]
