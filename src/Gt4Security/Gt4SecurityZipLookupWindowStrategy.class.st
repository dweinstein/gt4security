"
I am a composite strategy that hydrates a window query by combining the CSV-based row scan with an ecosystem-zip batch extract — instead of fanning out one HTTPS GET per id like {{gtClass:Gt4SecurityHydratedWindowStrategy}}.

## How I execute

1. Delegate the rows sub-query (scope #window, needFullRecords: false) to the selector on the context — typically resolves to {{gtClass:Gt4SecurityCachedCsvWindowStrategy}}, which gives me an OrderedCollection of `{timestamp, ecosystem, id}` dictionaries.
2. Group the row ids by ecosystem.
3. For each ecosystem group, ensure `<eco>/all.zip` is cached (via conditional GET), then run ONE `unzip -o -j -d <dir> <zip> <id1.json> <id2.json> …` subprocess to extract just the target entries to a temp directory.
4. Parse each extracted JSON into a {{gtClass:Gt4SecurityVulnerability}} and clean up the temp directory.

Result is a {{gtClass:Gt4SecurityVulnerabilityGroup}}.

## When the selector picks me

My cost function charges:
- `revalidateHandshakeBytes` when the ecosystem zip is already cached (304 revalidate is ~1 KB),
- `smallEcosystemZipBytes` or `largeEcosystemZipBytes` when not.

Against {{gtClass:Gt4SecurityHydratedWindowStrategy}} — whose cost is dominated by `perIdFetchBytes × id count` — I win when the zip is cached. On a cold cache for a large ecosystem (npm ~192 MB) the hydrated path transfers less total, so the selector stays with hydrated for the first run. Subsequent same-ecosystem queries within the zip's cache window flip to me automatically via cost comparison.

## Why this exists

Empirically, for a 90-day npm window with ~4541 ids on a warm zip cache, batched `unzip` takes ~9.5 s + ~1.5 s parse = ~11 s — versus ~20 s for the pooled HTTPS fanout. See the ""Improve Gt4SecurityQuery Perf"" Lepiter page for the full comparison.

## Limits

`unzip` argv holds the full list of target entry names in one invocation. macOS `ARG_MAX` is ~1 MB, so up to ~40,000 ids with typical names fit in one call. Beyond that we would need to chunk — not a problem for any realistic hydrated window today.
"
Class {
	#name : 'Gt4SecurityZipLookupWindowStrategy',
	#superclass : 'Gt4SecurityFeedStrategy',
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'selecting' }
Gt4SecurityZipLookupWindowStrategy >> canExecute: aQuery inContext: aContext [
	"Applicable to windowed hydrated queries (needFullRecords) with at least one ecosystem.
	The unzip tool is required — if it is not available on this platform we fall through to
	other strategies. We do NOT require the zip to be already cached; the cost function is
	what steers the selector toward fanout on a cold cache."
	^ aQuery scope = #window
		and: [ aQuery needFullRecords
		and: [ aQuery ecosystems notNil
		and: [ aQuery ecosystems isNotEmpty
		and: [ Gt4SecurityUnzipTool default isAvailable ] ] ] ]
]

{ #category : 'ranking' }
Gt4SecurityZipLookupWindowStrategy >> costFor: aQuery inContext: aContext [
	"Charge the row-fetch cost (matches CachedCsvWindow / Stream) plus the per-ecosystem zip
	transfer. Cached zips only pay the revalidate handshake; uncached zips pay the full size
	(large or small per the cost model). The per-id fetch cost that dominates HydratedWindow
	is absent here — that's the whole point."
	| days rowsCost zipCost |
	days := aQuery since
		ifNil: [ Gt4SecurityFeedCostModel defaultWindowDays ]
		ifNotNil: [ (DateAndTime now - aQuery since asDateAndTime) asDays asInteger max: 1 ].
	rowsCost := aContext isCsvCacheAvailable
		ifTrue: [ Gt4SecurityFeedCostModel revalidateHandshakeBytes ]
		ifFalse: [ (days * Gt4SecurityFeedCostModel modifiedIdsBytesPerDay)
			min: Gt4SecurityFeedCostModel modifiedIdsFullBytes ].
	zipCost := 0.
	aQuery ecosystems do: [ :eco |
		zipCost := zipCost + ((aContext isEcosystemZipCacheAvailable: eco)
			ifTrue: [ Gt4SecurityFeedCostModel revalidateHandshakeBytes ]
			ifFalse: [ (aContext isLargeEcosystem: eco)
				ifTrue: [ Gt4SecurityFeedCostModel largeEcosystemZipBytes ]
				ifFalse: [ Gt4SecurityFeedCostModel smallEcosystemZipBytes ] ]) ].
	^ rowsCost + zipCost
]

{ #category : 'describing' }
Gt4SecurityZipLookupWindowStrategy >> description [
	^ 'cached all.zip batch-extract for modified-id window'
]

{ #category : 'executing' }
Gt4SecurityZipLookupWindowStrategy >> doExecute: aQuery on: aClient inContext: aContext [
	"Compose: delegate the rows fetch to the selector (typically CachedCsvWindow), group the
	resulting ids by ecosystem, then for each ecosystem ensure the zip is cached and batch
	extract just the matching entries via one unzip subprocess. Parse the extracted JSON into
	vulnerabilities and return a group. Temp directories are always cleaned up in an ensure:."
	| rowsQuery rowsStrategy rows rowsByEco vulns |
	rowsQuery := Gt4SecurityFeedQuery new
		scope: #window;
		since: aQuery since;
		ecosystems: aQuery ecosystems;
		needFullRecords: false;
		yourself.
	rowsStrategy := aContext selector
		ifNotNil: [ :s | s select: rowsQuery inContext: aContext ]
		ifNil: [ Gt4SecurityCachedCsvWindowStrategy default ].
	rows := rowsStrategy execute: rowsQuery on: aClient inContext: aContext.

	"Group ids by ecosystem so we unzip each all.zip at most once."
	rowsByEco := Dictionary new.
	rows do: [ :row |
		| eco list |
		eco := row at: 'ecosystem'.
		list := rowsByEco at: eco ifAbsentPut: [ OrderedCollection new ].
		list add: (row at: 'id') ].

	vulns := OrderedCollection new.
	rowsByEco keysAndValuesDo: [ :eco :ids |
		vulns addAll: (self hydrateEcosystem: eco ids: ids on: aClient) ].

	^ Gt4SecurityVulnerabilityGroup withAll: vulns
]

{ #category : 'executing' }
Gt4SecurityZipLookupWindowStrategy >> hydrateEcosystem: anEcosystemString ids: anIdCollection on: aClient [
	"Download (or revalidate) anEcosystemString's all.zip, batch-extract the listed ids into
	a fresh temp directory, parse each JSON into a Gt4SecurityVulnerability, and clean up.
	Records a single non-HTTP 'unzip' event on the client history so the Calls view surfaces
	the local extraction alongside the network calls.
	Individual parse failures are logged to history (kind: http, bytes: 0) and skipped — the
	batch continues, matching the best-effort semantics of fetchVulnsFromRows:concurrency:."
	| zipPath entryNames extractDir tool startedAt elapsedMs vulns |
	zipPath := aClient downloadEcosystemZip: anEcosystemString.
	entryNames := anIdCollection collect: [ :id | id , '.json' ].
	extractDir := aClient ensureCacheDirectory
		/ ('ziplookup-' , anEcosystemString , '-' , UUID new asString36).
	tool := Gt4SecurityUnzipTool default.
	vulns := OrderedCollection new.
	startedAt := DateAndTime now.
	^ [
		tool extractEntries: entryNames from: zipPath to: extractDir.
		(extractDir filesMatching: '*.json') do: [ :f |
			[ vulns add: (Gt4SecurityVulnerability fromOsvDictionary:
				(NeoJSONReader fromString: f contents)) ]
				on: Error
				do: [ :e | aClient
					recordCall: 'skip ' , anEcosystemString , '/' , f basename
					response: e messageText
					bytes: 0 ] ].
		elapsedMs := (DateAndTime now - startedAt) asMilliSeconds.
		aClient
			recordCall: 'unzip ' , anEcosystemString , '/all.zip (batch ' , entryNames size asString , ')'
			response: vulns size asString , ' vulns extracted in ' , elapsedMs asString , ' ms'
			bytes: 0.
		vulns ]
		ensure: [ extractDir exists ifTrue: [ extractDir ensureDeleteAll ] ]
]

{ #category : 'ranking' }
Gt4SecurityZipLookupWindowStrategy >> tiebreakPriority [
	"Sits between FullEcosystemZip (30) and CachedCsvWindow (40) — cheap on warm cache, slightly
	heavier than a pure zip-all parse because we do two passes (row scan + extract), but still
	preferable to the hydrated fanout when the zip is on disk."
	^ 35
]
