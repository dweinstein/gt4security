"
Client for the OSV.dev bulk feed at https://storage.googleapis.com/osv-vulnerabilities.

Unlike {{gtClass:Gt4SecurityOsvClient}} — which goes through the REST query API and requires a package descriptor per call — this client fetches ecosystem-level data in bulk. That's the canonical path for ""all npm vulns in the last 90 days"" queries: the REST API has no ecosystem-only filter, the bulk feed does.

Primary APIs:
- ecosystemFull: 'npm' — download the per-ecosystem zip, parse into a Gt4SecurityVulnerabilityGroup
- recentSince:ecosystem: — convenience wrapper that filters by publication date
- fetchEcosystem:id: — single-vuln GET, no zip involved

Downloaded zips are cached under cacheDirectory (defaults to a gt4security-osv-feed/ subdir under FileLocator temp). The cache is passive: hitting the same ecosystemFull: again returns the cached file without re-downloading. Use clearCache to force a refresh.

HTTP calls are logged to history for inspector visibility.

"
Class {
	#name : 'Gt4SecurityOsvFeedClient',
	#superclass : 'Object',
	#instVars : [
		'baseUrl',
		'cacheDirectory',
		'history',
		'currentRunId'
	],
	#category : 'Gt4Security-Clients',
	#package : 'Gt4Security',
	#tag : 'Clients'
}

{ #category : 'defaults' }
Gt4SecurityOsvFeedClient class >> defaultBaseUrl [
	^ 'https://storage.googleapis.com/osv-vulnerabilities'
]

{ #category : 'defaults' }
Gt4SecurityOsvFeedClient class >> defaultCacheDirectory [
	"A shared per-user cache for downloaded ecosystem zips."
	^ FileLocator temp asFileReference / 'gt4security-osv-feed'
]

{ #category : 'defaults' }
Gt4SecurityOsvFeedClient class >> defaultConcurrency [
	"Default cap for parallel per-ID fetches. 16 is the calibrated default — validated against OSV's GCS endpoints without triggering rate limiting."
	^ 16
]

{ #category : 'defaults' }
Gt4SecurityOsvFeedClient class >> executionGroupName [
	"Named async execution group for per-ID fetches. Isolates our bounded worker pool from other async work in the image."
	^ 'gt4security-osv-feed-fetch'
]

{ #category : 'ecosystems' }
Gt4SecurityOsvFeedClient class >> mobileEcosystems [
	"OSV ecosystems most relevant to mobile-application development.

	- 'npm' — React Native, Expo, Capacitor, Cordova, Ionic, NativeScript, Quasar, and countless web-view bundled libraries
	- 'Android' — Google's Android Security Bulletin advisories for platform + system packages
	- 'Maven' — Android Java/Kotlin libraries (OkHttp, Retrofit, Glide, Firebase SDKs, log4j, Jackson, ...)
	- 'Pub' — Flutter / Dart packages
	- 'SwiftURL' — iOS / Swift Package Manager libraries
	- 'NuGet' — Xamarin, .NET MAUI, Unity mobile libraries
	- 'RubyGems' — Fastlane and CocoaPods itself (iOS release tooling)

	Deliberately omitted: PyPI (not mobile-first — Kivy/BeeWare are niche; most PyPI vulns are server-side), crates.io (Rust on mobile is rare), Packagist (PHP web backends), Go (mobile backends only).
	"
	^ #('npm' 'Android' 'Maven' 'Pub' 'SwiftURL' 'NuGet' 'RubyGems')
]

{ #category : 'accessing' }
Gt4SecurityOsvFeedClient >> baseUrl [
	^ baseUrl
]

{ #category : 'accessing' }
Gt4SecurityOsvFeedClient >> baseUrl: aString [
	baseUrl := aString
]

{ #category : 'accessing' }
Gt4SecurityOsvFeedClient >> cacheDirectory [
	^ cacheDirectory asFileReference
]

{ #category : 'accessing' }
Gt4SecurityOsvFeedClient >> cacheDirectory: aFileReferenceOrString [
	cacheDirectory := aFileReferenceOrString asFileReference
]

{ #category : 'cache' }
Gt4SecurityOsvFeedClient >> cachePathForEcosystemZip: anEcosystemString [
	"A '/'-bearing name like 'crates.io' is fine as a filename slice, but we normalize to safe filenames."
	| safe |
	safe := (anEcosystemString copyReplaceAll: '/' with: '_') , '-all.zip'.
	^ self ensureCacheDirectory / safe
]

{ #category : 'cache' }
Gt4SecurityOsvFeedClient >> cachePathForEcosystemZipLastModified: anEcosystemString [
	"Sidecar file that stores the server's Last-Modified header for a given ecosystem's all.zip,
	so we can revalidate with If-Modified-Since."
	| zipPath |
	zipPath := self cachePathForEcosystemZip: anEcosystemString.
	^ zipPath parent / (zipPath basename , '.last-modified')
]

{ #category : 'cache' }
Gt4SecurityOsvFeedClient >> cachePathForModifiedIds [
	^ self ensureCacheDirectory / 'modified_id.csv'
]

{ #category : 'cache' }
Gt4SecurityOsvFeedClient >> cachePathForModifiedIdsLastModified [
	"Sidecar file that stores the server's Last-Modified header for modified_id.csv, so we can revalidate with If-Modified-Since."
	^ self ensureCacheDirectory / 'modified_id.csv.last-modified'
]

{ #category : 'cache' }
Gt4SecurityOsvFeedClient >> clearCache [
	"Delete every file under cacheDirectory."
	cacheDirectory exists ifFalse: [ ^ self ].
	cacheDirectory children do: [ :each | each ensureDelete ]
]

{ #category : 'accessing' }
Gt4SecurityOsvFeedClient >> currentRunId [
	"Identifier stamped on every event recorded during an outer run: block. Nil when no outer
	runWithId:do: is active — events recorded outside a run are simply untagged."
	^ currentRunId
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> downloadEcosystemZip: anEcosystemString [
	"Download <ecosystem>/all.zip with If-Modified-Since revalidation. Returns the cached FileReference."
	^ self
		downloadWithRevalidation: (self cachePathForEcosystemZip: anEcosystemString)
		from: (self urlForEcosystemZip: anEcosystemString)
		sidecar: (self cachePathForEcosystemZipLastModified: anEcosystemString)
		timeout: 300
		label: anEcosystemString , ' all.zip'
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> downloadModifiedIds [
	"Download modified_id.csv with If-Modified-Since revalidation. Returns the cached FileReference.
	Use clearCache to force a full refresh."
	^ self
		downloadWithRevalidation: self cachePathForModifiedIds
		from: self urlForModifiedIds
		sidecar: self cachePathForModifiedIdsLastModified
		timeout: 300
		label: 'modified_id.csv'
]

{ #category : 'downloading' }
Gt4SecurityOsvFeedClient >> downloadWithRevalidation: target from: url sidecar: sidecar timeout: timeoutSeconds label: aLabel [
	"Shared conditional-GET download used by modified_id.csv and ecosystem zips.
	When both target and sidecar exist, sends If-Modified-Since and short-circuits on 304.
	On 2xx, stages through a temp path and atomically moves it into place, then refreshes the sidecar.
	ZnClient downloadTo: refuses to overwrite an existing file; 304 responses leave the target untouched.
	On non-2xx non-304 (e.g. 404 for an ecosystem that OSV does not serve), raises with a clear
	status message rather than a misleading FileDoesNotExistException from the missed move.
	Logs via history using aLabel as a human-readable prefix. The request-log line notes the
	If-Modified-Since header on BOTH 304 and 200 responses so the Calls view can distinguish
	cold-download from revalidated-server-had-newer-data. Returns target.
	On exception, the temp path is removed and a failure row is logged before the exception propagates."
	| client cachedLastModified tempPath newLastModified requestLabel |
	cachedLastModified := (target exists and: [ sidecar exists ])
		ifTrue: [ sidecar contents trimBoth ]
		ifFalse: [ nil ].
	tempPath := target parent / (target basename , '.download').
	tempPath ensureDelete.
	requestLabel := cachedLastModified
		ifNil: [ 'GET ' , url ]
		ifNotNil: [ 'GET ' , url , ' (If-Modified-Since: ' , cachedLastModified , ')' ].
	^ [
		| code |
		client := ZnClient new.
		client timeout: timeoutSeconds.
		client url: url.
		client signalProgress: true.
		cachedLastModified ifNotNil: [
			client headerAt: 'If-Modified-Since' put: cachedLastModified ].
		client downloadTo: tempPath.
		code := client response code.
		code = 304
			ifTrue: [
				self
					recordCall: requestLabel
					response: '304 Not Modified; ' , aLabel , ' cache preserved'
					bytes: 0.
				target ]
			ifFalse: [
				client isSuccess ifFalse: [
					tempPath ensureDelete.
					Error signal:
						'OSV feed download failed: HTTP ' , code asString , ' for ' , aLabel ].
				target ensureDelete.
				tempPath moveTo: target.
				newLastModified := client response headers at: 'Last-Modified' ifAbsent: [ nil ].
				newLastModified ifNotNil: [
					sidecar ensureDelete.
					sidecar writeStreamDo: [ :s | s nextPutAll: newLastModified ] ].
				self
					recordCall: requestLabel
					response: 'downloaded ' , target size asString , ' bytes (' , aLabel
							, '; Last-Modified: ' , (newLastModified ifNil: [ '<missing>' ]) , ')'
					bytes: target size.
				target ] ]
		on: Error
		do: [ :e |
			tempPath ensureDelete.
			self
				recordCall: requestLabel
				response: 'failed: ' , aLabel , '; ' , e messageText
				bytes: 0.
			e pass ]
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> ecosystemFull: anEcosystemString [
	"Download (or reuse cached) <ecosystem>/all.zip and return a Gt4SecurityVulnerabilityGroup parsed from it. Blocks the npm dump (192 MB) unless explicitly allowed — use ecosystemFull:acceptLargeDownload: true for npm."
	^ self ecosystemFull: anEcosystemString acceptLargeDownload: false
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> ecosystemFull: anEcosystemString acceptLargeDownload: aBoolean [
	"Download <ecosystem>/all.zip (or use cache) and parse into a Gt4SecurityVulnerabilityGroup. When aBoolean is false, refuse to start large downloads (e.g. npm @ 192 MB) unless the zip is already cached."
	| target vulns |
	target := self cachePathForEcosystemZip: anEcosystemString.
	(target exists not and: [ aBoolean not and: [ self isLargeEcosystem: anEcosystemString ] ])
		ifTrue: [ Error signal: 'Ecosystem ', anEcosystemString, ' dump is large and not cached; pass acceptLargeDownload: true to proceed.' ].
	target := self downloadEcosystemZip: anEcosystemString.
	vulns := self parseEcosystemZip: target.
	^ Gt4SecurityVulnerabilityGroup withAll: vulns
]

{ #category : 'cache' }
Gt4SecurityOsvFeedClient >> ensureCacheDirectory [
	cacheDirectory exists ifFalse: [ cacheDirectory ensureCreateDirectory ].
	^ cacheDirectory
]

{ #category : 'feed operations' }
Gt4SecurityOsvFeedClient >> extractTimestampFromLine: aLine [
	"Pull the timestamp prefix (up to the first comma) from a modified_id.csv line without
	allocating the full row Dictionary. Used for short-circuit decisions before the ecosystem
	filter commits to parsing."
	| commaIndex |
	commaIndex := aLine indexOf: $,.
	commaIndex = 0 ifTrue: [ ^ nil ].
	^ aLine copyFrom: 1 to: commaIndex - 1
]

{ #category : 'feed operations' }
Gt4SecurityOsvFeedClient >> fetchEcosystem: anEcosystemString id: anIdString [
	"GET <ecosystem>/<id>.json with a freshly-opened ZnClient. Closes the client after.
	Used by single-id scope (Gt4SecuritySingleIdStrategy). Bulk fan-out goes through
	fetchVulnsFromRows:concurrency: which pools clients instead."
	| client |
	client := self newFetchClient.
	^ [ self fetchEcosystem: anEcosystemString id: anIdString using: client ]
		ensure: [ [ client close ] on: Error do: [ :e | ] ]
]

{ #category : 'feed operations' }
Gt4SecurityOsvFeedClient >> fetchEcosystem: anEcosystemString id: anIdString using: aZnClient [
	"GET <ecosystem>/<id>.json using a supplied client (so callers can reuse TLS connections
	across multiple fetches). Records the call on history with byte count. Raises on non-2xx."
	| url dict bodySize |
	url := self urlForEcosystem: anEcosystemString id: anIdString.
	aZnClient url: url.
	aZnClient get.
	bodySize := aZnClient contents ifNil: [ 0 ] ifNotNil: [ :c | c size ].
	self
		recordCall: 'GET ' , url
		response: aZnClient response code asString , ' ' , aZnClient response contentType asString
		bytes: bodySize.
	aZnClient isSuccess ifFalse: [
		Error signal: 'OSV feed fetch failed: HTTP ' , aZnClient response code asString , ' at ' , url ].
	dict := NeoJSONReader fromString: aZnClient contents.
	^ Gt4SecurityVulnerability fromOsvDictionary: dict
]

{ #category : 'feed operations' }
Gt4SecurityOsvFeedClient >> fetchVulnsFromRows: aRowCollection concurrency: anInteger [
	"Parallel per-ID fetch via async futures with a bounded in-flight buffer:
	at most anInteger promises are scheduled at a time, advancing as each
	completes. This caps peak memory at O(anInteger) rather than O(N) — see
	pressure-test results for 100..10000 rows where eager scheduling held
	all N promise objects live simultaneously, while this windowed pattern
	holds at most anInteger.

	Pools anInteger ZnClients through a SharedQueue so workers reuse TLS
	connections — ZnClient holds an open socket with 10s keep-alive, so the
	handshake is amortized over the whole batch. Best-effort: individual
	fetch failures are logged to history with full row context and skipped —
	the batch continues. Returns an OrderedCollection of successfully fetched
	Gt4SecurityVulnerability, in input order."

	| cfg pool vulns inFlight rows |
	cfg := AsyncFutureExecutionConfiguration new
		userBackgroundPriority;
		customGroup: self class executionGroupName;
		maxAmountOfWorkers: anInteger;
		yourself.
	pool := SharedQueue new.
	anInteger timesRepeat: [ pool nextPut: self newFetchClient ].
	vulns := OrderedCollection new.
	inFlight := OrderedCollection new.
	rows := aRowCollection readStream.
	[ inFlight size < anInteger and: [ rows atEnd not ] ] whileTrue: [
		inFlight addLast: (self schedulePromiseForRow: rows next pool: pool config: cfg) ].
	[ inFlight isEmpty ] whileFalse: [
		| result |
		result := inFlight removeFirst wait.
		(result value isKindOf: Error)
			ifTrue: [ self recordCall:
					'skip ' , (result key at: 'ecosystem') , '/' , (result key at: 'id')
				response: result value messageText ]
			ifFalse: [ vulns add: result value ].
		rows atEnd ifFalse: [
			inFlight addLast: (self schedulePromiseForRow: rows next pool: pool config: cfg) ] ].
	"Drain + close pool so we don't leak sockets."
	[ pool isEmpty ] whileFalse: [
		[ pool next close ] on: Error do: [ :e | ] ].
	^ vulns
]

{ #category : 'gt - views' }
Gt4SecurityOsvFeedClient >> gtCachedZipsFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Cache';
		priority: 3;
		items: [ cacheDirectory exists
			ifTrue: [ cacheDirectory children sorted: [ :a :b | a basename < b basename ] ]
			ifFalse: [ #() ] ];
		column: 'File' text: [ :f | f basename ] weight: 3;
		column: 'Size'
			text: [ :f | (f size / 1048576.0 printShowingDecimalPlaces: 2) asString , ' MB' ]
			weight: 1
]

{ #category : 'gt - views' }
Gt4SecurityOsvFeedClient >> gtCallsFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Calls';
		priority: 2;
		items: [ history reverse ];
		column: 'At'
			text: [ :call | (call at: 'at') printString ]
			weight: 1;
		column: 'Request'
			text: [ :call | call at: 'request' ]
			weight: 3;
		column: 'Response'
			text: [ :call | call at: 'response' ]
			weight: 2
]

{ #category : 'gt - views' }
Gt4SecurityOsvFeedClient >> gtConfigurationFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Configuration';
		priority: 1;
		items: [ {
			'Base URL' -> baseUrl.
			'Cache dir' -> cacheDirectory fullName.
			'Cache dir exists' -> cacheDirectory exists printString.
			'Cached zips' -> (cacheDirectory exists
				ifTrue: [ (cacheDirectory children select: [ :f | f basename endsWith: '.zip' ]) size printString ]
				ifFalse: [ '0' ]).
			'Calls recorded' -> history size printString } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'accessing' }
Gt4SecurityOsvFeedClient >> history [
	^ history
]

{ #category : 'initialize-release' }
Gt4SecurityOsvFeedClient >> initialize [
	super initialize.
	baseUrl := self class defaultBaseUrl.
	cacheDirectory := self class defaultCacheDirectory.
	history := OrderedCollection new
]

{ #category : 'policy' }
Gt4SecurityOsvFeedClient >> isLargeEcosystem: anEcosystemString [
	"Best-effort list of ecosystems whose all.zip exceeds ~50 MB and warrants explicit opt-in."
	^ #('npm' 'Debian' 'Ubuntu' 'AlmaLinux' 'Rocky Linux' 'Red Hat' 'SUSE')
		includes: anEcosystemString
]

{ #category : 'private' }
Gt4SecurityOsvFeedClient >> isoDateStringFor: aDateOrDateTimeOrTimespanOrString [
	"Normalize to a lexicographically-comparable ISO-8601 date string 'YYYY-MM-DD' which sorts correctly against the 'YYYY-MM-DDTHH:MM:SS.sssZ' timestamps in modified_id.csv."
	| d |
	aDateOrDateTimeOrTimespanOrString isString ifTrue: [ ^ aDateOrDateTimeOrTimespanOrString ].
	d := (aDateOrDateTimeOrTimespanOrString respondsTo: #asDate)
		ifTrue: [ aDateOrDateTimeOrTimespanOrString asDate ]
		ifFalse: [ aDateOrDateTimeOrTimespanOrString start asDate ].
	^ String streamContents: [ :s |
		s print: d year; nextPut: $-.
		d monthIndex < 10 ifTrue: [ s nextPut: $0 ].
		s print: d monthIndex; nextPut: $-.
		d dayOfMonth < 10 ifTrue: [ s nextPut: $0 ].
		s print: d dayOfMonth ]
]

{ #category : 'parsing' }
Gt4SecurityOsvFeedClient >> modifiedIdsMatching: aBlock [
	"Stream through the cached modified_id.csv and yield parsed rows (dicts) where aBlock returns true. Caller gets an OrderedCollection of matching rows so filtering is O(N) but we don't hold all rows in memory."
	| target matches |
	target := self downloadModifiedIds.
	matches := OrderedCollection new.
	target readStreamDo: [ :s |
		[ s atEnd ] whileFalse: [
			| row |
			row := self parseModifiedIdsLine: (s nextLine ifNil: [ '' ]).
			(row notNil and: [ aBlock value: row ])
				ifTrue: [ matches add: row ] ] ].
	^ matches
]

{ #category : 'feed operations' }
Gt4SecurityOsvFeedClient >> modifiedIdsSince: aCutoffTimestamp ecosystems: anEcosystemSet [
	"Scan the cached modified_id.csv and return parsed rows newer than aCutoffTimestamp whose
	ecosystem is in anEcosystemSet (nil = any). Two optimizations over the previous
	modifiedIdsMatching: block-only API:
	1. Short-circuits the scan when a row's timestamp is older than aCutoffTimestamp. The feed
	   is strictly descending by timestamp (verified across all 836,880 rows), so once we pass
	   the cutoff every remaining row will also be rejected. ISO-8601 Z-suffixed timestamps
	   sort lexicographically by chronology, so string compare is sufficient.
	2. Rejects non-matching ecosystems via a raw-line ',<eco>/' prefix check BEFORE building
	   the row Dictionary. For a single-ecosystem filter this skips ~70% of dict allocations,
	   directly reducing the GC pressure that the profile flagged as ~32% of wall time."
	| target matches prefixes |
	target := self downloadModifiedIds.
	matches := OrderedCollection new.
	prefixes := anEcosystemSet
		ifNotNil: [ anEcosystemSet collect: [ :e | ',' , e , '/' ] ].
	target readStreamDo: [ :s |
		[ s atEnd ] whileFalse: [
			| line ecoMatched row timestamp |
			line := s nextLine ifNil: [ '' ].
			line isEmpty ifFalse: [
				ecoMatched := prefixes isNil
					or: [ prefixes anySatisfy: [ :p | line includesSubstring: p ] ].
				"Check timestamp regardless of ecoMatched — a rejected line still tells us
				whether we're past the cutoff, so we can short-circuit even through non-npm rows."
				timestamp := self extractTimestampFromLine: line.
				timestamp ifNil: [ "malformed row — skip, don't short-circuit" ]
				ifNotNil: [
					timestamp < aCutoffTimestamp ifTrue: [ ^ matches ].
					ecoMatched ifTrue: [
						row := self parseModifiedIdsLine: line.
						row ifNotNil: [ matches add: row ] ] ] ] ] ].
	^ matches
]

{ #category : 'feed operations' }
Gt4SecurityOsvFeedClient >> newFetchClient [
	"A ZnClient configured for OSV fetch-by-id calls. Kept as a helper so the pool in
	fetchVulnsFromRows:concurrency: and the one-shot fetchEcosystem:id: stay consistent.
	ZnClient's default connectionReuseTimeout of 10 s is plenty — HTTPS handshakes to the
	OSV CDN complete well under that window between batch iterations."
	^ ZnClient new
		timeout: 60;
		yourself
]

{ #category : 'parsing' }
Gt4SecurityOsvFeedClient >> parseEcosystemZip: aFileReference [
	"Read every JSON entry in aFileReference and parse each into a Gt4SecurityVulnerability.
	Strategy: try Pharo's in-memory ZipArchive first (fast, no subprocess, works for non-ZIP64 archives). On failure — typically `setPosition:to:` primitive failure on ZIP64 archives like npm's all.zip — fall back to Gt4SecurityUnzipTool (native unzip via subprocess, handles ZIP64)."
	^ [ self parseEcosystemZipViaZipArchive: aFileReference ]
		on: Error
		do: [ :e |
			self recordCall: 'ZipArchive failed on ' , aFileReference basename
				response: 'fallback to unzip tool: ' , e messageText.
			self parseEcosystemZipViaUnzipTool: aFileReference ]
]

{ #category : 'parsing' }
Gt4SecurityOsvFeedClient >> parseEcosystemZipViaUnzipTool: aFileReference [
	"ZIP64 fallback via native unzip. Extracts to a UUID-named tmpdir under the feed cache directory, iterates every *.json child, parses each, then deletes the tmpdir (even if parsing raises). Raises if Gt4SecurityUnzipTool is not available on this platform."
	| tool tmpDir vulns |
	tool := Gt4SecurityUnzipTool default.
	tool ifNil: [ Error signal:
		'Cannot parse ' , aFileReference basename , ': Pharo ZipArchive failed (likely ZIP64) and Gt4SecurityUnzipTool is not available on this platform.' ].
	tmpDir := self ensureCacheDirectory / ('extract-' , UUID new asString36).
	^ [
		tool extractAllTo: tmpDir from: aFileReference.
		vulns := OrderedCollection new.
		(tmpDir filesMatching: '*.json') do: [ :jsonFile |
			[ vulns add: (Gt4SecurityVulnerability fromOsvDictionary:
				(NeoJSONReader fromString: jsonFile contents)) ]
				on: Error
				do: [ :e | self recordCall: 'skip ' , jsonFile basename response: e messageText ] ].
		self recordCall: 'parsed ' , aFileReference basename , ' via unzip tool'
			response: vulns size asString , ' vulnerabilities'.
		vulns ]
		ensure: [ tmpDir exists ifTrue: [ tmpDir ensureDeleteAll ] ]
]

{ #category : 'parsing' }
Gt4SecurityOsvFeedClient >> parseEcosystemZipViaZipArchive: aFileReference [
	"Original path. Fast but fails on ZIP64 archives (npm/Debian/Ubuntu/RHEL/Alma/Rocky/SUSE)."
	| vulns |
	vulns := OrderedCollection new.
	aFileReference binaryReadStreamDo: [ :stream |
		| zip |
		zip := ZipArchive new readFrom: stream.
		zip members do: [ :member |
			(member fileName endsWith: '.json') ifTrue: [
				[ vulns add: (Gt4SecurityVulnerability fromOsvDictionary:
					(NeoJSONReader fromString: member contents asString)) ]
					on: Error
					do: [ :e | self recordCall: 'skip ' , member fileName response: e messageText ] ] ] ].
	^ vulns
]

{ #category : 'parsing' }
Gt4SecurityOsvFeedClient >> parseModifiedIdsLine: aLine [
	"Parse one row of modified_id.csv — 'ISO timestamp,ecosystem/id'. Returns a Dictionary or nil for malformed rows."
	| commaIndex slashIndex timestamp ecoAndId ecosystem id |
	aLine isEmpty ifTrue: [ ^ nil ].
	commaIndex := aLine indexOf: $,.
	commaIndex = 0 ifTrue: [ ^ nil ].
	timestamp := aLine copyFrom: 1 to: commaIndex - 1.
	ecoAndId := aLine copyFrom: commaIndex + 1 to: aLine size.
	slashIndex := ecoAndId indexOf: $/.
	slashIndex = 0 ifTrue: [ ^ nil ].
	ecosystem := ecoAndId copyFrom: 1 to: slashIndex - 1.
	id := ecoAndId copyFrom: slashIndex + 1 to: ecoAndId size.
	^ Dictionary new
		at: 'timestamp' put: timestamp;
		at: 'ecosystem' put: ecosystem;
		at: 'id' put: id;
		yourself
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> recentMobileSince: aDate [
	^ self recentMobileSince: aDate concurrency: 16
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> recentMobileSince: aDate concurrency: anInteger [
	"Hydrated window across the mobile-relevant ecosystems."
	^ self run: ((Gt4SecurityFeedQuery mobileWindowSince: aDate)
		concurrency: anInteger;
		yourself)
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> recentModifiedSince: aDate ecosystem: anEcosystemString [
	^ self recentModifiedSince: aDate ecosystem: anEcosystemString concurrency: 16
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> recentModifiedSince: aDate ecosystem: anEcosystemString concurrency: anInteger [
	"Windowed hydrated query for one ecosystem. Works on any ecosystem (including ZIP64 feeds
	like npm/Debian that ecosystemFull: cant parse) because it goes through modified_id.csv + per-id fetch."
	^ self run: ((Gt4SecurityFeedQuery hydratedWindowSince: aDate inEcosystem: anEcosystemString)
		concurrency: anInteger;
		yourself)
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> recentRowsSince: aDate ecosystem: anEcosystemString [
	"Rows (timestamp + ecosystem + id) from modified_id.csv. Selector picks between cached+scan
	and streaming with early termination based on cache freshness and window size."
	^ self run: (Gt4SecurityFeedQuery windowSince: aDate inEcosystem: anEcosystemString)
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> recentSince: aDate ecosystem: anEcosystemString [
	^ self recentSince: aDate ecosystem: anEcosystemString acceptLargeDownload: false
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> recentSince: aDate ecosystem: anEcosystemString acceptLargeDownload: aBoolean [
	"Full ecosystem dump filtered in-memory by publication date."
	| group |
	group := self run: ((Gt4SecurityFeedQuery fullEcosystem: anEcosystemString)
		acceptLargeDownload: aBoolean;
		yourself).
	^ group publishedSince: (self isoDateStringFor: aDate)
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> recentSince: aDate ecosystems: anEcosystemArray [
	^ self recentSince: aDate ecosystems: anEcosystemArray acceptLargeDownload: false
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> recentSince: aDate ecosystems: anEcosystemArray acceptLargeDownload: aBoolean [
	"Full ecosystem dumps across multiple ecosystems, merged, then publication-date filtered."
	| group |
	group := self run: (Gt4SecurityFeedQuery new
		scope: #ecosystem;
		ecosystems: anEcosystemArray asArray;
		needFullRecords: true;
		acceptLargeDownload: aBoolean;
		yourself).
	^ group publishedSince: (self isoDateStringFor: aDate)
]

{ #category : 'recording' }
Gt4SecurityOsvFeedClient >> recordCall: aRequestString response: aResponseSummary [
	"Log an HTTP call to history with no byte count (non-network event, failure, or 304).
	Delegates to recordCall:response:bytes: so every http entry carries a bytes field."
	^ self recordCall: aRequestString response: aResponseSummary bytes: 0
]

{ #category : 'recording' }
Gt4SecurityOsvFeedClient >> recordCall: aRequestString response: aResponseSummary bytes: anInteger [
	"Log an HTTP-ish call to history. Tagged kind: #http so views can filter.
	Bytes is the number of bytes transferred (0 for 304 responses, failures, or
	events like 'skip' / 'parsed from local file' that do not involve network IO).
	RunId is the currentRunId (nil when recorded outside a runWithId:do: block)."
	history add: (Dictionary new
		at: 'kind' put: #http;
		at: 'at' put: DateAndTime now;
		at: 'request' put: aRequestString;
		at: 'response' put: aResponseSummary;
		at: 'bytes' put: anInteger;
		at: 'runId' put: currentRunId;
		yourself)
]

{ #category : 'recording' }
Gt4SecurityOsvFeedClient >> recordStrategyEnd: aStrategy startedAt: aStartDateAndTime [
	"Log that a strategy finished. Paired with recordStrategyStart: for span attribution."
	history add: (Dictionary new
		at: 'kind' put: #strategyEnd;
		at: 'at' put: DateAndTime now;
		at: 'strategy' put: aStrategy class name;
		at: 'description' put: aStrategy description;
		at: 'startedAt' put: aStartDateAndTime;
		at: 'runId' put: currentRunId;
		yourself)
]

{ #category : 'history' }
Gt4SecurityOsvFeedClient >> recordStrategyStart: aStrategy forQuery: aQuery cost: anInteger [
	"Log that a strategy was just selected and is about to run. Tagged kind: #strategyStart.
	Returns a DateAndTime start marker the caller should pass to recordStrategyEnd:..."
	| at |
	at := DateAndTime now.
	history add: (Dictionary new
		at: 'kind' put: #strategyStart;
		at: 'at' put: at;
		at: 'strategy' put: aStrategy;
		at: 'description' put: aStrategy description;
		at: 'query' put: aQuery;
		at: 'ecosystems' put: (aQuery ecosystems ifNil: [ #() ] ifNotNil: [ :e | e asArray ]);
		at: 'cost' put: anInteger;
		at: 'runId' put: currentRunId;
		yourself).
	^ at
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> run: aQuery [
	"Run a Gt4SecurityFeedQuery via strategy selection. Delegates to the default selector
	which picks the cheapest applicable strategy given the current cache state.
	Returns whatever the chosen strategy returns (shape depends on query scope:
	#singleId -> Gt4SecurityVulnerability; #ecosystem or hydrated #window -> Gt4SecurityVulnerabilityGroup;
	rows-only #window -> OrderedCollection of row dictionaries)."
	^ self run: aQuery with: Gt4SecurityFeedStrategySelector new
]

{ #category : 'fetching' }
Gt4SecurityOsvFeedClient >> run: aQuery with: aSelector [
	"Same as run: but with an explicit selector — use for injecting custom or reduced strategy sets
	(e.g. a selector with only StreamWindow registered, to force the stream path)."
	| ctx |
	ctx := Gt4SecurityFeedContext for: self.
	^ aSelector evaluate: aQuery on: self inContext: ctx
]

{ #category : 'recording' }
Gt4SecurityOsvFeedClient >> runWithId: aRunId do: aBlock [
	"Push aRunId as the currentRunId for the duration of aBlock so every event recorded
	(http, strategyStart, strategyEnd) carries it. Nested callers overwrite for their window —
	the outer caller restores on return. Nil aRunId disables tagging within the block."
	| saved |
	saved := currentRunId.
	currentRunId := aRunId.
	^ [ aBlock value ] ensure: [ currentRunId := saved ]
]

{ #category : 'feed operations' }
Gt4SecurityOsvFeedClient >> schedulePromiseForRow: aRow pool: aPool config: aCfg [
	"Schedule a single per-row fetch onto the GT async pool. Always resolves to
	aRow -> vuln OR aRow -> error so the consuming wait loop has a predictable
	shape and preserves row context on error paths. The block captures aRow as
	an argument — never read from a shared cursor inside the async block."

	^ [ | client |
	client := aPool next.
	[ [ aRow -> (self fetchEcosystem: (aRow at: 'ecosystem') id: (aRow at: 'id') using: client) ]
		on: Error
		do: [ :e | aRow -> e ] ]
		ensure: [ aPool nextPut: client ] ]
		asAsyncFuture await: aCfg
]

{ #category : 'feed operations' }
Gt4SecurityOsvFeedClient >> streamModifiedIdsSince: aDateOrDateTime do: aBlock [
	"Stream rows of modified_id.csv whose timestamp >= aDateOrDateTime and invoke aBlock with each parsed row.
	The feed is sorted newest-first, so we close the connection as soon as an older row appears —
	bandwidth is proportional to the time window rather than the whole 41MB file.
	Does NOT read or write the disk cache; use modifiedIdsMatching: for cache-backed queries."
	| client cutoff url charStream bytes rows stopped start |
	cutoff := self isoDateStringFor: aDateOrDateTime.
	url := self urlForModifiedIds.
	start := DateAndTime now.
	bytes := 0.
	rows := 0.
	stopped := false.
	client := ZnClient new.
	client timeout: 300.
	client url: url.
	client streaming: true.
	client get.
	client isSuccess ifFalse: [
		| status |
		status := client response statusLine printString.
		client close.
		self
			recordCall: 'GET (stream) ' , url , ' since ' , cutoff
			response: 'failed: ' , status
			bytes: 0.
		^ self ].
	[
		charStream := ZnCharacterReadStream
			on: client response entity readStream
			encoding: 'utf-8'.
		[ stopped or: [ charStream atEnd ] ] whileFalse: [
			| line row |
			line := charStream nextLine.
			line isNil
				ifTrue: [ stopped := true ]
				ifFalse: [
					line isEmpty ifFalse: [
						bytes := bytes + line size + 1.
						row := self parseModifiedIdsLine: line.
						(row notNil and: [ (row at: 'timestamp') >= cutoff ])
							ifTrue: [
								rows := rows + 1.
								aBlock value: row ]
							ifFalse: [ stopped := true ] ] ] ]
	] ensure: [ client close ].
	self
		recordCall: 'GET (stream) ' , url , ' since ' , cutoff
		response: rows asString , ' rows, ' , bytes asString , ' bytes in '
				, (DateAndTime now - start) asMilliSeconds asString , ' ms'
		bytes: bytes
]

{ #category : 'urls' }
Gt4SecurityOsvFeedClient >> urlForEcosystem: anEcosystemString id: anIdString [
	"E.g. https://storage.googleapis.com/osv-vulnerabilities/npm/GHSA-xxxx.json"
	^ baseUrl , '/' , anEcosystemString , '/' , anIdString , '.json'
]

{ #category : 'urls' }
Gt4SecurityOsvFeedClient >> urlForEcosystemZip: anEcosystemString [
	"E.g. https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip"
	^ baseUrl , '/' , anEcosystemString , '/all.zip'
]

{ #category : 'urls' }
Gt4SecurityOsvFeedClient >> urlForModifiedIds [
	^ baseUrl , '/modified_id.csv'
]
