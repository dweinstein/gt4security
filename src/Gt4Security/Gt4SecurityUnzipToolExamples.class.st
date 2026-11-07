Class {
	#name : 'Gt4SecurityUnzipToolExamples',
	#superclass : 'Object',
	#category : 'Gt4Security-Examples',
	#package : 'Gt4Security',
	#tag : 'Examples'
}

{ #category : 'examples - live' }
Gt4SecurityUnzipToolExamples >> batchConcurrencyCaps [
	"Live: contentsOfEntries:in:concurrency: actually caps. Read 20 real entries at cap=4; elapsed should be ~5x the single-call cost, not 1x (fully-parallel) nor 20x (serial)."
	<gtExample>
	<noTest>
	<return: #Duration>
	| tool zipFile entries elapsed results |
	tool := Gt4SecurityUnzipTool default.
	tool ifNil: [ ^ 0 seconds ].
	zipFile := Gt4SecurityOsvFeedClient new cachePathForEcosystemZip: 'npm'.
	zipFile exists ifFalse: [ ^ 0 seconds ].
	entries := ((tool listEntries: zipFile) first: 20)
		collect: [ :row | row at: 'name' ].
	elapsed := [ results := tool
		contentsOfEntries: entries
		in: zipFile
		concurrency: 4 ] timeToRun.
	self assert: results size equals: 20.
	self assert: (results allSatisfy: [ :each | each isKindOf: Association ]).
	^ elapsed
]

{ #category : 'examples - live' }
Gt4SecurityUnzipToolExamples >> contentsOfEntryRoundTripOnCachedNpmZip [
	"Live: extract a known GHSA entry from the cached npm zip and round-trip through the domain parser."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerability>
	| tool zipFile bytes vuln |
	tool := Gt4SecurityUnzipTool default.
	tool ifNil: [ ^ nil ].
	zipFile := Gt4SecurityOsvFeedClient new cachePathForEcosystemZip: 'npm'.
	zipFile exists ifFalse: [ ^ nil ].
	bytes := tool contentsOfEntry: 'GHSA-xvch-5gv4-984h.json' in: zipFile.
	vuln := Gt4SecurityVulnerability fromOsvDictionary: (NeoJSONReader fromString: bytes).
	self assert: vuln id equals: 'GHSA-xvch-5gv4-984h'.
	self assert: vuln primaryEcosystem equals: 'npm'.
	self assert: (vuln affected items first packageName) equals: 'minimist'.
	^ vuln
]

{ #category : 'examples - availability' }
Gt4SecurityUnzipToolExamples >> isAvailableOnThisPlatform [
	"Offline: the tool reports availability based on the default path. Safe to run on CI — just asserts that either unzip is present OR isAvailable correctly returns false."
	<gtExample>
	<return: #Boolean>
	| tool |
	tool := Gt4SecurityUnzipTool new.
	tool isAvailable
		ifTrue: [ self assert: tool version notNil.
			self assert: tool version isString ]
		ifFalse: [ self assert: tool version isNil ].
	^ tool isAvailable
]

{ #category : 'examples - live' }
Gt4SecurityUnzipToolExamples >> listEntriesOnCachedNpmZip [
	"Live: if the npm all.zip is already cached (from a previous Gt4SecurityOsvFeedClient download), list its entries and confirm we got >65535 rows (proving we're reading a ZIP64 archive)."
	<gtExample>
	<noTest>
	<return: #OrderedCollection>
	| tool zipFile rows |
	tool := Gt4SecurityUnzipTool default.
	tool ifNil: [ ^ #() ].
	zipFile := Gt4SecurityOsvFeedClient new cachePathForEcosystemZip: 'npm'.
	zipFile exists ifFalse: [
		^ #() "skip — zip not cached; run feedClient downloadEcosystemZip: 'npm' first" ].
	rows := tool listEntries: zipFile.
	self assert: rows size > 65535.
	self assert: ((rows first at: 'name') endsWith: '.json').
	^ rows
]

{ #category : 'examples - live' }
Gt4SecurityUnzipToolExamples >> missingEntryRaisesGtSubprocessError [
	"Live: asking for a non-existent entry signals a GtSubprocessError with the unzip stderr attached."
	<gtExample>
	<noTest>
	<return: #GtSubprocessError>
	| tool zipFile caught |
	tool := Gt4SecurityUnzipTool default.
	tool ifNil: [ ^ nil ].
	zipFile := Gt4SecurityOsvFeedClient new cachePathForEcosystemZip: 'npm'.
	zipFile exists ifFalse: [ ^ nil ].
	caught := nil.
	[ tool contentsOfEntry: 'GHSA-does-not-exist-aaaa.json' in: zipFile ]
		on: GtSubprocessError
		do: [ :e | caught := e ].
	self assert: caught notNil description: 'expected GtSubprocessError'.
	self assert: (caught messageText includesSubstring: 'filename not matched').
	^ caught
]

{ #category : 'examples - listing' }
Gt4SecurityUnzipToolExamples >> parseListingOutputRoundTrip [
	"Offline: parseListingOutput: against a canned unzip -l -qq sample parses size/date/time/name correctly."
	<gtExample>
	<return: #OrderedCollection>
	| tool sample rows |
	tool := Gt4SecurityUnzipTool new.
	sample := '     2629  03-23-2026 13:41   GHSA-2234-fmw7-43wr.json
     1753  03-23-2026 01:02   MAL-2026-994.json
      120  01-01-2020 00:00   some name with spaces.json'.
	rows := tool parseListingOutput: sample.
	self assert: rows size equals: 3.
	self assert: (rows first at: 'size') equals: 2629.
	self assert: (rows first at: 'name') equals: 'GHSA-2234-fmw7-43wr.json'.
	self assert: (rows second at: 'name') equals: 'MAL-2026-994.json'.
	self assert: (rows third at: 'name') equals: 'some name with spaces.json'.
	^ rows
]

{ #category : 'examples - availability' }
Gt4SecurityUnzipToolExamples >> unavailableWhenPathIsBogus [
	"Offline: construct a tool whose unzipPath doesn't exist; isAvailable returns false without raising."
	<gtExample>
	<return: #Gt4SecurityUnzipTool>
	| tool |
	tool := Gt4SecurityUnzipTool new.
	tool unzipPath: '/definitely/not/here/unzip'.
	self assert: tool isAvailable not.
	self assert: tool version isNil.
	^ tool
]

{ #category : 'examples - safety' }
Gt4SecurityUnzipToolExamples >> validateEntryNameRejectsTraversal [
	"Offline: validateEntryName: rejects traversal attempts + control chars before any subprocess launches."
	<gtExample>
	<return: #Gt4SecurityUnzipTool>
	| tool bad raised |
	tool := Gt4SecurityUnzipTool new.
	bad := #('../foo.json' '../../etc/passwd' '' '/absolute/path.json' 'foo\bar.json' 'has space.json').
	bad do: [ :name |
		raised := false.
		[ tool validateEntryName: name ]
			on: Error do: [ :e | raised := true ].
		self assert: raised description: 'expected rejection for: ' , name printString ].
	"Good names pass (no exception)"
	tool validateEntryName: 'GHSA-xvch-5gv4-984h.json'.
	tool validateEntryName: 'MAL-2026-999.json'.
	tool validateEntryName: 'npm/GHSA-xxxx-yyyy-zzzz.json'.
	^ tool
]
