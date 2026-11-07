"
A caller-facing intent record describing an OSV feed query.

Holds the scope (#singleId | #window | #ecosystem), ecosystems, since cutoff, id, hydration preference (needFullRecords), and optional limits (maxBytes, concurrency, acceptLargeDownload). Serves as input to {{gtClass:Gt4SecurityFeedStrategySelector}}, which picks a concrete fetch strategy based on the query shape plus the current {{gtClass:Gt4SecurityFeedContext}} (cache state, ecosystem size hints).

Fluent class-side constructors cover the common shapes:
- singleId:inEcosystem:
- fullEcosystem:
- windowSince:inEcosystem: / windowSince:inEcosystems: / windowSince: (rows-only)
- hydratedWindowSince:inEcosystem: / hydratedWindowSince:inEcosystems: (full records)
- mobileWindowSince: (hydrated window across the mobile ecosystems set)

#validate raises on incoherent queries before a strategy picks one up.
"
Class {
	#name : 'Gt4SecurityFeedQuery',
	#superclass : 'Object',
	#instVars : [
		'scope',
		'ecosystems',
		'since',
		'id',
		'needFullRecords',
		'maxBytes',
		'concurrency',
		'acceptLargeDownload'
	],
	#category : 'Gt4Security-Query',
	#package : 'Gt4Security',
	#tag : 'Query'
}

{ #category : 'examples' }
Gt4SecurityFeedQuery class >> exampleFullEcosystemQuery [
	<gtExample>
	| q |
	q := self fullEcosystem: 'Pub'.
	self assert: q scope = #ecosystem.
	self assert: q ecosystems first = 'Pub'.
	self assert: q needFullRecords.
	q validate.
	^ q
]

{ #category : 'examples' }
Gt4SecurityFeedQuery class >> exampleInvalidQueryRaises [
	<gtExample>
	| raised |
	raised := false.
	[ self new validate ] on: Error do: [ :e | raised := true ].
	self assert: raised.
	^ raised
]

{ #category : 'examples' }
Gt4SecurityFeedQuery class >> exampleMobileWindowQuery [
	<gtExample>
	| q |
	q := self mobileWindowSince: Date today - 3 days.
	self assert: q scope = #window.
	self assert: q ecosystems asArray = Gt4SecurityOsvFeedClient mobileEcosystems.
	self assert: q needFullRecords.
	q validate.
	^ q
]

{ #category : 'examples' }
Gt4SecurityFeedQuery class >> exampleSingleIdQuery [
	<gtExample>
	| q |
	q := self singleId: 'GHSA-7xr2-q9vf-x4r5' inEcosystem: 'npm'.
	self assert: q scope = #singleId.
	self assert: q id = 'GHSA-7xr2-q9vf-x4r5'.
	self assert: q ecosystems first = 'npm'.
	self assert: q needFullRecords.
	q validate.
	^ q
]

{ #category : 'examples' }
Gt4SecurityFeedQuery class >> exampleWindowRowsQuery [
	<gtExample>
	| q |
	q := self windowSince: Date today - 7 days inEcosystem: 'npm'.
	self assert: q scope = #window.
	self assert: q needFullRecords not.
	q validate.
	^ q
]

{ #category : 'instance creation' }
Gt4SecurityFeedQuery class >> fullEcosystem: anEcosystemString [
	"Build a query that fetches the entire all.zip dump for one ecosystem. Needs
	acceptLargeDownload: true for large ecosystems (npm, Debian, etc.)."
	^ self new
		scope: #ecosystem;
		ecosystems: (Array with: anEcosystemString);
		needFullRecords: true;
		yourself
]

{ #category : 'instance creation' }
Gt4SecurityFeedQuery class >> hydratedWindowSince: aDateOrDateTime inEcosystem: anEcosystemString [
	"Build a windowed query that returns fully-hydrated Gt4SecurityVulnerability records
	(via per-ID fetch) for a single ecosystem."
	^ self new
		scope: #window;
		since: aDateOrDateTime;
		ecosystems: (Array with: anEcosystemString);
		needFullRecords: true;
		yourself
]

{ #category : 'instance creation' }
Gt4SecurityFeedQuery class >> hydratedWindowSince: aDateOrDateTime inEcosystems: aCollection [
	"Build a windowed query that returns fully-hydrated vulnerabilities across multiple ecosystems."
	^ self new
		scope: #window;
		since: aDateOrDateTime;
		ecosystems: aCollection asArray;
		needFullRecords: true;
		yourself
]

{ #category : 'instance creation' }
Gt4SecurityFeedQuery class >> mobileWindowSince: aDateOrDateTime [
	"Shorthand for a hydrated window across the mobile-relevant ecosystems."
	^ self
		hydratedWindowSince: aDateOrDateTime
		inEcosystems: Gt4SecurityOsvFeedClient mobileEcosystems
]

{ #category : 'instance creation' }
Gt4SecurityFeedQuery class >> singleId: anIdString inEcosystem: anEcosystemString [
	"Build a query that fetches a single vulnerability JSON document."
	^ self new
		scope: #singleId;
		id: anIdString;
		ecosystems: (Array with: anEcosystemString);
		needFullRecords: true;
		yourself
]

{ #category : 'instance creation' }
Gt4SecurityFeedQuery class >> windowSince: aDateOrDateTime [
	"Build a rows-only query windowed across ALL ecosystems (no ecosystem filter)."
	^ self new
		scope: #window;
		since: aDateOrDateTime;
		needFullRecords: false;
		yourself
]

{ #category : 'instance creation' }
Gt4SecurityFeedQuery class >> windowSince: aDateOrDateTime inEcosystem: anEcosystemString [
	"Build a rows-only (IDs + timestamps) query windowed to >= aDateOrDateTime
	for one ecosystem."
	^ self new
		scope: #window;
		since: aDateOrDateTime;
		ecosystems: (Array with: anEcosystemString);
		needFullRecords: false;
		yourself
]

{ #category : 'instance creation' }
Gt4SecurityFeedQuery class >> windowSince: aDateOrDateTime inEcosystems: aCollection [
	"Build a rows-only query windowed to >= aDateOrDateTime across multiple ecosystems."
	^ self new
		scope: #window;
		since: aDateOrDateTime;
		ecosystems: aCollection asArray;
		needFullRecords: false;
		yourself
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> acceptLargeDownload [
	^ acceptLargeDownload
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> acceptLargeDownload: aBoolean [
	acceptLargeDownload := aBoolean
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> concurrency [
	^ concurrency
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> concurrency: anInteger [
	concurrency := anInteger
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> ecosystems [
	^ ecosystems
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> ecosystems: aCollection [
	ecosystems := aCollection
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> ecosystemsDisplay [
	"Comma-joined ecosystem names; '—' for nil/empty."
	(ecosystems isNil or: [ ecosystems isEmpty ])
		ifTrue: [ ^ '—' ].
	^ ', ' join: (ecosystems collect: [ :each | each asString ])
]

{ #category : 'printing' }
Gt4SecurityFeedQuery >> gtDisplayOn: aStream [
	"Concise inspector title — 'window · npm · since 29 Jan 2026 · full' style. Avoids the
	doubled-printString look the default gives."
	aStream nextPutAll: self scopeDisplay.
	(ecosystems notNil and: [ ecosystems notEmpty ]) ifTrue: [
		aStream nextPutAll: ' · '; nextPutAll: self ecosystemsDisplay ].
	since ifNotNil: [ aStream nextPutAll: ' · '; nextPutAll: self sinceDisplay ].
	id ifNotNil: [ aStream nextPutAll: ' · id='; nextPutAll: id asString ].
	needFullRecords ifTrue: [ aStream nextPutAll: ' · full' ]
]

{ #category : 'gt-views' }
Gt4SecurityFeedQuery >> gtSummaryFor: aView [
	"Field-level summary; rows are 3-tuples { label. clickValue. displayText. } so the
	Value cell shows human text while send: still spawns the underlying domain object."
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 1;
		items: [ self summaryRows ];
		column: 'Field' text: [ :row | row first ] weight: 0.4;
		column: 'Value' text: [ :row | row third ] weight: 0.6;
		send: [ :row | row second ]
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> id [
	^ id
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> id: aString [
	id := aString
]

{ #category : 'initialize-release' }
Gt4SecurityFeedQuery >> initialize [
	super initialize.
	needFullRecords := false.
	concurrency := 16.
	acceptLargeDownload := false
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> maxBytes [
	^ maxBytes
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> maxBytes: anInteger [
	maxBytes := anInteger
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> maxBytesDisplay [
	^ Gt4SecurityFormat humanBytes: maxBytes
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> needFullRecords [
	^ needFullRecords
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> needFullRecords: aBoolean [
	needFullRecords := aBoolean
]

{ #category : 'printing' }
Gt4SecurityFeedQuery >> printOn: aStream [
	aStream nextPutAll: 'FeedQuery('.
	scope
		ifNil: [ aStream nextPutAll: '?' ]
		ifNotNil: [ aStream nextPutAll: scope asString ].
	(scope = #window or: [ scope = #mobileWindow ]) ifTrue: [
		aStream nextPutAll: ' since='.
		since ifNotNil: [ aStream print: since asDate ] ].
	ecosystems ifNotNil: [
		aStream nextPutAll: ' eco='.
		aStream print: ecosystems ].
	id ifNotNil: [
		aStream nextPutAll: ' id='; nextPutAll: id ].
	needFullRecords ifTrue: [ aStream nextPutAll: ' full' ].
	aStream nextPutAll: ')'
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> scope [
	^ scope
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> scope: aSymbol [
	scope := aSymbol
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> scopeDisplay [
	^ scope ifNil: [ '—' ] ifNotNil: [ scope asString ]
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> since [
	^ since
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> since: aDateOrDateTime [
	since := aDateOrDateTime
]

{ #category : 'accessing' }
Gt4SecurityFeedQuery >> sinceDisplay [
	"Delegates to Gt4SecurityFormat so 'since' renders consistently with QueryResult's
	Published-since cell."
	^ Gt4SecurityFormat humanTimespan: since
]

{ #category : 'printing' }
Gt4SecurityFeedQuery >> summaryRows [
	"Field/clickValue/displayText 3-tuples for the gtSummary view. clickValue stays as the
	raw domain object so the columned-list send: spawns a useful inspector on click; the
	displayText is the human-friendly form rendered in the Value cell."
	^ {
		{ 'scope'. scope. self scopeDisplay }.
		{ 'ecosystems'. ecosystems. self ecosystemsDisplay }.
		{ 'since'. since. self sinceDisplay }.
		{ 'id'. id. id ifNil: [ '—' ] ifNotNil: [ id asString ] }.
		{ 'needFullRecords'. needFullRecords. needFullRecords ifTrue: [ 'yes' ] ifFalse: [ 'no' ] }.
		{ 'concurrency'. concurrency. concurrency ifNil: [ '—' ] ifNotNil: [ concurrency asString ] }.
		{ 'maxBytes'. maxBytes. self maxBytesDisplay }.
		{ 'acceptLargeDownload'. acceptLargeDownload. acceptLargeDownload ifTrue: [ 'yes' ] ifFalse: [ 'no' ] } }
]

{ #category : 'validation' }
Gt4SecurityFeedQuery >> validate [
	"Raise if the query is incoherent. Called before execution so invalid queries fail fast
	rather than picking an inapplicable strategy."
	scope ifNil: [ Error signal: 'FeedQuery: scope is required' ].
	scope = #singleId ifTrue: [
		(id notNil and: [ ecosystems notNil and: [ ecosystems size = 1 ] ])
			ifFalse: [ Error signal: 'FeedQuery: singleId scope needs id + exactly one ecosystem' ] ].
	scope = #window ifTrue: [
		since ifNil: [ Error signal: 'FeedQuery: window scope needs a since cutoff' ] ].
	scope = #ecosystem ifTrue: [
		(ecosystems notNil and: [ ecosystems isNotEmpty ])
			ifFalse: [ Error signal: 'FeedQuery: ecosystem scope needs ecosystems' ] ].
	^ self
]
