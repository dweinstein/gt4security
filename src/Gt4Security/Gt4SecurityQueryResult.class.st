"
Result of executing a {{gtClass:Gt4SecurityQuery}}. Wraps the result {{gtClass:Gt4SecurityVulnerabilityGroup}} with provenance:
- query — the Gt4SecurityQuery that produced this result
- runAt — timestamp
- nvdCount / osvCount — raw result counts per source (before dedup)
- dedupedCount — number of duplicates removed
- errors — per-source error messages

Preserves the query so `gtRefreshActionFor:` can re-run it.

Forward views (Vulnerabilities, By ecosystem, By severity) delegate to the group.
"
Class {
	#name : 'Gt4SecurityQueryResult',
	#superclass : 'Object',
	#instVars : [
		'query',
		'group',
		'runAt',
		'nvdCount',
		'osvCount',
		'feedCount',
		'dedupedCount',
		'errors',
		'runDuration',
		'nvdItems',
		'osvItems',
		'feedItems',
		'mergedGroup',
		'runId'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'accessing' }
Gt4SecurityQueryResult >> addError: aString [
	errors add: aString
]

{ #category : 'gt-search' }
Gt4SecurityQueryResult >> appendSearchField: aValue to: aStream [
	| text |
	aValue ifNil: [ ^ self ].
	text := aValue asString.
	text ifEmpty: [ ^ self ].
	aStream nextPutAll: text; space
]

{ #category : 'gt-search' }
Gt4SecurityQueryResult >> appendSearchFields: aCollection to: aStream [
	aCollection ifNil: [ ^ self ].
	aCollection do: [ :each | self appendSearchField: each to: aStream ]
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> dedupedCount [
	^ dedupedCount
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> dedupedCount: anInteger [
	dedupedCount := anInteger
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> errors [
	^ errors
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> feedCount [
	^ feedCount ifNil: [ 0 ]
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> feedCount: anInteger [
	feedCount := anInteger
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> feedItems [
	^ feedItems
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> filteredOut [
	"Items that survived dedup but were dropped by post-filters (publishedSince / severityFloor).
	Returns an empty group when no post-filter was configured or nothing was dropped."
	| keepIds |
	(mergedGroup isNil or: [ group isNil ])
		ifTrue: [ ^ Gt4SecurityVulnerabilityGroup new ].
	keepIds := (group items collect: [ :each | each id ]) asSet.
	^ Gt4SecurityVulnerabilityGroup withAll:
		(mergedGroup items reject: [ :each | keepIds includes: each id ])
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> filteredOutCount [
	^ self filteredOut size
]

{ #category : 'private - summary' }
Gt4SecurityQueryResult >> formattedRunDuration [
	"Compact run-duration text for the Summary tree. Delegates to
	Gt4SecurityFormat>>#humanDuration: so it matches the rest of the duration cells —
	Pharo's Duration>>humanReadablePrintString is too verbose
	('22 seconds 628 milliseconds 722 microseconds')."
	^ runDuration
		ifNil: [ '(not run)' ]
		ifNotNil: [ Gt4SecurityFormat humanDuration: runDuration ]
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> group [
	^ group
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> group: aGroup [
	group := aGroup
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtByCpeVendorFor: aView [
	<gtView>
	group ifNil: [ ^ aView empty ].
	(group items anySatisfy: [ :v | v hasCpeAffected ]) ifFalse: [ ^ aView empty ].
	^ aView forward
		title: 'By CPE vendor';
		priority: 3.5;
		object: [ group ];
		view: #gtByCpeVendorFor:
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtByEcosystemFor: aView [
	<gtView>
	group ifNil: [ ^ aView empty ].
	^ aView forward
		title: 'By ecosystem';
		priority: 3;
		object: [ group ];
		view: #gtByEcosystemFor:
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtByPackageFor: aView [
	<gtView>
	group ifNil: [ ^ aView empty ].
	^ aView forward
		title: 'By package';
		priority: 6;
		object: [ group ];
		view: #gtByPackageFor:
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtByScoreFor: aView [
	<gtView>
	group ifNil: [ ^ aView empty ].
	^ aView forward
		title: 'By score';
		priority: 4;
		object: [ group ];
		view: #gtByScoreFor:
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtBySeverityFor: aView [
	<gtView>
	group ifNil: [ ^ aView empty ].
	^ aView forward
		title: 'By severity';
		priority: 4;
		object: [ group ];
		view: #gtBySeverityFor:
]

{ #category : 'printing' }
Gt4SecurityQueryResult >> gtDisplayOn: aStream [
	aStream
		print: (group ifNil: [ 0 ] ifNotNil: [ group size ]);
		nextPutAll: ' items'.
	runAt ifNotNil: [
		aStream nextPutAll: ' @ '; nextPutAll: runAt asTime print24 ]
]

{ #category : 'as yet unclassified' }
Gt4SecurityQueryResult >> gtExportActionFor: anAction [
	<gtAction>
	^ anAction button
		icon: BrGlamorousVectorIcons savetodisk;
		tooltip: 'Export to CSV and open the file';
		action: [ :aButton | 
			| fileRef |
			fileRef := self group exportToCsv.
			aButton phlow spawnObject: fileRef ]
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtKevFor: aView [
	"Forwarding KEV view on the query result. Hidden (aView empty) when group has no KEV
	entries, so the tab does not appear on pure-OSV result sets that never touch NVD/KEV."
	<gtView>
	group ifNil: [ ^ aView empty ].
	group inKev isEmpty ifTrue: [ ^ aView empty ].
	^ aView forward
		title: 'CISA KEV';
		priority: 2.2;
		object: [ group ];
		view: #gtKevFor:
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtMalwareFor: aView [
	"Distinct Malware view on the query result, priority 2.5 so it sits between Vulnerabilities (2)
	and Strategies (3). Forwards to the group's gtMalwareFor: which filters to MAL-* / origins."
	<gtView>
	group ifNil: [ ^ aView empty ].
	group malicious isEmpty ifTrue: [ ^ aView empty ].
	^ aView forward
		title: 'Malware';
		priority: 2.5;
		object: [ group ];
		view: #gtMalwareFor:
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtRefreshActionFor: anAction [
	<gtAction>
	^ anAction button
		icon: BrGlamorousVectorIcons refresh;
		tooltip: 'Re-run query';
		priority: 10;
		action: [ :aButton |
			query ifNotNil: [
				aButton phlow spawnObject: query run ] ]
]

{ #category : 'gt-search' }
Gt4SecurityQueryResult >> gtSearchAdvisoriesFor: aSearch [
	<gtSearch>
	^ aSearch list
		title: 'Advisories';
		priority: 1;
		items: [ self searchableEntries ];
		itemName: [ :each | self searchTextForEntry: each ];
		filterBySubstring
]

{ #category : 'gt-views' }
Gt4SecurityQueryResult >> gtStrategiesFor: aView [
	"Per-strategy trace of what actually ran. Composite view that exposes Narrative prose,
	per-strategy Detail (columned list), and Totals rollup as sub-tabs from a single
	QueryResult tab. Order: Narrative → Detail → Totals — Narrative gives the at-a-glance
	read, Detail is the drill-down, Totals is the rollup. The Detail tab is the same
	gtSpansFor: view the SpanGroup uses standalone, just retitled here for context."
	<gtView>
	| group |
	group := self strategyTraceRows.
	^ aView composite
		title: 'Strategies';
		priority: 10;
		views: {
			group gtNarrativeFor: GtPhlowView empty.
			(group gtSpansFor: GtPhlowView empty) title: 'Detail'.
			group gtTotalsFor: GtPhlowView empty }
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtSummaryFor: aView [
	"Summary tree: Run / Counts / Sources / Errors / Query sections with drill-through targets.
	Leafs send their #target (a subgroup, timestamp, error, etc.) when clicked."
	<gtView>
	^ aView columnedTree
		title: 'Summary';
		priority: 1;
		items: [ self summaryRows ];
		children: [ :row | row at: #children ifAbsent: [ #() ] ];
		column: 'Property' text: [ :row | row at: #label ] weight: 1;
		column: 'Value' text: [ :row | row at: #display ] weight: 3;
		send: [ :row | row at: #target ifAbsent: [ nil ] ];
		expandOneLevel
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtTimelineFor: aView [
	<gtView>
	group ifNil: [ ^ aView empty ].
	^ aView forward
		title: 'Timeline';
		priority: 5;
		object: [ group ];
		view: #gtTimelineFor:
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> gtVulnerabilitiesFor: aView [
	"Forwarding Vulnerabilities view on the query result. Hidden (aView empty) when the
	group has no non-malicious entries so the tab does not appear on pure-malware result
	sets. Malware and KEV are separate forwards."
	<gtView>
	group ifNil: [ ^ aView empty ].
	group nonMalicious isEmpty ifTrue: [ ^ aView empty ].
	^ aView forward
		title: 'Vulnerabilities';
		priority: 2;
		object: [ group ];
		view: #gtVulnerabilitiesFor:
]

{ #category : 'views-support' }
Gt4SecurityQueryResult >> historyEntriesForThisRun: aHistory [
	"Select the history entries that belong to this run. Prefers runId filtering when this
	result carries one; falls back to a runAt-bounded time window for older results that were
	captured before runId tagging existed."
	runId ifNotNil: [
		^ aHistory select: [ :e | (e at: 'runId' ifAbsent: [ nil ]) = runId ] ].
	runAt ifNil: [ ^ #() ].
	^ aHistory select: [ :e |
		| t upper |
		t := e at: 'at'.
		upper := runDuration
			ifNil: [ DateAndTime now ]
			ifNotNil: [ runAt + runDuration + 5 seconds ].
		t >= runAt and: [ t <= upper ] ]
]

{ #category : 'initialization' }
Gt4SecurityQueryResult >> initialize [
	super initialize.
	nvdCount := 0.
	osvCount := 0.
	feedCount := 0.
	dedupedCount := 0.
	errors := OrderedCollection new.
	nvdItems := Gt4SecurityVulnerabilityGroup new.
	osvItems := Gt4SecurityVulnerabilityGroup new.
	feedItems := Gt4SecurityVulnerabilityGroup new.
	mergedGroup := Gt4SecurityVulnerabilityGroup new
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> mergedGroup [
	"The post-dedup, pre-post-filter merged group — everything that would have been in the
	final group if no publishedSince / severityFloor post-filters applied."
	^ mergedGroup
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> mergedGroup: aGroup [
	mergedGroup := aGroup
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> nvdCount [
	^ nvdCount
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> nvdCount: anInteger [
	nvdCount := anInteger
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> nvdItems [
	^ nvdItems
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> osvCount [
	^ osvCount
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> osvCount: anInteger [
	osvCount := anInteger
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> osvItems [
	^ osvItems
]

{ #category : 'printing' }
Gt4SecurityQueryResult >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (';
		print: (group ifNil: [ 0 ] ifNotNil: [ group size ]);
		nextPutAll: ' items, ';
		nextPutAll: (runAt ifNil: [ '(not run)' ] ifNotNil: [ runAt asTime print24 ]);
		nextPutAll: ')'
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> query [
	^ query
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> query: aQuery [
	query := aQuery
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> runAt [
	^ runAt
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> runAt: aDateAndTime [
	runAt := aDateAndTime
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> runDuration [
	"Duration from runAt until the query finished fanning out and post-filtering. nil until run completes."
	^ runDuration
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> runDuration: aDuration [
	runDuration := aDuration
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> runId [
	"Identifier stamped on every feed-client event recorded during this query's run.
	Used by strategyTraceRows to filter history precisely, without depending on a time
	window. Nil for results created before runId tagging was introduced."
	^ runId
]

{ #category : 'accessing' }
Gt4SecurityQueryResult >> runId: anIdString [
	runId := anIdString
]

{ #category : 'gt-search' }
Gt4SecurityQueryResult >> searchAliasIdsForEntry: anEntry [
	| aliases |
	aliases := anEntry aliases.
	aliases ifNil: [ ^ #() ].
	^ aliases items collect: [ :each | each id ]
]

{ #category : 'gt-search' }
Gt4SecurityQueryResult >> searchTextForEntry: anEntry [
	^ String streamContents: [ :stream |
		self appendSearchField: anEntry id to: stream.
		self appendSearchFields: (self searchAliasIdsForEntry: anEntry) to: stream.
		anEntry severity ifNotNil: [
			self appendSearchField: anEntry displaySeverity to: stream ].
		anEntry affected ifNotNil: [
			self appendSearchField: anEntry ecosystemDisplayText to: stream.
			self appendSearchFields: anEntry affectedPackageNames to: stream ].
		self appendSearchField: anEntry summary to: stream ]
]

{ #category : 'gt-search' }
Gt4SecurityQueryResult >> searchableEntries [
	group ifNil: [ ^ #() ].
	^ group items
]

{ #category : 'private - strategy trace' }
Gt4SecurityQueryResult >> strategyTraceRows [
	"Per-strategy span group reconstructed from structured strategyStart / strategyEnd
	events on the feed client history. Returns a Gt4SecurityStrategySpanGroup — a domain
	group with its own gtViews (Strategies columned list + Totals rollup) — so the result's
	Strategies tab can simply forward into it."
	| client entries |
	query ifNil: [ ^ Gt4SecurityStrategySpanGroup new ].
	client := [ query feedClient ] on: Error do: [ :e | ^ Gt4SecurityStrategySpanGroup new ].
	client isNil ifTrue: [ ^ Gt4SecurityStrategySpanGroup new ].
	entries := self historyEntriesForThisRun: client history.
	^ Gt4SecurityStrategySpanGroup fromHistoryEntries: entries
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> summaryCountsSection [
	"Post-filter counts broken down by kind (CVE / Malware / KEV) plus filtered/dedup. Header
	row's display is the group size; target spawns the whole group."
	| cves mal kev children |
	cves := group cves.
	mal := group malicious.
	kev := group inKev.
	children := OrderedCollection new.
	children add: (self summaryNodeLabel: 'Total (post-filter)' display: group size asString target: group children: #()).
	children add: (self summaryNodeLabel: 'CVEs' display: cves size asString target: (cves isEmpty ifFalse: [ cves ]) children: #()).
	children add: (self summaryNodeLabel: 'Malware' display: mal size asString target: (mal isEmpty ifFalse: [ mal ]) children: #()).
	children add: (self summaryNodeLabel: 'In CISA KEV' display: kev size asString target: (kev isEmpty ifFalse: [ kev ]) children: #()).
	children add: (self summaryNodeLabel: 'Filtered out' display: self filteredOutCount asString
		target: (self filteredOutCount > 0 ifTrue: [ self filteredOut ]) children: #()).
	children add: (self summaryNodeLabel: 'Deduplicated' display: dedupedCount asString target: nil children: #()).
	^ self summaryNodeLabel: 'Counts' display: group size asString target: group children: children
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> summaryErrorsSection [
	"Errors section. When no errors, the single row displays '(none)' with no children.
	When present, each error becomes a child row with the error text as its display."
	| display children |
	errors isEmpty
		ifTrue: [ display := '(none)'. children := #() ]
		ifFalse: [
			display := errors size asString.
			children := errors collect: [ :e | self summaryNodeLabel: '' display: e displayString target: e children: #() ] ].
	^ self summaryNodeLabel: 'Errors' display: display
		target: (errors isEmpty ifFalse: [ errors ])
		children: children
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> summaryNodeLabel: aLabel display: aDisplay target: aTarget children: aChildren [
	"Build one Summary tree node. Children default to #(); target is optional."
	| row |
	row := Dictionary new.
	row at: #label put: aLabel.
	row at: #display put: aDisplay.
	aTarget ifNotNil: [ row at: #target put: aTarget ].
	row at: #children put: aChildren.
	^ row
]

{ #category : 'private - summary' }
Gt4SecurityQueryResult >> summaryQuerySection [
	"Query parameters section — only built when #query is non-nil. Nested children show the
	individual inputs (CPEs, OSV packages, ecosystems, floor, since). Section display is empty;
	target spawns the Gt4SecurityQuery itself."
	| children feedDisplay |
	children := OrderedCollection new.
	children add: (self summaryNodeLabel: 'NVD CPEs'
		display: (', ' join: query nvdCpes)
		target: (query nvdCpes isEmpty ifFalse: [ query nvdCpes ])
		children: #()).
	children add: (self summaryNodeLabel: 'OSV packages'
		display: (', ' join: (query osvPackages collect: [ :a | a key , ':' , a value ]))
		target: (query osvPackages isEmpty ifFalse: [ query osvPackages ])
		children: #()).
	feedDisplay := (query feedSpecs isNil or: [ query feedSpecs isEmpty ])
		ifTrue: [ '(none)' ]
		ifFalse: [ ', ' join: (query feedSpecs collect: [ :s | s at: 'ecosystem' ]) ].
	children add: (self summaryNodeLabel: 'Feed ecosystems'
		display: feedDisplay
		target: query feedSpecs
		children: #()).
	children add: (self summaryNodeLabel: 'Published since'
		display: (query publishedSince
			ifNil: [ '(any)' ]
			ifNotNil: [ Gt4SecurityFormat humanTimespan: query publishedSince ])
		target: query publishedSince
		children: #()).
	children add: (self summaryNodeLabel: 'Severity floor'
		display: (query severityFloor ifNil: [ '(any)' ] ifNotNil: [ :s | s printString ])
		target: query severityFloor
		children: #()).
	^ self summaryNodeLabel: 'Query' display: '' target: query children: children
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> summaryRows [
	"Top-level sections for the Summary tree. Each section is a tree node with #label, #display,
	optional #target, and #children. The Counts and Query sections are conditional."
	| roots |
	roots := OrderedCollection new.
	roots add: self summaryRunSection.
	group ifNotNil: [ roots add: self summaryCountsSection ].
	roots add: self summarySourcesSection.
	roots add: self summaryErrorsSection.
	query ifNotNil: [ roots add: self summaryQuerySection ].
	^ roots
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> summaryRunSection [
	"Run metadata: when it ran and how long it took. Display of the Run row is the run timestamp."
	| runDisplay |
	runDisplay := runAt ifNil: [ '(not run)' ] ifNotNil: [ runAt printString ].
	^ self
		summaryNodeLabel: 'Run'
		display: runDisplay
		target: runAt
		children: {
			self summaryNodeLabel: 'Run at' display: runDisplay target: runAt children: #().
			self summaryNodeLabel: 'Run duration' display: self formattedRunDuration target: runDuration children: #() }
]

{ #category : 'gt - views' }
Gt4SecurityQueryResult >> summarySourcesSection [
	"Per-upstream totals — NVD/OSV/Feed. Section display is the sum; section target is the
	pre-post-filter merged group (so clicking the Sources row drills into what was merged
	before severityFloor / publishedSince trimmed it). Children only appear for sources that
	contributed, keeping the tree light on single-source runs."
	| total children |
	total := nvdCount + osvCount + self feedCount.
	children := OrderedCollection new.
	nvdCount > 0 ifTrue: [
		children add: (self summaryNodeLabel: 'From NVD' display: nvdCount asString
			target: (nvdItems isEmpty ifFalse: [ nvdItems ]) children: #()) ].
	osvCount > 0 ifTrue: [
		children add: (self summaryNodeLabel: 'From OSV' display: osvCount asString
			target: (osvItems isEmpty ifFalse: [ osvItems ]) children: #()) ].
	self feedCount > 0 ifTrue: [
		children add: (self summaryNodeLabel: 'From Feed' display: self feedCount asString
			target: (feedItems isEmpty ifFalse: [ feedItems ]) children: #()) ].
	^ self summaryNodeLabel: 'Sources' display: total asString
		target: (mergedGroup isEmpty ifFalse: [ mergedGroup ])
		children: children
]
