"
Fluent builder for cross-source CVE / advisory queries. Fans out to {{gtClass:Gt4SecurityNvdClient}} (CPE-based) and {{gtClass:Gt4SecurityOsvClient}} (package-based) and merges results into a single {{gtClass:Gt4SecurityVulnerabilityGroup}}, deduplicated by id and aliases.

Builder methods (return self, chainable):
- cpe:, ios — add NVD CPE targets
- package:ecosystem:, androidPackage: — add OSV package targets
- mobileOnly — populate iOS + Android kernel + framework
- publishedSince: — date floor (applied as NVD server-side filter and OSV client-side post-filter)
- severityAtLeast: — numeric CVSS baseScore floor (applied client-side)
- limit: — max per source

Call `run` to execute — returns a {{gtClass:Gt4SecurityQueryResult}} carrying the group plus provenance.

Inject alternative clients via `osvClient:` / `nvdClient:` for testing.
"
Class {
	#name : 'Gt4SecurityQuery',
	#superclass : 'Object',
	#instVars : [
		'osvPackages',
		'nvdCpes',
		'publishedSince',
		'severityFloor',
		'limit',
		'osvClient',
		'nvdClient',
		'feedSpecs',
		'feedClient'
	],
	#category : 'Gt4Security-Query',
	#package : 'Gt4Security',
	#tag : 'Query'
}

{ #category : 'private' }
Gt4SecurityQuery class >> nvdDateStringFor: aDate [
	"ISO 8601 midnight for lexicographic compare against published/modified strings.
	We reuse the instance method on the NVD client so there's one formatter."
	^ Gt4SecurityNvdClient new nvdDateString: aDate
]

{ #category : 'building' }
Gt4SecurityQuery >> androidPackage: aPackageNameString [
	"Shortcut for the OSV Android ecosystem."
	self package: aPackageNameString ecosystem: 'Android'
]

{ #category : 'building' }
Gt4SecurityQuery >> cpe: aCpeString [
	"Add an NVD virtual CPE target to this query."
	nvdCpes add: aCpeString
]

{ #category : 'accessing' }
Gt4SecurityQuery >> feedClient [
	^ feedClient ifNil: [ feedClient := Gt4SecurityOsvFeedClient new ]
]

{ #category : 'accessing' }
Gt4SecurityQuery >> feedClient: aClient [
	feedClient := aClient
]

{ #category : 'building' }
Gt4SecurityQuery >> feedEcosystem: anEcosystemString [
	"Add an OSV bulk-feed target to this query. Pairs with publishedSince: to bound the date range. For large ecosystems (npm etc.) this requires feedAcceptLargeDownload: true."
	feedSpecs add: (Dictionary new
		at: 'ecosystem' put: anEcosystemString;
		at: 'acceptLarge' put: false;
		yourself)
]

{ #category : 'building' }
Gt4SecurityQuery >> feedEcosystem: anEcosystemString acceptLargeDownload: aBoolean [
	"Same as feedEcosystem: but opts into large downloads (e.g. npm @ 192 MB)."
	feedSpecs add: (Dictionary new
		at: 'ecosystem' put: anEcosystemString;
		at: 'acceptLarge' put: aBoolean;
		yourself)
]

{ #category : 'accessing' }
Gt4SecurityQuery >> feedSpecs [
	^ feedSpecs
]

{ #category : 'gt - views' }
Gt4SecurityQuery >> gtConfigurationFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Configuration';
		priority: 1;
		items: [ {
			'NVD CPEs' -> (nvdCpes isEmpty ifTrue: [ '(none)' ] ifFalse: [ ', ' join: nvdCpes ]).
			'OSV packages' -> (osvPackages isEmpty
				ifTrue: [ '(none)' ]
				ifFalse: [ ', ' join: (osvPackages collect: [ :a | a key , ':' , a value ]) ]).
			'Feed ecosystems' -> ((feedSpecs isNil or: [ feedSpecs isEmpty ])
				ifTrue: [ '(none)' ]
				ifFalse: [ ', ' join: (feedSpecs collect: [ :s |
					(s at: 'ecosystem') , ((s at: 'acceptLarge' ifAbsent: [ false ])
						ifTrue: [ ' [large]' ] ifFalse: [ '' ]) ]) ]).
			'Published since' -> (publishedSince ifNil: [ '(any)' ] ifNotNil: [ publishedSince printString ]).
			'Severity floor' -> (severityFloor ifNil: [ '(any)' ] ifNotNil: [ severityFloor printString ]).
			'Limit per source' -> limit printString } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 4
]

{ #category : 'printing' }
Gt4SecurityQuery >> gtDisplayOn: aStream [
	aStream nextPutAll: 'Query: '.
	nvdCpes isEmpty ifFalse: [
		aStream print: nvdCpes size; nextPutAll: ' CPE'.
		nvdCpes size > 1 ifTrue: [ aStream nextPut: $s ] ].
	(nvdCpes notEmpty and: [ osvPackages notEmpty ]) ifTrue: [ aStream nextPutAll: ', ' ].
	osvPackages isEmpty ifFalse: [
		aStream print: osvPackages size; nextPutAll: ' OSV package'.
		osvPackages size > 1 ifTrue: [ aStream nextPut: $s ] ].
	(nvdCpes isEmpty and: [ osvPackages isEmpty ]) ifTrue: [ aStream nextPutAll: '(empty)' ]
]

{ #category : 'gt - views' }
Gt4SecurityQuery >> gtRunActionFor: anAction [
	<gtAction>
	^ anAction button
		icon: BrGlamorousVectorIcons play;
		tooltip: 'Run query';
		priority: 10;
		action: [ :aButton |
			| result |
			result := self run.
			aButton phlow spawnObject: result ]
]

{ #category : 'initialization' }
Gt4SecurityQuery >> initialize [
	super initialize.
	osvPackages := OrderedCollection new.
	nvdCpes := OrderedCollection new.
	feedSpecs := OrderedCollection new.
	limit := 100
]

{ #category : 'building' }
Gt4SecurityQuery >> ios [
	"Shortcut for Apple iPhone OS via NVD virtual CPE."
	self cpe: 'cpe:2.3:o:apple:iphone_os'
]

{ #category : 'accessing' }
Gt4SecurityQuery >> limit [
	^ limit
]

{ #category : 'building' }
Gt4SecurityQuery >> limit: anInteger [
	"Max results per source before dedup."
	limit := anInteger
]

{ #category : 'building' }
Gt4SecurityQuery >> mobileOnly [
	"Convenience: populate iOS + common Android package targets for a typical mobile query."
	self ios.
	self androidPackage: 'platform/frameworks/base'.
	self androidPackage: ':linux_kernel:'
]

{ #category : 'accessing' }
Gt4SecurityQuery >> nvdClient [
	^ nvdClient ifNil: [ nvdClient := Gt4SecurityNvdClient new ]
]

{ #category : 'accessing' }
Gt4SecurityQuery >> nvdClient: aClient [
	nvdClient := aClient
]

{ #category : 'accessing' }
Gt4SecurityQuery >> nvdCpes [
	^ nvdCpes
]

{ #category : 'accessing' }
Gt4SecurityQuery >> osvClient [
	^ osvClient ifNil: [ osvClient := Gt4SecurityOsvClient new ]
]

{ #category : 'accessing' }
Gt4SecurityQuery >> osvClient: aClient [
	osvClient := aClient
]

{ #category : 'accessing' }
Gt4SecurityQuery >> osvPackages [
	^ osvPackages
]

{ #category : 'building' }
Gt4SecurityQuery >> package: aPackageNameString ecosystem: anEcosystemString [
	"Add an OSV package target to this query."
	osvPackages add: (anEcosystemString -> aPackageNameString)
]

{ #category : 'execution' }
Gt4SecurityQuery >> postFilter: aGroup [
	"Apply client-side post-filters that can't always be pushed into the source APIs (OSV has no
	publishedSince, and neither API supports a severity floor in the query)."
	| result |
	result := aGroup.
	publishedSince ifNotNil: [
		result := result publishedSince: (self class nvdDateStringFor: publishedSince) ].
	severityFloor ifNotNil: [
		result := result severityAtLeast: severityFloor ].
	^ result
]

{ #category : 'printing' }
Gt4SecurityQuery >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (';
		print: nvdCpes size;
		nextPutAll: ' CPEs, ';
		print: osvPackages size;
		nextPutAll: ' OSV packages)'
]

{ #category : 'accessing' }
Gt4SecurityQuery >> publishedSince [
	^ publishedSince
]

{ #category : 'building' }
Gt4SecurityQuery >> publishedSince: aDate [
	"Filter to vulnerabilities published on or after the given Date. NVD queries get a server-side filter;
	OSV queries get a client-side filter since OSV does not expose a published-since endpoint."
	publishedSince := aDate
]

{ #category : 'executing' }
Gt4SecurityQuery >> run [
	"Fan out to NVD + OSV + Feed clients, merge results into a single group, dedupe by id and
	alias, apply post-filters, and wrap in a Gt4SecurityQueryResult with provenance (runAt +
	runDuration, runId, per-source counts, errors). The merged (post-dedup, pre-post-filter)
	group is preserved on the result so consumers can see what was dropped by publishedSince /
	severityFloor. The feed call is wrapped in runWithId:do: so every strategy / http event
	recorded during this run carries the result's runId, enabling precise strategyTraceRows."
	| merged seen result startedAt |
	result := Gt4SecurityQueryResult new.
	result query: self.
	result runId: UUID new asString36.
	startedAt := DateAndTime now.
	result runAt: startedAt.
	merged := Gt4SecurityVulnerabilityGroup new.
	seen := Set new.
	self runNvdInto: merged seen: seen result: result.
	self runOsvInto: merged seen: seen result: result.
	self feedClient runWithId: result runId do: [
		self runFeedInto: merged seen: seen result: result ].
	result mergedGroup: merged.
	result group: (self postFilter: merged).
	result runDuration: DateAndTime now - startedAt.
	^ result
]

{ #category : 'running' }
Gt4SecurityQuery >> runFeedInto: aGroup seen: aSet result: aResult [
	"Fan out each feed target into aGroup with id+alias dedup. Raw per-source items (pre-dedup) are
	also captured on the result for inspection.
	Routing when publishedSince is set:
	- Small, non-ZIP64 ecosystems (per Gt4SecurityOsvFeedClient>>#isLargeEcosystem:) use the zip path + publishedSince post-filter. A single download + in-memory parse is 8-16x faster than fanning out hundreds-to-thousands of per-ID HTTP GETs.
	- ZIP64 / large ecosystems (npm, Debian, Ubuntu, RHEL, Alma, Rocky, SUSE) use modified_id.csv + parallel per-ID fetch. The zip is either too large to parse in-memory or ZIP64, which Pharo's ZipArchive can't seek; even with our unzip-subprocess fallback, extraction of 200K+ entries is slow-by-design.
	When publishedSince is unset, use ecosystemFull: for the whole ecosystem (acceptLargeDownload honored)."
	feedSpecs do: [ :spec |
		[ | eco accept group |
		eco := spec at: 'ecosystem'.
		accept := spec at: 'acceptLarge' ifAbsent: [ false ].
		group := publishedSince
			ifNotNil: [
				(self feedClient isLargeEcosystem: eco)
					ifTrue: [ self feedClient
						recentModifiedSince: publishedSince
						ecosystem: eco
						concurrency: 16 ]
					ifFalse: [ self feedClient
						recentSince: publishedSince
						ecosystem: eco
						acceptLargeDownload: accept ] ]
			ifNil: [ self feedClient ecosystemFull: eco acceptLargeDownload: accept ].
		group items do: [ :each |
			| dup |
			aResult feedCount: aResult feedCount + 1.
			aResult feedItems addItem: each.
			dup := (each id notNil and: [ aSet includes: each id ])
				or: [ each aliases anySatisfy: [ :alias | aSet includes: alias id ] ].
			dup
				ifTrue: [ aResult dedupedCount: aResult dedupedCount + 1 ]
				ifFalse: [
					each id ifNotNil: [ :anId | aSet add: anId ].
					each aliases do: [ :alias | aSet add: alias id ].
					aGroup addItem: each ] ] ]
		on: Error do: [ :e |
			aResult addError: 'Feed (' , (spec at: 'ecosystem') , '): ' , e messageText ] ]
]

{ #category : 'execution' }
Gt4SecurityQuery >> runNvdInto: aGroup seen: aSet [
	"For each configured NVD CPE, query the client and add non-duplicate results to aGroup."
	nvdCpes do: [ :cpe |
		| result |
		result := publishedSince
			ifNil: [ self nvdClient cvesForVirtualCpe: cpe limit: limit ]
			ifNotNil: [
				self nvdClient
					cvesForVirtualCpe: cpe
					publishedSince: publishedSince
					until: Date today + 1 day
					limit: limit ].
		result do: [ :each |
			each id ifNotNil: [ :anId |
				(aSet includes: anId) ifFalse: [
					aSet add: anId.
					aGroup addItem: each ] ] ] ]
]

{ #category : 'running' }
Gt4SecurityQuery >> runNvdInto: aGroup seen: aSet result: aResult [
	"For each configured NVD CPE, query the client and add non-duplicate results to aGroup.
	Raw per-source items (pre-dedup) are also captured on the result for inspection."
	nvdCpes do: [ :cpe |
		[ | items |
		items := publishedSince
			ifNil: [ self nvdClient cvesForVirtualCpe: cpe limit: limit ]
			ifNotNil: [
				self nvdClient
					cvesForVirtualCpe: cpe
					publishedSince: publishedSince
					until: Date today + 1 day
					limit: limit ].
		items do: [ :each |
			aResult nvdCount: aResult nvdCount + 1.
			aResult nvdItems addItem: each.
			each id ifNotNil: [ :anId |
				(aSet includes: anId)
					ifTrue: [ aResult dedupedCount: aResult dedupedCount + 1 ]
					ifFalse: [
						aSet add: anId.
						aGroup addItem: each ] ] ] ]
		on: Error do: [ :e |
			aResult addError: 'NVD (' , cpe , '): ' , e messageText ] ]
]

{ #category : 'execution' }
Gt4SecurityQuery >> runOsvInto: aGroup seen: aSet [
	"For each configured OSV package, query the client and add non-duplicate results.
	Also dedupe by alias — an OSV vuln's aliases often contain a CVE id already seen from NVD."
	osvPackages do: [ :assoc |
		| result |
		result := self osvClient queryEcosystem: assoc key package: assoc value.
		result do: [ :each |
			| dup |
			dup := (each id notNil and: [ aSet includes: each id ])
				or: [ each aliases anySatisfy: [ :alias | aSet includes: alias ] ].
			dup ifFalse: [
				each id ifNotNil: [ :anId | aSet add: anId ].
				each aliases do: [ :alias | aSet add: alias ].
				aGroup addItem: each ] ] ]
]

{ #category : 'running' }
Gt4SecurityQuery >> runOsvInto: aGroup seen: aSet result: aResult [
	"For each configured OSV package, query the client and add non-duplicate results.
	Dedupe by alias id — an OSV vuln's aliases often contain a CVE id already seen from NVD.
	Raw per-source items (pre-dedup) are also captured on the result for inspection."
	osvPackages do: [ :assoc |
		[ | result |
		result := self osvClient queryEcosystem: assoc key package: assoc value.
		result do: [ :each |
			| dup |
			aResult osvCount: aResult osvCount + 1.
			aResult osvItems addItem: each.
			dup := (each id notNil and: [ aSet includes: each id ])
				or: [ each aliases anySatisfy: [ :alias | aSet includes: alias id ] ].
			dup
				ifTrue: [ aResult dedupedCount: aResult dedupedCount + 1 ]
				ifFalse: [
					each id ifNotNil: [ :anId | aSet add: anId ].
					each aliases do: [ :alias | aSet add: alias id ].
					aGroup addItem: each ] ] ]
		on: Error do: [ :e |
			aResult addError: 'OSV (' , assoc key , ':' , assoc value , '): ' , e messageText ] ]
]

{ #category : 'building' }
Gt4SecurityQuery >> severityAtLeast: aNumber [
	"Post-filter: drop vulnerabilities whose primary baseScore is below aNumber."
	severityFloor := aNumber
]

{ #category : 'accessing' }
Gt4SecurityQuery >> severityFloor [
	^ severityFloor
]
