"
Wraps a single entry in a Gt4SecurityVulnerability's affected array — an (ecosystem, package, versions) triple.

The ecosystem slot carries an OSV-schema package ecosystem (npm, PyPI, Maven, Android, Pub, ...) when the entry comes from OSV. For NVD-sourced entries, ecosystem is nil because CPE is an identifier scheme (OS / application / hardware), not a package ecosystem.

For CPE entries, the package name is a raw CPE 2.3 string like `cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*`. Use `cpeVendor`, `cpeProduct`, `cpeVersion` to extract components, `displayName` for a short vendor/product label, and `isCpe` to branch on scheme.

For OSV-sourced entries, the package name is the native ecosystem identifier (Maven coords, npm name, etc.) and `isCpe` returns false.
"
Class {
	#name : 'Gt4SecurityAffectedEntry',
	#superclass : 'Object',
	#instVars : [
		'ecosystem',
		'packageName',
		'versions',
		'ranges',
		'rawDict',
		'fixes',
		'vanirSignatures',
		'spl',
		'ecosystemSeverity',
		'ecosystemTypes',
		'vulnerable',
		'matchCriteriaId',
		'configurationIndex',
		'nodeIndex',
		'nodeOperator'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityAffectedEntry class >> fromDictionary: aDictionary [
	"Parse an OSV or NVD-normalized affected entry ({package: {ecosystem, name}, versions, ranges, ...}). Also unpacks the Android-style ecosystem_specific block (fixes, vanir_signatures, spl, severity, types) and the NVD provenance annotations (__nvd_*) emitted by Gt4SecurityVulnerability class>>#nvdAffectedFrom:."
	| pkg rawRanges es rawFixes rawVanir rawTypes |
	pkg := aDictionary at: 'package' ifAbsent: [ Dictionary new ].
	rawRanges := aDictionary at: 'ranges' ifAbsent: [ #() ].
	es := aDictionary at: 'ecosystem_specific' ifAbsent: [ Dictionary new ].
	rawFixes := es at: 'fixes' ifAbsent: [ #() ].
	rawVanir := es at: 'vanir_signatures' ifAbsent: [ #() ].
	rawTypes := es at: 'types' ifAbsent: [ #() ].
	^ self new
		ecosystem: (pkg at: 'ecosystem' ifAbsent: [ nil ]);
		packageName: (pkg at: 'name' ifAbsent: [ nil ]);
		versions: (aDictionary at: 'versions' ifAbsent: [ #() ]);
		ranges: (rawRanges collect: [ :each | Gt4SecurityVersionRange fromDictionary: each ]) asArray;
		rawDict: aDictionary;
		fixes: (Gt4SecurityFixGroup withAll:
			(rawFixes collect: [ :url | Gt4SecurityFix fromUrl: url ]));
		vanirSignatures: (Gt4SecurityVanirSignatureGroup withAll:
			(rawVanir collect: [ :each | Gt4SecurityVanirSignature fromDictionary: each ]));
		spl: (es at: 'spl' ifAbsent: [ nil ]);
		ecosystemSeverity: (es at: 'severity' ifAbsent: [ nil ]);
		ecosystemTypes: rawTypes;
		vulnerable: (aDictionary at: '__nvd_vulnerable' ifAbsent: [ nil ]);
		matchCriteriaId: (aDictionary at: '__nvd_matchCriteriaId' ifAbsent: [ nil ]);
		configurationIndex: (aDictionary at: '__nvd_configurationIndex' ifAbsent: [ nil ]);
		nodeIndex: (aDictionary at: '__nvd_nodeIndex' ifAbsent: [ nil ]);
		nodeOperator: (aDictionary at: '__nvd_nodeOperator' ifAbsent: [ nil ]);
		yourself
]

{ #category : 'derived' }
Gt4SecurityAffectedEntry >> advisorySourceUrl [
	"URL of the advisory file this affected entry was sourced from (OSV database_specific.source — present for GHSA-reviewed and malicious-packages entries). Nil when absent."
	| dbSpec |
	rawDict ifNil: [ ^ nil ].
	dbSpec := rawDict at: 'database_specific' ifAbsent: [ ^ nil ].
	dbSpec ifNil: [ ^ nil ].
	^ dbSpec at: 'source' ifAbsent: [ nil ]
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> configurationIndex [
	^ configurationIndex
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> configurationIndex: anInteger [
	configurationIndex := anInteger
]

{ #category : 'derived' }
Gt4SecurityAffectedEntry >> cpeParts [
	"Split a CPE 2.3 string on colons. Returns an array or nil if not a CPE."
	self isCpe ifFalse: [ ^ nil ].
	^ packageName splitOn: $:
]

{ #category : 'derived' }
Gt4SecurityAffectedEntry >> cpeProduct [
	"Extract product from a CPE 2.3 string, or nil."
	| parts |
	parts := self cpeParts.
	parts ifNil: [ ^ nil ].
	^ parts size >= 5 ifTrue: [ parts fifth ] ifFalse: [ nil ]
]

{ #category : 'derived' }
Gt4SecurityAffectedEntry >> cpeVendor [
	"Extract vendor from a CPE 2.3 string, or nil."
	| parts |
	parts := self cpeParts.
	parts ifNil: [ ^ nil ].
	^ parts size >= 4 ifTrue: [ parts fourth ] ifFalse: [ nil ]
]

{ #category : 'derived' }
Gt4SecurityAffectedEntry >> cpeVersion [
	"Extract version from a CPE 2.3 string, or nil."
	| parts |
	parts := self cpeParts.
	parts ifNil: [ ^ nil ].
	^ parts size >= 6 ifTrue: [ parts sixth ] ifFalse: [ nil ]
]

{ #category : 'derived' }
Gt4SecurityAffectedEntry >> displayName [
	"Short label for columned-list display."
	| vendor product |
	self isCpe ifFalse: [ ^ packageName ifNil: [ '(unknown)' ] ].
	vendor := self cpeVendor ifNil: [ '?' ].
	product := self cpeProduct ifNil: [ '?' ].
	^ vendor , '/' , product
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> ecosystem [
	^ ecosystem
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> ecosystem: aString [
	ecosystem := aString
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> ecosystemSeverity [
	ecosystemSeverity ifNil: [
		rawDict ifNotNil: [
			ecosystemSeverity := (rawDict at: 'ecosystem_specific' ifAbsent: [ Dictionary new ])
				at: 'severity' ifAbsent: [ nil ] ] ].
	^ ecosystemSeverity
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> ecosystemSeverity: aString [
	ecosystemSeverity := aString
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> ecosystemTypes [
	ecosystemTypes ifNil: [
		rawDict ifNotNil: [
			ecosystemTypes := (rawDict at: 'ecosystem_specific' ifAbsent: [ Dictionary new ])
				at: 'types' ifAbsent: [ #() ] ] ].
	^ ecosystemTypes
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> ecosystemTypes: aCollection [
	ecosystemTypes := aCollection
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> fixes [
	"Lazily parse from rawDict so instances created before ecosystem_specific was modeled still work."
	fixes ifNil: [
		rawDict ifNotNil: [
			| es raw |
			es := rawDict at: 'ecosystem_specific' ifAbsent: [ Dictionary new ].
			raw := es at: 'fixes' ifAbsent: [ #() ].
			fixes := Gt4SecurityFixGroup withAll:
				(raw collect: [ :url | Gt4SecurityFix fromUrl: url ]) ] ].
	^ fixes
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> fixes: aGroup [
	fixes := aGroup
]

{ #category : 'printing' }
Gt4SecurityAffectedEntry >> gtDisplayOn: aStream [
	aStream
		nextPutAll: self displayName;
		nextPutAll: ' (';
		nextPutAll: (ecosystem ifNil: [ '?' ]);
		nextPut: $)
]

{ #category : 'gt - views' }
Gt4SecurityAffectedEntry >> gtFixesFor: aView [
	<gtView>
	(fixes isNil or: [ fixes isEmpty ]) ifTrue: [ ^ aView empty ].
	^ aView forward
		title: 'Fixes';
		priority: 2;
		object: [ fixes ];
		view: #gtFixesFor:
]

{ #category : 'gt - views' }
Gt4SecurityAffectedEntry >> gtOpenAdvisorySourceActionFor: anAction [
	<gtAction>
	self advisorySourceUrl ifNil: [ ^ anAction noAction ].
	^ anAction button
		icon: BrGlamorousVectorIcons browse;
		tooltip: 'Open advisory source file in browser';
		priority: 15;
		action: [ :aButton |
			self advisorySourceUrl ifNotNil: [ :url | WebBrowser openOn: url ] ]
]

{ #category : 'gt - views' }
Gt4SecurityAffectedEntry >> gtRangesFor: aView [
	<gtView>
	self ranges isEmpty ifTrue: [ ^ aView empty ].
	^ aView columnedList
		title: 'Ranges';
		priority: 2;
		items: [ self ranges ];
		column: 'Type' text: [ :r | r type ifNil: [ '?' ] ] weight: 1;
		column: 'Constraint' text: [ :r | r summary ] weight: 3
]

{ #category : 'gt - views' }
Gt4SecurityAffectedEntry >> gtRawFor: aView [
	<gtView>
	rawDict ifNil: [ ^ aView empty ].
	^ aView textEditor
		title: 'Raw';
		priority: 10;
		text: [ NeoJSONWriter toStringPretty: rawDict ]
]

{ #category : 'gt - views' }
Gt4SecurityAffectedEntry >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 1;
		items: [ | items |
			items := OrderedCollection new.
			items add: 'Ecosystem' -> (ecosystem ifNil: [ '(unknown)' ]).
			items add: 'Package' -> (packageName ifNil: [ '(unknown)' ]).
			self isCpe ifTrue: [
				items add: 'CPE Vendor' -> (self cpeVendor ifNil: [ '?' ]).
				items add: 'CPE Product' -> (self cpeProduct ifNil: [ '?' ]).
				items add: 'CPE Version' -> (self cpeVersion ifNil: [ '*' ]) ].
			items add: 'Versions' -> self versionRangeSummary.
			self advisorySourceUrl ifNotNil: [ :url |
				items add: 'Advisory source' -> url ].
			vulnerable ifNotNil: [
				items add: 'Vulnerable?' ->
					(vulnerable = true ifTrue: [ 'yes' ] ifFalse: [ 'no' ]) ].
			configurationIndex ifNotNil: [
				items add: 'NVD configuration' ->
					('config[' , configurationIndex printString , '] / node[' , (nodeIndex ifNil: [ '?' ]) printString , '] (',
						(nodeOperator ifNil: [ 'OR' ]) , ')') ].
			matchCriteriaId ifNotNil: [
				items add: 'Match criteria ID' -> matchCriteriaId ].
			items ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'gt - views' }
Gt4SecurityAffectedEntry >> gtVanirSignaturesFor: aView [
	<gtView>
	(vanirSignatures isNil or: [ vanirSignatures isEmpty ]) ifTrue: [ ^ aView empty ].
	^ aView forward
		title: 'Vanir signatures';
		priority: 3;
		object: [ vanirSignatures ];
		view: #gtSignaturesFor:
]

{ #category : 'derived' }
Gt4SecurityAffectedEntry >> isCpe [
	"True if this entry's package name is a CPE 2.3 identifier. CPE is an identifier scheme (NVD uses it for OS, applications, and hardware) — orthogonal to OSV-style package ecosystems."
	^ packageName notNil and: [ packageName beginsWith: 'cpe:' ]
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> matchCriteriaId [
	^ matchCriteriaId
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> matchCriteriaId: aString [
	matchCriteriaId := aString
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> nodeIndex [
	^ nodeIndex
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> nodeIndex: anInteger [
	nodeIndex := anInteger
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> nodeOperator [
	^ nodeOperator
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> nodeOperator: aString [
	nodeOperator := aString
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> packageName [
	^ packageName
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> packageName: aString [
	packageName := aString
]

{ #category : 'printing' }
Gt4SecurityAffectedEntry >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (';
		nextPutAll: (ecosystem ifNil: [ '?' ]);
		nextPutAll: ': ';
		nextPutAll: self displayName;
		nextPutAll: ')'
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> ranges [
	^ ranges ifNil: [ #() ]
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> ranges: anArray [
	ranges := anArray
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> rawDict: aDictionary [
	rawDict := aDictionary
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> spl [
	spl ifNil: [
		rawDict ifNotNil: [
			spl := (rawDict at: 'ecosystem_specific' ifAbsent: [ Dictionary new ])
				at: 'spl' ifAbsent: [ nil ] ] ].
	^ spl
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> spl: aString [
	spl := aString
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> vanirSignatures [
	"Lazily parse from rawDict so instances created before ecosystem_specific was modeled still work."
	vanirSignatures ifNil: [
		rawDict ifNotNil: [
			| es raw |
			es := rawDict at: 'ecosystem_specific' ifAbsent: [ Dictionary new ].
			raw := es at: 'vanir_signatures' ifAbsent: [ #() ].
			vanirSignatures := Gt4SecurityVanirSignatureGroup withAll:
				(raw collect: [ :each | Gt4SecurityVanirSignature fromDictionary: each ]) ] ].
	^ vanirSignatures
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> vanirSignatures: aGroup [
	vanirSignatures := aGroup
]

{ #category : 'querying' }
Gt4SecurityAffectedEntry >> versionRangeSummary [
	"Human-readable version constraint summary.
	For npm/GHSA-style OSV entries, the real payload is in `ranges` (introduced/fixed events) — prefer it over the sparse `versions` array."

	self ranges ifNotEmpty: [
		^ '; ' join: (self ranges collect: [ :r | r summary ]) ].

	(versions isNil or: [ versions isEmpty ]) ifTrue: [
		"NVD cpeMatch with no range bounds: the CPE criteria's own version field is the target.
		'*' means any version; anything else means that specific version only."
		self isCpe ifTrue: [
			| cv |
			cv := self cpeVersion.
			(cv isNil or: [ cv = '*' or: [ cv = '-' ] ]) ifTrue: [ ^ '(all versions)' ].
			^ '= ' , cv ].
		^ '(all versions)' ].

	"NVD-style: constraint strings start with < or > (e.g., '>= 1.0', '< 2.0')."
	(versions first isString and: [
		(versions first beginsWith: '<') or: [ versions first beginsWith: '>' ] ])
			ifTrue: [ ^ ', ' join: versions ].

	"OSV-style: plain version numbers — list them, truncating if long."
	versions size <= 5 ifTrue: [ ^ ', ' join: (versions collect: [ :v | v asString ]) ].
	^ String streamContents: [ :s |
		s << (', ' join: ((versions first: 5) collect: [ :v | v asString ])).
		s << ' (+'.
		s print: versions size - 5.
		s << ' more)' ]
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> versions [
	^ versions
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> versions: anArrayOrCollection [
	versions := anArrayOrCollection
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> vulnerable [
	^ vulnerable
]

{ #category : 'accessing' }
Gt4SecurityAffectedEntry >> vulnerable: aBoolean [
	vulnerable := aBoolean
]
