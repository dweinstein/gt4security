"
N-way comparison of {{gtClass:Gt4SecurityCvssVector}} instances. Useful for:
- Comparing the same logical vulnerability scored across V2, V3.1, V4.0
- Comparing two CVEs to see which is worse and why

Construct via:
- `compare:with:` — 2-way with auto labels
- `compareAll:` — n-way with custom label -> vector associations
- `fromVectorStrings:` — convenience that parses each string

GT views:
- Score chart (Mondrian with colored severity bars, click a bar to drill into the vector)
- Differences (only metrics that diverge; rows spawn Gt4SecurityCvssMetricComparison)
- All metrics (full grid with != flags; rows spawn Gt4SecurityCvssMetricComparison)
- Vector diff (GT-native TextDiffBuilder, 2-way only)
"
Class {
	#name : 'Gt4SecurityCvssComparison',
	#superclass : 'Object',
	#instVars : [
		'entries'
	],
	#category : 'Gt4Security-CVSS',
	#package : 'Gt4Security',
	#tag : 'CVSS'
}

{ #category : 'instance creation' }
Gt4SecurityCvssComparison class >> compare: aVector with: anotherVector [
	"Two-way comparison. Labels default to the CVSS version."
	^ self compareAll: {
		('v' , aVector version) -> aVector.
		('v' , anotherVector version) -> anotherVector }
]

{ #category : 'instance creation' }
Gt4SecurityCvssComparison class >> compareAll: anOrderedCollectionOfAssociations [
	"N-way comparison. Each association is label -> Gt4SecurityCvssVector."
	^ self new entries: anOrderedCollectionOfAssociations asOrderedCollection
]

{ #category : 'instance creation' }
Gt4SecurityCvssComparison class >> fromVectorStrings: anOrderedCollectionOfAssociations [
	"Convenience: label -> vectorString pairs. Parses each."
	^ self compareAll: (anOrderedCollectionOfAssociations collect: [ :assoc |
		assoc key -> (Gt4SecurityCvssVector fromString: assoc value) ])
]

{ #category : 'derived' }
Gt4SecurityCvssComparison >> allMetricAbbreviations [
	"Union of all metric abbreviations across all vectors, in encounter order."
	| seen result |
	seen := Set new.
	result := OrderedCollection new.
	entries do: [ :e |
		e value metrics do: [ :m |
			(seen includes: m abbreviation) ifFalse: [
				seen add: m abbreviation.
				result add: m abbreviation ] ] ].
	^ result
]

{ #category : 'private' }
Gt4SecurityCvssComparison >> colorForSeverity: aLabel [
	aLabel = 'CRITICAL' ifTrue: [ ^ Color r: 0.7 g: 0.0 b: 0.0 ].
	aLabel = 'HIGH' ifTrue: [ ^ Color r: 0.9 g: 0.3 b: 0.0 ].
	aLabel = 'MEDIUM' ifTrue: [ ^ Color r: 0.9 g: 0.7 b: 0.0 ].
	aLabel = 'LOW' ifTrue: [ ^ Color r: 0.2 g: 0.7 b: 0.2 ].
	^ Color gray
]

{ #category : 'accessing' }
Gt4SecurityCvssComparison >> entries [
	^ entries
]

{ #category : 'accessing' }
Gt4SecurityCvssComparison >> entries: anOrderedCollection [
	entries := anOrderedCollection
]

{ #category : 'gt - views' }
Gt4SecurityCvssComparison >> gtDifferencesFor: aView [
	<gtView>
	| view |
	view := aView columnedList
		title: 'Differences';
		priority: 2;
		items: [ self metricComparisons select: [ :mc | mc differs ] ].
	view column: 'Metric' text: [ :mc | mc fullName ] weight: 2.
	entries doWithIndex: [ :e :i |
		view column: e key text: [ :mc | (mc valuesByLabel at: i) value ] weight: 1 ].
	view send: [ :mc | mc ].
	^ view
]

{ #category : 'printing' }
Gt4SecurityCvssComparison >> gtDisplayOn: aStream [
	aStream nextPutAll: 'Comparing: '.
	entries
		do: [ :e | aStream nextPutAll: e key ]
		separatedBy: [ aStream nextPutAll: ' vs ' ]
]

{ #category : 'gt - views' }
Gt4SecurityCvssComparison >> gtMetricDiffFor: aView [
	<gtView>
	| view |
	view := aView columnedList
		title: 'All metrics';
		priority: 3;
		items: [ self metricComparisons ].
	view column: 'Metric' text: [ :mc | mc fullName ] weight: 2.
	entries doWithIndex: [ :e :i |
		view column: e key text: [ :mc | (mc valuesByLabel at: i) value ] weight: 0.8 ].
	view column: 'Differs?' text: [ :mc | mc differs ifTrue: [ '!=' ] ifFalse: [ '' ] ] weight: 0.5.
	view send: [ :mc | mc ].
	^ view
]

{ #category : 'gt - views' }
Gt4SecurityCvssComparison >> gtScoreChartFor: aView [
	<gtView>
	^ aView mondrian
		title: 'Score chart';
		priority: 1;
		painting: [ :m |
			entries do: [ :e |
				m nodes
					stencil: [ :vec |
						| color barWidth label assoc |
						color := self colorForSeverity: vec severityLabel.
						barWidth := (vec baseScore * 40) rounded max: 4.
						"find the label for this vector"
						assoc := entries detect: [ :a | a value == vec ].
						label := assoc key , '  ' , vec baseScore printString , ' ' , vec severityLabel.
						BrHorizontalPane new
							hMatchParent; vFitContent;
							addChild: (BlElement new
								background: color;
								constraintsDo: [ :c | c horizontal exact: barWidth. c vertical exact: 24 ]);
							addChild: (BrLabel new
								aptitude: (BrGlamorousLabelAptitude new fontSize: 12);
								text: label;
								margin: (BlInsets left: 8)) ];
					with: { e value } ].
			m layout vertical ]
]

{ #category : 'gt - views' }
Gt4SecurityCvssComparison >> gtStringDiffFor: aView [
	<gtView>
	entries size = 2 ifFalse: [ ^ aView empty ].
	^ aView explicit
		title: 'Vector diff';
		priority: 2;
		stencil: [
			| v1 v2 diff |
			v1 := entries first value vectorString copyReplaceAll: '/' with: String cr.
			v2 := entries second value vectorString copyReplaceAll: '/' with: String cr.
			diff := TextDiffBuilder from: v1 to: v2.
			GtDiffElement onDiff: diff ]
]

{ #category : 'derived' }
Gt4SecurityCvssComparison >> maxScore [
	^ (entries collect: [ :e | e value baseScore ]) max
]

{ #category : 'derived' }
Gt4SecurityCvssComparison >> metricComparisons [
	"Build a Gt4SecurityCvssMetricComparison per metric across all entries."
	| names |
	names := Gt4SecurityCvssVector metricFullNames.
	^ self allMetricAbbreviations collect: [ :abbr |
		| values |
		values := entries collect: [ :e |
			| metric |
			metric := e value metrics detect: [ :m | m abbreviation = abbr ] ifNone: [ nil ].
			e key -> (metric ifNil: [ '—' ] ifNotNil: [ metric value ]) ].
		Gt4SecurityCvssMetricComparison
			abbreviation: abbr
			fullName: (names at: abbr ifAbsent: [ abbr ])
			valuesByLabel: values ]
]

{ #category : 'printing' }
Gt4SecurityCvssComparison >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (';
		nextPutAll: (', ' join: (entries collect: [ :e | e key ]));
		nextPutAll: ')'
]
