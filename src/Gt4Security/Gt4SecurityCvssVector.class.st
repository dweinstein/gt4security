"
Abstract base for CVSS vector domain objects. Parses any CVSS vector string (V2, V3.0, V3.1, V4.0) via `fromString:` and dispatches to the right subclass ({{gtClass:Gt4SecurityCvssV2Vector}}, {{gtClass:Gt4SecurityCvssV3Vector}}, {{gtClass:Gt4SecurityCvssV4Vector}}) based on the prefix.

Each subclass:
- Stores metric values as typed ivars
- Computes its own baseScore using the version-specific formula
- Has Magritte descriptions so the vector is its own editor (Edit tab appears automatically in the inspector)
- Rebuilds vectorString from ivars on Magritte accept and spawns a refreshed vector

Common accessors: `version`, `vectorString`, `baseScore`, `severityLabel`, `metrics` (Gt4SecurityCvssMetric collection).

Scoring formulas sourced from FIRST.org specifications — see known-answer tests in {{gtClass:Gt4SecurityCvssExamples}}.
"
Class {
	#name : 'Gt4SecurityCvssVector',
	#superclass : 'Object',
	#instVars : [
		'version',
		'vectorString',
		'metrics',
		'baseScore'
	],
	#category : 'Gt4Security-CVSS',
	#package : 'Gt4Security',
	#tag : 'CVSS'
}

{ #category : 'instance creation' }
Gt4SecurityCvssVector class >> fromString: aVectorString [
	"Parse a CVSS vector string and instantiate the right version-specific subclass."
	| vec subclass |
	subclass := (aVectorString beginsWith: 'CVSS:4.0/')
		ifTrue: [ Gt4SecurityCvssV4Vector ]
		ifFalse: [ (aVectorString beginsWith: 'CVSS:3.')
			ifTrue: [ Gt4SecurityCvssV3Vector ]
			ifFalse: [ Gt4SecurityCvssV2Vector ] ].
	vec := subclass new.
	vec vectorString: aVectorString.
	vec parse.
	vec computeBaseScore.
	^ vec
]

{ #category : 'metric names' }
Gt4SecurityCvssVector class >> metricFullNames [
	"Abbreviation → full human-readable name."
	^ Dictionary new
		at: 'AV' put: 'Attack Vector';
		at: 'AC' put: 'Attack Complexity';
		at: 'Au' put: 'Authentication';
		at: 'PR' put: 'Privileges Required';
		at: 'UI' put: 'User Interaction';
		at: 'S' put: 'Scope';
		at: 'C' put: 'Confidentiality';
		at: 'I' put: 'Integrity';
		at: 'A' put: 'Availability';
		at: 'AT' put: 'Attack Requirements';
		at: 'VC' put: 'Vulnerable Confidentiality';
		at: 'VI' put: 'Vulnerable Integrity';
		at: 'VA' put: 'Vulnerable Availability';
		at: 'SC' put: 'Subsequent Confidentiality';
		at: 'SI' put: 'Subsequent Integrity';
		at: 'SA' put: 'Subsequent Availability';
		at: 'E' put: 'Exploit Maturity';
		at: 'CR' put: 'Confidentiality Requirement';
		at: 'IR' put: 'Integrity Requirement';
		at: 'AR' put: 'Availability Requirement';
		yourself
]

{ #category : 'scoring - v4 tables' }
Gt4SecurityCvssVector class >> v4DistanceMap [
	"Per-metric severity distance values (step = 0.1). Higher = further from worst case."
	| d |
	d := Dictionary new.
	d at: 'AV' put: { 'N'->0. 'A'->1. 'L'->2. 'P'->3 } asDictionary.
	d at: 'PR' put: { 'N'->0. 'L'->1. 'H'->2 } asDictionary.
	d at: 'UI' put: { 'N'->0. 'P'->1. 'A'->2 } asDictionary.
	d at: 'AC' put: { 'L'->0. 'H'->1 } asDictionary.
	d at: 'AT' put: { 'N'->0. 'P'->1 } asDictionary.
	d at: 'VC' put: { 'H'->0. 'L'->1. 'N'->2 } asDictionary.
	d at: 'VI' put: { 'H'->0. 'L'->1. 'N'->2 } asDictionary.
	d at: 'VA' put: { 'H'->0. 'L'->1. 'N'->2 } asDictionary.
	d at: 'SC' put: { 'H'->1. 'L'->2. 'N'->3 } asDictionary.
	d at: 'SI' put: { 'S'->0. 'H'->1. 'L'->2. 'N'->3 } asDictionary.
	d at: 'SA' put: { 'S'->0. 'H'->1. 'L'->2. 'N'->3 } asDictionary.
	d at: 'CR' put: { 'H'->0. 'M'->1. 'L'->2 } asDictionary.
	d at: 'IR' put: { 'H'->0. 'M'->1. 'L'->2 } asDictionary.
	d at: 'AR' put: { 'H'->0. 'M'->1. 'L'->2 } asDictionary.
	d at: 'E' put: { 'A'->0. 'P'->1. 'U'->2 } asDictionary.
	^ d
]

{ #category : 'scoring - v4 tables' }
Gt4SecurityCvssVector class >> v4LookupTable [
	"MacroVector (6-digit string) → base score. 312 entries from FIRST spec."
	^ Dictionary new
		at: '000000' put: 10.0; at: '000001' put: 9.9; at: '000010' put: 9.8; at: '000011' put: 9.5;
		at: '000020' put: 9.5; at: '000021' put: 9.2; at: '000100' put: 10.0; at: '000101' put: 9.6;
		at: '000110' put: 9.3; at: '000111' put: 8.7; at: '000120' put: 9.1; at: '000121' put: 8.1;
		at: '000200' put: 9.3; at: '000201' put: 9.0; at: '000210' put: 8.9; at: '000211' put: 8.0;
		at: '000220' put: 8.1; at: '000221' put: 6.8;
		at: '001000' put: 9.8; at: '001001' put: 9.5; at: '001010' put: 9.5; at: '001011' put: 9.2;
		at: '001020' put: 9.0; at: '001021' put: 8.4; at: '001100' put: 9.3; at: '001101' put: 9.2;
		at: '001110' put: 8.9; at: '001111' put: 8.1; at: '001120' put: 8.1; at: '001121' put: 6.5;
		at: '001200' put: 8.8; at: '001201' put: 8.0; at: '001210' put: 7.8; at: '001211' put: 7.0;
		at: '001220' put: 6.9; at: '001221' put: 4.8;
		at: '002001' put: 9.2; at: '002011' put: 8.2; at: '002021' put: 7.2;
		at: '002101' put: 7.9; at: '002111' put: 6.9; at: '002121' put: 5.0;
		at: '002201' put: 6.9; at: '002211' put: 5.5; at: '002221' put: 2.7;
		at: '010000' put: 9.9; at: '010001' put: 9.7; at: '010010' put: 9.5; at: '010011' put: 9.2;
		at: '010020' put: 9.2; at: '010021' put: 8.5; at: '010100' put: 9.5; at: '010101' put: 9.1;
		at: '010110' put: 9.0; at: '010111' put: 8.3; at: '010120' put: 8.4; at: '010121' put: 7.1;
		at: '010200' put: 9.2; at: '010201' put: 8.1; at: '010210' put: 8.2; at: '010211' put: 7.1;
		at: '010220' put: 7.2; at: '010221' put: 5.3;
		at: '011000' put: 9.5; at: '011001' put: 9.3; at: '011010' put: 9.2; at: '011011' put: 8.5;
		at: '011020' put: 8.5; at: '011021' put: 7.3; at: '011100' put: 9.2; at: '011101' put: 8.2;
		at: '011110' put: 8.0; at: '011111' put: 7.2; at: '011120' put: 7.0; at: '011121' put: 5.9;
		at: '011200' put: 8.4; at: '011201' put: 7.0; at: '011210' put: 7.1; at: '011211' put: 5.2;
		at: '011220' put: 5.0; at: '011221' put: 3.0;
		at: '012001' put: 8.6; at: '012011' put: 7.5; at: '012021' put: 5.2;
		at: '012101' put: 7.1; at: '012111' put: 5.2; at: '012121' put: 2.9;
		at: '012201' put: 6.3; at: '012211' put: 2.9; at: '012221' put: 1.7;
		at: '100000' put: 9.8; at: '100001' put: 9.5; at: '100010' put: 9.4; at: '100011' put: 8.7;
		at: '100020' put: 9.1; at: '100021' put: 8.1; at: '100100' put: 9.4; at: '100101' put: 8.9;
		at: '100110' put: 8.6; at: '100111' put: 7.4; at: '100120' put: 7.7; at: '100121' put: 6.4;
		at: '100200' put: 8.7; at: '100201' put: 7.5; at: '100210' put: 7.4; at: '100211' put: 6.3;
		at: '100220' put: 6.3; at: '100221' put: 4.9;
		at: '101000' put: 9.4; at: '101001' put: 8.9; at: '101010' put: 8.8; at: '101011' put: 7.7;
		at: '101020' put: 7.6; at: '101021' put: 6.7; at: '101100' put: 8.6; at: '101101' put: 7.6;
		at: '101110' put: 7.4; at: '101111' put: 5.8; at: '101120' put: 5.9; at: '101121' put: 5.0;
		at: '101200' put: 7.2; at: '101201' put: 5.7; at: '101210' put: 5.7; at: '101211' put: 5.2;
		at: '101220' put: 5.2; at: '101221' put: 2.5;
		at: '102001' put: 8.3; at: '102011' put: 7.0; at: '102021' put: 5.4;
		at: '102101' put: 6.5; at: '102111' put: 5.8; at: '102121' put: 2.6;
		at: '102201' put: 5.3; at: '102211' put: 2.1; at: '102221' put: 1.3;
		at: '110000' put: 9.5; at: '110001' put: 9.0; at: '110010' put: 8.8; at: '110011' put: 7.6;
		at: '110020' put: 7.6; at: '110021' put: 7.0; at: '110100' put: 9.0; at: '110101' put: 7.7;
		at: '110110' put: 7.5; at: '110111' put: 6.2; at: '110120' put: 6.1; at: '110121' put: 5.3;
		at: '110200' put: 7.7; at: '110201' put: 6.6; at: '110210' put: 6.8; at: '110211' put: 5.9;
		at: '110220' put: 5.2; at: '110221' put: 3.0;
		at: '111000' put: 8.9; at: '111001' put: 7.8; at: '111010' put: 7.6; at: '111011' put: 6.7;
		at: '111020' put: 6.2; at: '111021' put: 5.8; at: '111100' put: 7.4; at: '111101' put: 5.9;
		at: '111110' put: 5.7; at: '111111' put: 5.7; at: '111120' put: 4.7; at: '111121' put: 2.3;
		at: '111200' put: 6.1; at: '111201' put: 5.2; at: '111210' put: 5.7; at: '111211' put: 2.9;
		at: '111220' put: 2.4; at: '111221' put: 1.6;
		at: '112001' put: 7.1; at: '112011' put: 5.9; at: '112021' put: 3.0;
		at: '112101' put: 5.8; at: '112111' put: 2.6; at: '112121' put: 1.5;
		at: '112201' put: 2.3; at: '112211' put: 1.3; at: '112221' put: 0.6;
		at: '200000' put: 9.3; at: '200001' put: 8.7; at: '200010' put: 8.6; at: '200011' put: 7.2;
		at: '200020' put: 7.5; at: '200021' put: 5.8; at: '200100' put: 8.6; at: '200101' put: 7.4;
		at: '200110' put: 7.4; at: '200111' put: 6.1; at: '200120' put: 5.6; at: '200121' put: 3.4;
		at: '200200' put: 7.0; at: '200201' put: 5.4; at: '200210' put: 5.2; at: '200211' put: 4.0;
		at: '200220' put: 4.0; at: '200221' put: 2.2;
		at: '201000' put: 8.5; at: '201001' put: 7.5; at: '201010' put: 7.4; at: '201011' put: 5.5;
		at: '201020' put: 6.2; at: '201021' put: 5.1; at: '201100' put: 7.2; at: '201101' put: 5.7;
		at: '201110' put: 5.5; at: '201111' put: 4.1; at: '201120' put: 4.6; at: '201121' put: 1.9;
		at: '201200' put: 5.3; at: '201201' put: 3.6; at: '201210' put: 3.4; at: '201211' put: 1.9;
		at: '201220' put: 1.9; at: '201221' put: 0.8;
		at: '202001' put: 6.4; at: '202011' put: 5.1; at: '202021' put: 2.0;
		at: '202101' put: 4.7; at: '202111' put: 2.1; at: '202121' put: 1.1;
		at: '202201' put: 2.4; at: '202211' put: 0.9; at: '202221' put: 0.4;
		at: '210000' put: 8.8; at: '210001' put: 7.5; at: '210010' put: 7.3; at: '210011' put: 5.3;
		at: '210020' put: 6.0; at: '210021' put: 5.0; at: '210100' put: 7.3; at: '210101' put: 5.5;
		at: '210110' put: 5.9; at: '210111' put: 4.0; at: '210120' put: 4.1; at: '210121' put: 2.0;
		at: '210200' put: 5.4; at: '210201' put: 4.3; at: '210210' put: 4.5; at: '210211' put: 2.2;
		at: '210220' put: 2.0; at: '210221' put: 1.1;
		at: '211000' put: 7.5; at: '211001' put: 5.5; at: '211010' put: 5.8; at: '211011' put: 4.5;
		at: '211020' put: 4.0; at: '211021' put: 2.1; at: '211100' put: 6.1; at: '211101' put: 5.1;
		at: '211110' put: 4.8; at: '211111' put: 1.8; at: '211120' put: 2.0; at: '211121' put: 0.9;
		at: '211200' put: 4.6; at: '211201' put: 1.8; at: '211210' put: 1.7; at: '211211' put: 0.7;
		at: '211220' put: 0.8; at: '211221' put: 0.2;
		at: '212001' put: 5.3; at: '212011' put: 2.4; at: '212021' put: 1.4;
		at: '212101' put: 2.4; at: '212111' put: 1.2; at: '212121' put: 0.5;
		at: '212201' put: 1.0; at: '212211' put: 0.3; at: '212221' put: 0.1;
		yourself
]

{ #category : 'accessing' }
Gt4SecurityCvssVector >> baseScore [
	^ baseScore
]

{ #category : 'scoring' }
Gt4SecurityCvssVector >> computeBaseScore [
	"Dispatch to version-specific scoring."
	version = '2.0' ifTrue: [ ^ baseScore := self computeV2Score ].
	(version = '3.0' or: [ version = '3.1' ]) ifTrue: [ ^ baseScore := self computeV3Score ].
	version = '4.0' ifTrue: [ ^ baseScore := self computeV4Score ].
	baseScore := nil
]

{ #category : 'scoring - v2' }
Gt4SecurityCvssVector >> computeV2Score [
	"CVSS v2 base score. Standard rounding to 1 decimal."
	| av ac au cVal iVal aVal impact exploitability fImpact raw |
	av := self v2Weight: 'AV' value: (self metricValue: 'AV').
	ac := self v2Weight: 'AC' value: (self metricValue: 'AC').
	au := self v2Weight: 'Au' value: (self metricValue: 'Au').
	cVal := self v2Weight: 'C' value: (self metricValue: 'C').
	iVal := self v2Weight: 'I' value: (self metricValue: 'I').
	aVal := self v2Weight: 'A' value: (self metricValue: 'A').
	impact := 10.41 * (1 - ((1 - cVal) * (1 - iVal) * (1 - aVal))).
	exploitability := 20 * av * ac * au.
	fImpact := impact = 0 ifTrue: [ 0 ] ifFalse: [ 1.176 ].
	raw := ((0.6 * impact) + (0.4 * exploitability) - 1.5) * fImpact.
	^ (raw * 10) rounded / 10.0
]

{ #category : 'scoring - v3' }
Gt4SecurityCvssVector >> computeV3Score [
	"CVSS v3.0/v3.1 base score. Uses Roundup (ceiling to nearest 0.1)."
	| av ac pr ui scope cVal iVal aVal iss impact exploitability raw |
	scope := self metricValue: 'S'.
	av := self v3Weight: 'AV'.
	ac := self v3Weight: 'AC'.
	pr := self v3PrWeight: (self metricValue: 'PR') scope: scope.
	ui := self v3Weight: 'UI'.
	cVal := self v3Weight: 'C'.
	iVal := self v3Weight: 'I'.
	aVal := self v3Weight: 'A'.
	iss := 1 - ((1 - cVal) * (1 - iVal) * (1 - aVal)).
	impact := scope = 'U'
		ifTrue: [ 6.42 * iss ]
		ifFalse: [ 7.52 * (iss - 0.029) - (3.25 * ((iss - 0.02) raisedTo: 15)) ].
	impact <= 0 ifTrue: [ ^ 0.0 ].
	exploitability := 8.22 * av * ac * pr * ui.
	raw := scope = 'U'
		ifTrue: [ (impact + exploitability) min: 10 ]
		ifFalse: [ (1.08 * (impact + exploitability)) min: 10 ].
	^ self roundUp: raw
]

{ #category : 'scoring - v4' }
Gt4SecurityCvssVector >> computeV4Score [
	"CVSS v4.0 base score via MacroVector lookup + interpolation. Standard rounding."
	| mv lookupScore |
	"All impact metrics zero → score 0"
	(#('VC' 'VI' 'VA' 'SC' 'SI' 'SA') allSatisfy: [ :m | (self metricValue: m) = 'N' ])
		ifTrue: [ ^ 0.0 ].
	mv := self v4MacroVector.
	lookupScore := self class v4LookupTable at: mv ifAbsent: [ ^ nil ].
	^ self v4InterpolateFrom: mv score: lookupScore
]

{ #category : 'printing' }
Gt4SecurityCvssVector >> gtDisplayOn: aStream [
	aStream
		nextPutAll: self severityLabel;
		nextPut: $ ;
		print: (baseScore ifNil: [ 0 ]);
		nextPutAll: ' (CVSS v';
		nextPutAll: (version ifNil: [ '?' ]);
		nextPut: $)
]

{ #category : 'gt - views' }
Gt4SecurityCvssVector >> gtMetricsFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Metrics';
		priority: 2;
		items: [ metrics ];
		column: 'Metric' text: [ :m | m fullName ] weight: 2;
		column: 'Abbr' text: [ :m | m abbreviation ] weight: 0.7;
		column: 'Value' text: [ :m | m value ] weight: 0.5
]

{ #category : 'gt - views' }
Gt4SecurityCvssVector >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 1;
		items: [ {
			'Version' -> ('CVSS v' , version).
			'Base score' -> (baseScore ifNil: [ '?' ] ifNotNil: [ baseScore printShowingDecimalPlaces: 1 ]).
			'Severity' -> self severityLabel.
			'Vector' -> vectorString } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'magritte' }
Gt4SecurityCvssVector >> magritteAcceptAction [
	<magritteActionDescription>
	"Shared by all subclasses: rebuild vector string from edited metric ivars, re-parse, spawn a fresh vector."
	^ super magritteAcceptAction
		label: 'Calculate';
		onSuccessCallback: (GtMagritteCallback new
			action: [ :aModel :aButton :aMemento :aDescription |
				| newVec |
				aMemento commit.
				newVec := Gt4SecurityCvssVector fromString: self buildVectorString.
				aButton phlow spawnObject: newVec ]);
		beEnabledOnValidOverallStatus
]

{ #category : 'private' }
Gt4SecurityCvssVector >> metricValue: anAbbreviation [
	"Look up the value of a metric by its abbreviation."
	^ (metrics detect: [ :m | m abbreviation = anAbbreviation ] ifNone: [ nil ])
		ifNotNil: [ :m | m value ]
		ifNil: [ nil ]
]

{ #category : 'accessing' }
Gt4SecurityCvssVector >> metrics [
	^ metrics
]

{ #category : 'parsing' }
Gt4SecurityCvssVector >> parse [
	"Detect version from prefix and parse metric key:value pairs."
	| body pairs names |
	(vectorString beginsWith: 'CVSS:4.0/')
		ifTrue: [ version := '4.0'. body := vectorString allButFirst: 9 ]
		ifFalse: [ (vectorString beginsWith: 'CVSS:3.1/')
			ifTrue: [ version := '3.1'. body := vectorString allButFirst: 9 ]
			ifFalse: [ (vectorString beginsWith: 'CVSS:3.0/')
				ifTrue: [ version := '3.0'. body := vectorString allButFirst: 9 ]
				ifFalse: [ version := '2.0'. body := vectorString ] ] ].
	names := self class metricFullNames.
	pairs := body splitOn: $/.
	metrics := pairs collect: [ :pair |
		| parts |
		parts := pair splitOn: $:.
		Gt4SecurityCvssMetric new
			abbreviation: parts first;
			value: parts second;
			fullName: (names at: parts first ifAbsent: [ parts first ]);
			yourself ]
]

{ #category : 'printing' }
Gt4SecurityCvssVector >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (v';
		nextPutAll: version;
		nextPutAll: ' ';
		nextPutAll: self severityLabel;
		nextPutAll: ' ';
		print: baseScore;
		nextPutAll: ')'
]

{ #category : 'scoring - util' }
Gt4SecurityCvssVector >> roundUp: aNumber [
	"CVSS v3 Roundup: ceiling to nearest 0.1 (NOT standard rounding).
	Roundup(x): i = round(x * 100000); if i % 10000 == 0 then i/100000.0 else (floor(i/10000)+1)/10.0"
	| i |
	i := (aNumber * 100000) rounded.
	(i \\ 10000) = 0
		ifTrue: [ ^ i / 100000.0 ]
		ifFalse: [ ^ ((i // 10000) + 1) / 10.0 ]
]

{ #category : 'derived' }
Gt4SecurityCvssVector >> severityLabel [
	"CVSS severity label from the base score."
	baseScore ifNil: [ ^ 'UNKNOWN' ].
	baseScore = 0.0 ifTrue: [ ^ version = '2.0' ifTrue: [ 'LOW' ] ifFalse: [ 'NONE' ] ].
	baseScore <= 3.9 ifTrue: [ ^ 'LOW' ].
	baseScore <= 6.9 ifTrue: [ ^ 'MEDIUM' ].
	baseScore <= 8.9 ifTrue: [ ^ 'HIGH' ].
	^ 'CRITICAL'
]

{ #category : 'scoring - v2' }
Gt4SecurityCvssVector >> v2Weight: anAbbreviation value: aValueString [
	"CVSS v2 numeric weight lookup."
	| map |
	map := Dictionary new
		at: 'AV' put: { 'L'->0.395. 'A'->0.646. 'N'->1.0 } asDictionary;
		at: 'AC' put: { 'H'->0.35. 'M'->0.61. 'L'->0.71 } asDictionary;
		at: 'Au' put: { 'M'->0.45. 'S'->0.56. 'N'->0.704 } asDictionary;
		at: 'C' put: { 'N'->0.0. 'P'->0.275. 'C'->0.660 } asDictionary;
		at: 'I' put: { 'N'->0.0. 'P'->0.275. 'C'->0.660 } asDictionary;
		at: 'A' put: { 'N'->0.0. 'P'->0.275. 'C'->0.660 } asDictionary;
		yourself.
	^ (map at: anAbbreviation) at: aValueString
]

{ #category : 'scoring - v3' }
Gt4SecurityCvssVector >> v3PrWeight: aPrValue scope: aScopeValue [
	"PR weight depends on Scope in CVSS v3."
	aScopeValue = 'U' ifTrue: [
		^ { 'N'->0.85. 'L'->0.62. 'H'->0.27 } asDictionary at: aPrValue ].
	"Scope = Changed"
	^ { 'N'->0.85. 'L'->0.68. 'H'->0.50 } asDictionary at: aPrValue
]

{ #category : 'scoring - v3' }
Gt4SecurityCvssVector >> v3Weight: anAbbreviation [
	"CVSS v3.0/v3.1 numeric weight (except PR which depends on Scope)."
	| map |
	map := Dictionary new
		at: 'AV' put: { 'N'->0.85. 'A'->0.62. 'L'->0.55. 'P'->0.20 } asDictionary;
		at: 'AC' put: { 'L'->0.77. 'H'->0.44 } asDictionary;
		at: 'UI' put: { 'N'->0.85. 'R'->0.62 } asDictionary;
		at: 'C' put: { 'H'->0.56. 'L'->0.22. 'N'->0.0 } asDictionary;
		at: 'I' put: { 'H'->0.56. 'L'->0.22. 'N'->0.0 } asDictionary;
		at: 'A' put: { 'H'->0.56. 'L'->0.22. 'N'->0.0 } asDictionary;
		yourself.
	^ (map at: anAbbreviation) at: (self metricValue: anAbbreviation)
]

{ #category : 'scoring - v4' }
Gt4SecurityCvssVector >> v4ComputeDistancesInto: anArray forMacroVector: aMv [
	"Compute per-EQ severity distance sums using per-metric distance values."
	| d |
	d := self class v4DistanceMap.
	"EQ1 = AV + PR + UI"
	anArray at: 1 put:
		((d at: 'AV') at: (self metricValue: 'AV'))
		+ ((d at: 'PR') at: (self metricValue: 'PR'))
		+ ((d at: 'UI') at: (self metricValue: 'UI')).
	"EQ2 = AC + AT"
	anArray at: 2 put:
		((d at: 'AC') at: (self metricValue: 'AC'))
		+ ((d at: 'AT') at: (self metricValue: 'AT')).
	"EQ3+EQ6 = VC + VI + VA + CR + IR + AR"
	anArray at: 3 put:
		((d at: 'VC') at: (self metricValue: 'VC'))
		+ ((d at: 'VI') at: (self metricValue: 'VI'))
		+ ((d at: 'VA') at: (self metricValue: 'VA'))
		+ ((d at: 'CR') at: (self v4EffectiveValue: 'CR'))
		+ ((d at: 'IR') at: (self v4EffectiveValue: 'IR'))
		+ ((d at: 'AR') at: (self v4EffectiveValue: 'AR')).
	"EQ4 = SC + SI + SA"
	anArray at: 4 put:
		((d at: 'SC') at: (self metricValue: 'SC'))
		+ ((d at: 'SI') at: (self v4EffectiveValue: 'SI'))
		+ ((d at: 'SA') at: (self v4EffectiveValue: 'SA')).
	"EQ5 = 0 always"
	anArray at: 5 put: 0.
	"EQ6 handled with EQ3"
	anArray at: 6 put: 0
]

{ #category : 'scoring - v4' }
Gt4SecurityCvssVector >> v4EffectiveValue: anAbbreviation [
	"Return the metric value with V4 defaults applied (E→A, CR/IR/AR→H)."
	| val |
	val := self metricValue: anAbbreviation.
	val ifNotNil: [ ^ val ].
	anAbbreviation = 'E' ifTrue: [ ^ 'A' ].
	(#('CR' 'IR' 'AR') includes: anAbbreviation) ifTrue: [ ^ 'H' ].
	anAbbreviation = 'SI' ifTrue: [ ^ self metricValue: 'SI' ifNil: [ 'L' ] ].
	anAbbreviation = 'SA' ifTrue: [ ^ self metricValue: 'SA' ifNil: [ 'L' ] ].
	^ val
]

{ #category : 'scoring - v4' }
Gt4SecurityCvssVector >> v4InterpolateFrom: aMacroVector score: aLookupScore [
	"V4 interpolation: severity distance from highest-severity vector, interpolated toward next-lower MacroVector score."
	| table eqDigits availDist totalDist sumNorm cnt |
	table := self class v4LookupTable.
	eqDigits := aMacroVector asArray collect: [ :c | c digitValue ].
	availDist := Array new: 6 withAll: nil.
	totalDist := Array new: 6 withAll: 0.
	"For each EQ, find next-lower MacroVector."
	1 to: 6 do: [ :eq |
		| nextDigits nextMv nextScore |
		nextDigits := eqDigits copy.
		nextDigits at: eq put: (nextDigits at: eq) + 1.
		nextMv := String streamContents: [ :s | nextDigits do: [ :d | s print: d ] ].
		nextScore := table at: nextMv ifAbsent: [ nil ].
		nextScore ifNotNil: [ availDist at: eq put: aLookupScore - nextScore ] ].
	"Compute severity distance per EQ."
	self v4ComputeDistancesInto: totalDist forMacroVector: aMacroVector.
	"Mean normalized distance."
	sumNorm := 0.0. cnt := 0.
	1 to: 6 do: [ :eq |
		(availDist at: eq) ifNotNil: [ :ad |
			| maxDepth proportion |
			maxDepth := self v4MaxDepthForEq: eq level: (eqDigits at: eq).
			proportion := maxDepth > 0 ifTrue: [ (totalDist at: eq) / maxDepth ] ifFalse: [ 0 ].
			sumNorm := sumNorm + (ad * proportion).
			cnt := cnt + 1 ] ].
	cnt = 0 ifTrue: [ ^ aLookupScore ].
	^ ((aLookupScore - (sumNorm / cnt) max: 0.0) min: 10.0) roundTo: 0.1
]

{ #category : 'scoring - v4' }
Gt4SecurityCvssVector >> v4MacroVector [
	"Compute the 6-digit MacroVector string from metric values."
	| eq1 eq2 eq3 eq4 eq5 eq6 av pr ui ac at vc vi va sc si sa e cr ir ar |
	av := self metricValue: 'AV'. pr := self metricValue: 'PR'. ui := self metricValue: 'UI'.
	ac := self metricValue: 'AC'. at := self metricValue: 'AT'.
	vc := self metricValue: 'VC'. vi := self metricValue: 'VI'. va := self metricValue: 'VA'.
	sc := self metricValue: 'SC'. si := self v4EffectiveValue: 'SI'. sa := self v4EffectiveValue: 'SA'.
	e := self v4EffectiveValue: 'E'.
	cr := self v4EffectiveValue: 'CR'. ir := self v4EffectiveValue: 'IR'. ar := self v4EffectiveValue: 'AR'.
	"EQ1: AV/PR/UI"
	eq1 := (av = 'N' and: [ pr = 'N' and: [ ui = 'N' ] ])
		ifTrue: [ 0 ]
		ifFalse: [ ((av = 'N' or: [ pr = 'N' or: [ ui = 'N' ] ]) and: [ av ~= 'P' ])
			ifTrue: [ 1 ] ifFalse: [ 2 ] ].
	"EQ2: AC/AT"
	eq2 := (ac = 'L' and: [ at = 'N' ]) ifTrue: [ 0 ] ifFalse: [ 1 ].
	"EQ3: VC/VI/VA"
	eq3 := (vc = 'H' and: [ vi = 'H' ])
		ifTrue: [ 0 ]
		ifFalse: [ (vc = 'H' or: [ vi = 'H' or: [ va = 'H' ] ])
			ifTrue: [ 1 ] ifFalse: [ 2 ] ].
	"EQ4: SC/SI/SA"
	eq4 := (si = 'S' or: [ sa = 'S' ])
		ifTrue: [ 0 ]
		ifFalse: [ (sc = 'H' or: [ si = 'H' or: [ sa = 'H' ] ])
			ifTrue: [ 1 ] ifFalse: [ 2 ] ].
	"EQ5: E"
	eq5 := e = 'A' ifTrue: [ 0 ] ifFalse: [ e = 'P' ifTrue: [ 1 ] ifFalse: [ 2 ] ].
	"EQ6: CR/IR/AR combined with VC/VI/VA"
	eq6 := ((cr = 'H' and: [ vc = 'H' ]) or: [ (ir = 'H' and: [ vi = 'H' ]) or: [ ar = 'H' and: [ va = 'H' ] ] ])
		ifTrue: [ 0 ] ifFalse: [ 1 ].
	^ String streamContents: [ :s |
		s print: eq1; print: eq2; print: eq3; print: eq4; print: eq5; print: eq6 ]
]

{ #category : 'scoring - v4' }
Gt4SecurityCvssVector >> v4MaxDepthForEq: anEqIndex level: aLevel [
	"Max severity distance (as 0.1 steps) for a given EQ at a given level."
	| depths |
	depths := {
		"EQ1" { 0->1. 1->4. 2->5 } asDictionary.
		"EQ2" { 0->1. 1->2 } asDictionary.
		"EQ3+6" { 0->7. 1->8. 2->10 } asDictionary.
		"EQ4" { 0->6. 1->5. 2->4 } asDictionary.
		"EQ5" { 0->1. 1->1. 2->1 } asDictionary.
		"EQ6" { 0->1. 1->1 } asDictionary }.
	^ ((depths at: anEqIndex) at: aLevel ifAbsent: [ 1 ]) * 0.1
]

{ #category : 'accessing' }
Gt4SecurityCvssVector >> vectorString [
	^ vectorString
]

{ #category : 'accessing' }
Gt4SecurityCvssVector >> vectorString: aString [
	vectorString := aString
]

{ #category : 'accessing' }
Gt4SecurityCvssVector >> version [
	^ version
]
