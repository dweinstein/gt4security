Class {
	#name : 'Gt4SecuritySeverity',
	#superclass : 'Object',
	#instVars : [
		'type',
		'vectorString',
		'baseScore',
		'baseSeverity',
		'rawDict'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecuritySeverity class >> fromDictionary: aDictionary [
	"Parse a severity entry from OSV or NVD-normalized format."
	^ self new
		type: (aDictionary at: 'type' ifAbsent: [ nil ]);
		vectorString: (aDictionary at: 'score' ifAbsent: [ nil ]);
		baseScore: (aDictionary at: 'baseScore' ifAbsent: [ nil ]);
		baseSeverity: (aDictionary at: 'baseSeverity' ifAbsent: [ nil ]);
		rawDict: aDictionary;
		yourself
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> baseScore [
	^ baseScore
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> baseScore: aNumber [
	baseScore := aNumber
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> baseSeverity [
	^ baseSeverity
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> baseSeverity: aString [
	baseSeverity := aString
]

{ #category : 'derived' }
Gt4SecuritySeverity >> cvssVector [
	"Parse the vector string into a Gt4SecurityCvssVector (with a computed score)."
	(vectorString isNil or: [ vectorString isEmpty ]) ifTrue: [ ^ nil ].
	^ [ Gt4SecurityCvssVector fromString: vectorString ]
		on: Error do: [ :e | nil ]
]

{ #category : 'printing' }
Gt4SecuritySeverity >> displayLabel [
	"Human-readable label combining severity + score."
	| label score |
	label := self label.
	score := self formattedScore.
	(label notNil and: [ score notNil ]) ifTrue: [ ^ label , ' ' , score ].
	score ifNotNil: [ ^ score ].
	label ifNotNil: [ ^ label ].
	^ type ifNil: [ '' ]
]

{ #category : 'querying' }
Gt4SecuritySeverity >> formattedScore [
	"CVSS scores are always reported to 1 decimal place per the spec. Guards against float imprecision (e.g., 9.200000000000001 from v4 baseScore computation)."
	^ self numericScore ifNotNil: [ :s | s printShowingDecimalPlaces: 1 ]
]

{ #category : 'gt - views' }
Gt4SecuritySeverity >> gtCvssVectorFor: aView [
	<gtView>
	| vec |
	vec := self cvssVector.
	vec ifNil: [ ^ aView empty ].
	^ aView forward
		title: 'CVSS vector';
		priority: 2;
		object: [ vec ];
		view: #gtMetricsFor:
]

{ #category : 'printing' }
Gt4SecuritySeverity >> gtDisplayOn: aStream [
	aStream nextPutAll: self displayLabel
]

{ #category : 'gt - views' }
Gt4SecuritySeverity >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Severity';
		priority: 1;
		items: [ {
			'Type' -> (type ifNil: [ '(unknown)' ]).
			'Base score' -> (self formattedScore ifNil: [ '(not available)' ]).
			'Severity label' -> (self label ifNil: [ '(not available)' ]).
			'CVSS vector' -> (vectorString ifNil: [ '(none)' ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'derived' }
Gt4SecuritySeverity >> label [
	"Severity label — from NVD or derived from computed CVSS score."
	baseSeverity ifNotNil: [ ^ baseSeverity ].
	^ self cvssVector ifNotNil: [ :v | v severityLabel ] ifNil: [ nil ]
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> numericScore [
	"NVD-provided baseScore, or computed from the CVSS vector.
	Memoizes the computed score into baseScore so repeat callers (summary, By severity /
	By score / severity-band helpers) don't reparse the same vectorString. Only caches when
	the computation yields a non-nil score so we don't poison the happy path if parsing fails
	transiently."
	| computed |
	baseScore ifNotNil: [ ^ baseScore ].
	computed := self cvssVector ifNotNil: [ :v | v baseScore ].
	computed ifNotNil: [ baseScore := computed ].
	^ computed
]

{ #category : 'printing' }
Gt4SecuritySeverity >> printOn: aStream [
	super printOn: aStream.
	aStream nextPutAll: ' ('; nextPutAll: self displayLabel; nextPut: $)
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> rawDict: aDict [
	rawDict := aDict
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> type [
	^ type
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> type: aString [
	type := aString
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> vectorString [
	^ vectorString
]

{ #category : 'accessing' }
Gt4SecuritySeverity >> vectorString: aString [
	vectorString := aString
]
