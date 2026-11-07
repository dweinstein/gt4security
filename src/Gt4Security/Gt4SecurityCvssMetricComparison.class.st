"
Per-metric comparison row — one metric viewed across all vectors in a {{gtClass:Gt4SecurityCvssComparison}}. Spawned when you click a row in the Differences or All metrics views.

Fields: abbreviation, fullName, valuesByLabel (OrderedCollection of label -> value associations in column order).

Derived: `differs` (true if any two vectors have different values), `presentValues` (filters out '—' absences).
"
Class {
	#name : 'Gt4SecurityCvssMetricComparison',
	#superclass : 'Object',
	#instVars : [
		'abbreviation',
		'fullName',
		'valuesByLabel'
	],
	#category : 'Gt4Security-CVSS',
	#package : 'Gt4Security',
	#tag : 'CVSS'
}

{ #category : 'instance creation' }
Gt4SecurityCvssMetricComparison class >> abbreviation: anAbbrev fullName: aName valuesByLabel: aDictionary [
	^ self new
		abbreviation: anAbbrev;
		fullName: aName;
		valuesByLabel: aDictionary;
		yourself
]

{ #category : 'accessing' }
Gt4SecurityCvssMetricComparison >> abbreviation [
	^ abbreviation
]

{ #category : 'accessing' }
Gt4SecurityCvssMetricComparison >> abbreviation: aString [
	abbreviation := aString
]

{ #category : 'derived' }
Gt4SecurityCvssMetricComparison >> differs [
	"True if any two vectors have different values for this metric."
	^ self presentValues asSet size > 1
]

{ #category : 'accessing' }
Gt4SecurityCvssMetricComparison >> fullName [
	^ fullName
]

{ #category : 'accessing' }
Gt4SecurityCvssMetricComparison >> fullName: aString [
	fullName := aString
]

{ #category : 'gt - views' }
Gt4SecurityCvssMetricComparison >> gtMetaFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Metric';
		priority: 2;
		items: [ {
			'Abbreviation' -> abbreviation.
			'Name' -> fullName.
			'Differs across vectors?' -> (self differs ifTrue: [ 'Yes' ] ifFalse: [ 'No' ]).
			'Present in # vectors' -> self presentValues size printString.
			'Unique values' -> (', ' join: self presentValues asSet asArray) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'gt - views' }
Gt4SecurityCvssMetricComparison >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Values by vector';
		priority: 1;
		items: [ valuesByLabel ];
		column: 'Vector' text: [ :assoc | assoc key ] weight: 2;
		column: 'Value' text: [ :assoc | assoc value ] weight: 1
]

{ #category : 'derived' }
Gt4SecurityCvssMetricComparison >> presentValues [
	"The metric values excluding entries where the metric is absent (—)."
	^ (valuesByLabel collect: [ :assoc | assoc value ]) reject: [ :v | v = '—' ]
]

{ #category : 'printing' }
Gt4SecurityCvssMetricComparison >> printOn: aStream [
	aStream
		nextPutAll: fullName;
		nextPutAll: ' (';
		nextPutAll: abbreviation;
		nextPutAll: '): ';
		nextPutAll: (self differs ifTrue: [ 'DIFFERS' ] ifFalse: [ 'same' ])
]

{ #category : 'accessing' }
Gt4SecurityCvssMetricComparison >> valuesByLabel [
	"OrderedCollection of label -> value associations, in input order (preserves comparison column order)."
	^ valuesByLabel
]

{ #category : 'accessing' }
Gt4SecurityCvssMetricComparison >> valuesByLabel: anOrderedCollection [
	valuesByLabel := anOrderedCollection
]
