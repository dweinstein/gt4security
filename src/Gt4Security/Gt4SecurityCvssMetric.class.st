"
Single CVSS metric as a key-value pair with human-readable name: abbreviation (e.g., 'AV'), value (e.g., 'N'), fullName (e.g., 'Attack Vector'). Extracted by {{gtMethod:Gt4SecurityCvssVector>>#parse}} and exposed via `metrics` on a vector.
"
Class {
	#name : 'Gt4SecurityCvssMetric',
	#superclass : 'Object',
	#instVars : [
		'abbreviation',
		'value',
		'fullName'
	],
	#category : 'Gt4Security-CVSS',
	#package : 'Gt4Security',
	#tag : 'CVSS'
}

{ #category : 'accessing' }
Gt4SecurityCvssMetric >> abbreviation [
	^ abbreviation
]

{ #category : 'accessing' }
Gt4SecurityCvssMetric >> abbreviation: aString [
	abbreviation := aString
]

{ #category : 'accessing' }
Gt4SecurityCvssMetric >> fullName [
	^ fullName
]

{ #category : 'accessing' }
Gt4SecurityCvssMetric >> fullName: aString [
	fullName := aString
]

{ #category : 'gt - views' }
Gt4SecurityCvssMetric >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Metric';
		priority: 1;
		items: [ {
			'Abbreviation' -> (abbreviation ifNil: [ '' ]).
			'Full name' -> (fullName ifNil: [ abbreviation ifNil: [ '' ] ]).
			'Value' -> (value ifNil: [ '' ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'printing' }
Gt4SecurityCvssMetric >> printOn: aStream [
	aStream
		nextPutAll: abbreviation;
		nextPut: $:;
		nextPutAll: value
]

{ #category : 'accessing' }
Gt4SecurityCvssMetric >> value [
	^ value
]

{ #category : 'accessing' }
Gt4SecurityCvssMetric >> value: aString [
	value := aString
]
