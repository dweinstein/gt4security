"
Single origin-report entry from OSSF Malicious Packages, nested under `database_specific.malicious-packages-origins` in OSV records. Each origin identifies who reported the package as malicious and where the report can be verified.

Fields: source, sourceType, ref (source-specific reference URL or id), rawDict.

Constructed from dictionaries via {{gtMethod:Gt4SecurityMaliciousOrigin class>>#fromDictionary:}}. Used by {{gtMethod:Gt4SecurityVulnerability>>#maliciousOriginEntries}}.
"
Class {
	#name : 'Gt4SecurityMaliciousOrigin',
	#superclass : 'Object',
	#instVars : [
		'source',
		'sourceType',
		'ref',
		'rawDict'
	],
	#category : 'Gt4Security-Domain',
	#package : 'Gt4Security',
	#tag : 'Domain'
}

{ #category : 'instance creation' }
Gt4SecurityMaliciousOrigin class >> fromDictionary: aDictionary [
	^ self new
		source: (aDictionary at: 'source' ifAbsent: [ nil ]);
		sourceType: (aDictionary at: 'source_type' ifAbsent: [ nil ]);
		ref: (aDictionary at: 'ref' ifAbsent: [ nil ]);
		rawDict: aDictionary;
		yourself
]

{ #category : 'gt - views' }
Gt4SecurityMaliciousOrigin >> gtRawFor: aView [
	<gtView>
	rawDict ifNil: [ ^ aView empty ].
	^ aView textEditor
		title: 'Raw';
		priority: 10;
		text: [ NeoJSONWriter toStringPretty: rawDict ]
]

{ #category : 'gt - views' }
Gt4SecurityMaliciousOrigin >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Origin';
		priority: 1;
		items: [ {
			'Source' -> (source ifNil: [ '(unknown)' ]).
			'Source type' -> (sourceType ifNil: [ '(unknown)' ]).
			'Reference' -> (ref ifNil: [ '(none)' ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'printing' }
Gt4SecurityMaliciousOrigin >> printOn: aStream [
	aStream
		nextPutAll: (source ifNil: [ '(unknown source)' ]);
		nextPutAll: ' — ';
		nextPutAll: (sourceType ifNil: [ '?' ])
]

{ #category : 'accessing' }
Gt4SecurityMaliciousOrigin >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityMaliciousOrigin >> rawDict: aDictionary [
	rawDict := aDictionary
]

{ #category : 'accessing' }
Gt4SecurityMaliciousOrigin >> ref [
	^ ref
]

{ #category : 'accessing' }
Gt4SecurityMaliciousOrigin >> ref: aString [
	ref := aString
]

{ #category : 'accessing' }
Gt4SecurityMaliciousOrigin >> source [
	^ source
]

{ #category : 'accessing' }
Gt4SecurityMaliciousOrigin >> source: aString [
	source := aString
]

{ #category : 'accessing' }
Gt4SecurityMaliciousOrigin >> sourceType [
	^ sourceType
]

{ #category : 'accessing' }
Gt4SecurityMaliciousOrigin >> sourceType: aString [
	sourceType := aString
]
