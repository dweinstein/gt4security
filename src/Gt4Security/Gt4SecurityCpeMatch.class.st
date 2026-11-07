Class {
	#name : 'Gt4SecurityCpeMatch',
	#superclass : 'Object',
	#instVars : [
		'criteria',
		'vulnerable',
		'matchCriteriaId',
		'versionStartIncluding',
		'versionStartExcluding',
		'versionEndIncluding',
		'versionEndExcluding',
		'rawDict'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityCpeMatch class >> fromDictionary: aDictionary [
	^ self new
		criteria: (aDictionary at: 'criteria' ifAbsent: [ nil ]);
		vulnerable: (aDictionary at: 'vulnerable' ifAbsent: [ nil ]);
		matchCriteriaId: (aDictionary at: 'matchCriteriaId' ifAbsent: [ nil ]);
		versionStartIncluding: (aDictionary at: 'versionStartIncluding' ifAbsent: [ nil ]);
		versionStartExcluding: (aDictionary at: 'versionStartExcluding' ifAbsent: [ nil ]);
		versionEndIncluding: (aDictionary at: 'versionEndIncluding' ifAbsent: [ nil ]);
		versionEndExcluding: (aDictionary at: 'versionEndExcluding' ifAbsent: [ nil ]);
		rawDict: aDictionary;
		yourself
]

{ #category : 'querying' }
Gt4SecurityCpeMatch >> cpeParts [
	"Colon-separated CPE 2.3 components, or #() if not a well-formed cpe string."
	(criteria notNil and: [ criteria beginsWith: 'cpe:' ])
		ifFalse: [ ^ #() ].
	^ (criteria substrings: ':') asArray
]

{ #category : 'querying' }
Gt4SecurityCpeMatch >> cpeProduct [
	^ self cpeParts size >= 5 ifTrue: [ self cpeParts at: 5 ] ifFalse: [ nil ]
]

{ #category : 'querying' }
Gt4SecurityCpeMatch >> cpeVendor [
	^ self cpeParts size >= 4 ifTrue: [ self cpeParts at: 4 ] ifFalse: [ nil ]
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> criteria [
	^ criteria
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> criteria: aString [
	criteria := aString
]

{ #category : 'gt - views' }
Gt4SecurityCpeMatch >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 1;
		items: [ {
			'Criteria' -> (criteria ifNil: [ '(none)' ]).
			'Vendor' -> (self cpeVendor ifNil: [ '(none)' ]).
			'Product' -> (self cpeProduct ifNil: [ '(none)' ]).
			'Vulnerable?' -> (vulnerable = true ifTrue: [ 'YES' ] ifFalse: [ vulnerable = false ifTrue: [ 'no' ] ifFalse: [ '(unknown)' ] ]).
			'Version range' -> self versionRangeSummary.
			'Match criteria ID' -> (matchCriteriaId ifNil: [ '(none)' ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> matchCriteriaId [
	^ matchCriteriaId
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> matchCriteriaId: aString [
	matchCriteriaId := aString
]

{ #category : 'printing' }
Gt4SecurityCpeMatch >> printOn: aStream [
	aStream nextPutAll: 'CpeMatch('.
	aStream nextPutAll: (self cpeProduct ifNil: [ criteria ifNil: [ '?' ] ]).
	aStream nextPutAll: ' '.
	aStream nextPutAll: self versionRangeSummary.
	aStream nextPut: $)
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> rawDict: aDict [
	rawDict := aDict
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> versionEndExcluding [
	^ versionEndExcluding
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> versionEndExcluding: aString [
	versionEndExcluding := aString
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> versionEndIncluding [
	^ versionEndIncluding
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> versionEndIncluding: aString [
	versionEndIncluding := aString
]

{ #category : 'querying' }
Gt4SecurityCpeMatch >> versionRangeSummary [
	"Human-readable bounds combining start/end including/excluding."
	| parts |
	parts := OrderedCollection new.
	versionStartIncluding ifNotNil: [ parts add: '>= ' , versionStartIncluding ].
	versionStartExcluding ifNotNil: [ parts add: '> ' , versionStartExcluding ].
	versionEndIncluding ifNotNil: [ parts add: '<= ' , versionEndIncluding ].
	versionEndExcluding ifNotNil: [ parts add: '< ' , versionEndExcluding ].
	parts isEmpty ifTrue: [ ^ 'any' ].
	^ ', ' join: parts
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> versionStartExcluding [
	^ versionStartExcluding
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> versionStartExcluding: aString [
	versionStartExcluding := aString
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> versionStartIncluding [
	^ versionStartIncluding
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> versionStartIncluding: aString [
	versionStartIncluding := aString
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> vulnerable [
	^ vulnerable
]

{ #category : 'accessing' }
Gt4SecurityCpeMatch >> vulnerable: aBoolean [
	vulnerable := aBoolean
]
