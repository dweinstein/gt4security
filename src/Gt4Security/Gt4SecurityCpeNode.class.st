Class {
	#name : 'Gt4SecurityCpeNode',
	#superclass : 'Object',
	#instVars : [
		'operator',
		'negate',
		'cpeMatches',
		'children',
		'rawDict'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityCpeNode class >> fromDictionary: aDictionary [
	"NVD node: {operator, negate, cpeMatch: [...], children: [...]}."
	| rawMatches rawChildren |
	rawMatches := aDictionary at: 'cpeMatch' ifAbsent: [ #() ].
	rawChildren := aDictionary at: 'children' ifAbsent: [ #() ].
	^ self new
		operator: (aDictionary at: 'operator' ifAbsent: [ 'OR' ]);
		negate: (aDictionary at: 'negate' ifAbsent: [ false ]);
		cpeMatches: (rawMatches collect: [ :each | Gt4SecurityCpeMatch fromDictionary: each ]) asArray;
		children: (rawChildren collect: [ :each | self fromDictionary: each ]) asArray;
		rawDict: aDictionary;
		yourself
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> children [
	^ children
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> children: aCollection [
	children := aCollection
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> cpeMatches [
	^ cpeMatches
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> cpeMatches: aCollection [
	cpeMatches := aCollection
]

{ #category : 'gt - views' }
Gt4SecurityCpeNode >> gtChildrenFor: aView [
	<gtView>
	(children isNil or: [ children isEmpty ]) ifTrue: [ ^ aView empty ].
	^ aView columnedList
		title: 'Child nodes';
		priority: 2;
		items: [ children ];
		column: 'Operator' text: [ :n | n operator ifNil: [ 'OR' ] ] weight: 1;
		column: 'Matches' text: [ :n | (n cpeMatches ifNil: [ #() ]) size printString ] weight: 1;
		column: 'Children' text: [ :n | (n children ifNil: [ #() ]) size printString ] weight: 1
]

{ #category : 'gt - views' }
Gt4SecurityCpeNode >> gtMatchesFor: aView [
	<gtView>
	(cpeMatches isNil or: [ cpeMatches isEmpty ]) ifTrue: [ ^ aView empty ].
	^ aView columnedList
		title: 'CPE matches';
		priority: 1;
		items: [ cpeMatches ];
		column: 'Vendor' text: [ :m | m cpeVendor ifNil: [ '' ] ] weight: 1;
		column: 'Product' text: [ :m | m cpeProduct ifNil: [ '' ] ] weight: 2;
		column: 'Range' text: [ :m | m versionRangeSummary ] weight: 2;
		column: 'Vuln?' text: [ :m | m vulnerable = true ifTrue: [ 'yes' ] ifFalse: [ m vulnerable = false ifTrue: [ 'no' ] ifFalse: [ '?' ] ] ] weight: 1
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> negate [
	^ negate
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> negate: aBoolean [
	negate := aBoolean
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> operator [
	^ operator
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> operator: aString [
	operator := aString
]

{ #category : 'printing' }
Gt4SecurityCpeNode >> printOn: aStream [
	aStream nextPutAll: 'CpeNode('.
	aStream nextPutAll: (operator ifNil: [ 'OR' ]).
	aStream nextPutAll: ', '.
	aStream nextPutAll: (cpeMatches ifNil: [ #() ]) size printString.
	aStream nextPutAll: ' match(es)'.
	(children isNil or: [ children isEmpty ]) ifFalse: [
		aStream nextPutAll: ', '.
		aStream nextPutAll: children size printString.
		aStream nextPutAll: ' child(ren)' ].
	aStream nextPut: $)
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityCpeNode >> rawDict: aDict [
	rawDict := aDict
]
