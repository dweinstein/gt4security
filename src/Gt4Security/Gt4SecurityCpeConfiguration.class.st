Class {
	#name : 'Gt4SecurityCpeConfiguration',
	#superclass : 'Object',
	#instVars : [
		'operator',
		'negate',
		'nodes',
		'rawDict'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityCpeConfiguration class >> fromDictionary: aDictionary [
	"NVD configuration: {operator, negate, nodes: [...]}."
	| rawNodes |
	rawNodes := aDictionary at: 'nodes' ifAbsent: [ #() ].
	^ self new
		operator: (aDictionary at: 'operator' ifAbsent: [ nil ]);
		negate: (aDictionary at: 'negate' ifAbsent: [ false ]);
		nodes: (rawNodes collect: [ :each | Gt4SecurityCpeNode fromDictionary: each ]) asArray;
		rawDict: aDictionary;
		yourself
]

{ #category : 'querying' }
Gt4SecurityCpeConfiguration >> allCpeMatches [
	"Flatten all cpeMatches across all nodes (including children) into one array."
	| result visit |
	result := OrderedCollection new.
	visit := nil.
	visit := [ :aNode |
		(aNode cpeMatches ifNil: [ #() ]) do: [ :m | result add: m ].
		(aNode children ifNil: [ #() ]) do: [ :child | visit value: child ] ].
	(nodes ifNil: [ #() ]) do: [ :n | visit value: n ].
	^ result asArray
]

{ #category : 'gt - views' }
Gt4SecurityCpeConfiguration >> gtAllMatchesFor: aView [
	<gtView>
	| all |
	all := self allCpeMatches.
	all isEmpty ifTrue: [ ^ aView empty ].
	^ aView columnedList
		title: 'All matches';
		priority: 2;
		items: [ all ];
		column: 'Vendor' text: [ :m | m cpeVendor ifNil: [ '' ] ] weight: 1;
		column: 'Product' text: [ :m | m cpeProduct ifNil: [ '' ] ] weight: 2;
		column: 'Range' text: [ :m | m versionRangeSummary ] weight: 2;
		column: 'Vuln?' text: [ :m | m vulnerable = true ifTrue: [ 'yes' ] ifFalse: [ m vulnerable = false ifTrue: [ 'no' ] ifFalse: [ '?' ] ] ] weight: 1
]

{ #category : 'gt - views' }
Gt4SecurityCpeConfiguration >> gtNodesFor: aView [
	<gtView>
	(nodes isNil or: [ nodes isEmpty ]) ifTrue: [ ^ aView empty ].
	^ aView columnedList
		title: 'Nodes';
		priority: 1;
		items: [ nodes ];
		column: 'Operator' text: [ :n | n operator ifNil: [ 'OR' ] ] weight: 1;
		column: 'Matches' text: [ :n | (n cpeMatches ifNil: [ #() ]) size printString ] weight: 1;
		column: 'Children' text: [ :n | (n children ifNil: [ #() ]) size printString ] weight: 1;
		column: 'Negate' text: [ :n | n negate = true ifTrue: [ 'yes' ] ifFalse: [ 'no' ] ] weight: 1
]

{ #category : 'accessing' }
Gt4SecurityCpeConfiguration >> negate [
	^ negate
]

{ #category : 'accessing' }
Gt4SecurityCpeConfiguration >> negate: aBoolean [
	negate := aBoolean
]

{ #category : 'accessing' }
Gt4SecurityCpeConfiguration >> nodes [
	^ nodes
]

{ #category : 'accessing' }
Gt4SecurityCpeConfiguration >> nodes: aCollection [
	nodes := aCollection
]

{ #category : 'accessing' }
Gt4SecurityCpeConfiguration >> operator [
	^ operator
]

{ #category : 'accessing' }
Gt4SecurityCpeConfiguration >> operator: aString [
	operator := aString
]

{ #category : 'printing' }
Gt4SecurityCpeConfiguration >> printOn: aStream [
	aStream nextPutAll: 'CpeConfig('.
	operator ifNotNil: [ aStream nextPutAll: operator; nextPutAll: ', ' ].
	aStream nextPutAll: (nodes ifNil: [ #() ]) size printString.
	aStream nextPutAll: ' node(s), '.
	aStream nextPutAll: self allCpeMatches size printString.
	aStream nextPutAll: ' total match(es)'.
	aStream nextPut: $)
]

{ #category : 'accessing' }
Gt4SecurityCpeConfiguration >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityCpeConfiguration >> rawDict: aDict [
	rawDict := aDict
]
