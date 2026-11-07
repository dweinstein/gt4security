Class {
	#name : 'Gt4SecurityCredit',
	#superclass : 'Object',
	#instVars : [
		'name',
		'contact',
		'type',
		'rawDict'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityCredit class >> fromDictionary: aDictionary [
	^ self new
		name: (aDictionary at: 'name' ifAbsent: [ nil ]);
		contact: (aDictionary at: 'contact' ifAbsent: [ #() ]);
		type: (aDictionary at: 'type' ifAbsent: [ nil ]);
		rawDict: aDictionary;
		yourself
]

{ #category : 'accessing' }
Gt4SecurityCredit >> contact [
	^ contact
]

{ #category : 'accessing' }
Gt4SecurityCredit >> contact: anArrayOrCollection [
	contact := anArrayOrCollection
]

{ #category : 'gt - views' }
Gt4SecurityCredit >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Credit';
		priority: 1;
		items: [ {
			'Name' -> (name ifNil: [ '(unknown)' ]).
			'Type' -> (type ifNil: [ '(unknown)' ]).
			'Contact' -> ((contact isNil or: [ contact isEmpty ])
				ifTrue: [ '(none)' ]
				ifFalse: [ ', ' join: contact ]) } ];
		column: 'Property' text: [ :a | a key ] weight: 1;
		column: 'Value' text: [ :a | a value ] weight: 3
]

{ #category : 'accessing' }
Gt4SecurityCredit >> name [
	^ name
]

{ #category : 'accessing' }
Gt4SecurityCredit >> name: aString [
	name := aString
]

{ #category : 'printing' }
Gt4SecurityCredit >> printOn: aStream [
	aStream
		nextPutAll: (name ifNil: [ '(unknown)' ]);
		nextPutAll: ' ['; nextPutAll: (type ifNil: [ '?' ]); nextPut: $]
]

{ #category : 'accessing' }
Gt4SecurityCredit >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityCredit >> rawDict: aDict [
	rawDict := aDict
]

{ #category : 'accessing' }
Gt4SecurityCredit >> type [
	^ type
]

{ #category : 'accessing' }
Gt4SecurityCredit >> type: aString [
	type := aString
]
