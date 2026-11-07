Class {
	#name : 'Gt4SecurityAliasGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityAliasGroup class >> withAll: aCollection [
	"Accepts Gt4SecurityAlias instances or raw id strings."
	| aliases |
	aliases := aCollection collect: [ :each |
		(each isKindOf: Gt4SecurityAlias)
			ifTrue: [ each ]
			ifFalse: [ Gt4SecurityAlias id: each ] ].
	^ self new addItems: aliases; yourself
]

{ #category : 'filtering' }
Gt4SecurityAliasGroup >> cves [
	^ self select: [ :each | each isCve ]
]

{ #category : 'filtering' }
Gt4SecurityAliasGroup >> ghsas [
	^ self select: [ :each | each isGhsa ]
]

{ #category : 'gt - views' }
Gt4SecurityAliasGroup >> gtAliasesFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Aliases';
		priority: 1;
		items: [ self items ];
		column: 'ID' text: [ :each | each id ] weight: 3;
		column: 'Scheme' text: [ :each | each scheme ] weight: 1;
		send: [ :each | each lookup ifNil: [ each ] ]
]

{ #category : 'gt - views' }
Gt4SecurityAliasGroup >> gtByScheme: aView [
	<gtView>
	^ aView columnedList
		title: 'By scheme';
		priority: 2;
		items: [
			(self items
				inject: Dictionary new
				into: [ :acc :each |
					acc at: each scheme put: ((acc at: each scheme ifAbsent: [ 0 ]) + 1).
					acc ])
				associations
				sort: [ :a :b | a value > b value ] ];
		column: 'Scheme' text: [ :a | a key ] weight: 2;
		column: 'Count' text: [ :a | a value printString ] weight: 1;
		send: [ :a | self ofScheme: a key ]
]

{ #category : 'printing' }
Gt4SecurityAliasGroup >> gtDisplayOn: aStream [
	aStream print: self size; nextPutAll: ' aliases'
]

{ #category : 'derived' }
Gt4SecurityAliasGroup >> idStrings [
	"The plain id strings — for legacy compatibility with code that iterates aliases as strings."
	^ self items collect: [ :each | each id ]
]

{ #category : 'testing' }
Gt4SecurityAliasGroup >> notEmpty [
	^ self isEmpty not
]

{ #category : 'filtering' }
Gt4SecurityAliasGroup >> ofScheme: aSchemeString [
	^ self select: [ :each | each scheme = aSchemeString ]
]

{ #category : 'printing' }
Gt4SecurityAliasGroup >> printOn: aStream [
	super printOn: aStream.
	aStream nextPutAll: ' ('; print: self size; nextPutAll: ' aliases)'
]
