Class {
	#name : 'Gt4SecurityCweGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityCweGroup class >> withAll: aCollection [
	^ self new addItems: aCollection; yourself
]

{ #category : 'gt - views' }
Gt4SecurityCweGroup >> gtCwesFor: aView [
	<gtView>
	^ aView columnedList
		title: 'CWEs';
		priority: 1;
		items: [ self items ];
		column: 'ID' text: [ :each | each id ifNil: [ '' ] ] weight: 1;
		column: 'Description' text: [ :each | each description ifNil: [ '(unknown)' ] ] weight: 4;
		column: 'Source' text: [ :each | each source ifNil: [ '' ] ] weight: 1
]

{ #category : 'printing' }
Gt4SecurityCweGroup >> gtDisplayOn: aStream [
	self isEmpty
		ifTrue: [ aStream nextPutAll: '(no CWEs)' ]
		ifFalse: [ aStream nextPutAll: (', ' join: (self items collect: [ :c | c id ])) ]
]

{ #category : 'testing' }
Gt4SecurityCweGroup >> notEmpty [
	^ self isEmpty not
]

{ #category : 'printing' }
Gt4SecurityCweGroup >> printOn: aStream [
	super printOn: aStream.
	aStream nextPutAll: ' ('; print: self size; nextPutAll: ' CWEs)'
]
