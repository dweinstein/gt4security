Class {
	#name : 'Gt4SecurityCreditGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityCreditGroup class >> withAll: aCollection [
	^ self new addItems: aCollection; yourself
]

{ #category : 'gt - views' }
Gt4SecurityCreditGroup >> gtCreditsFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Credits';
		priority: 1;
		items: [ self items ];
		column: 'Name' text: [ :each | each name ifNil: [ '' ] ] weight: 2;
		column: 'Type' text: [ :each | each type ifNil: [ '' ] ] weight: 1
]

{ #category : 'printing' }
Gt4SecurityCreditGroup >> gtDisplayOn: aStream [
	aStream print: self size; nextPutAll: ' credits'
]

{ #category : 'testing' }
Gt4SecurityCreditGroup >> notEmpty [
	^ self isEmpty not
]

{ #category : 'printing' }
Gt4SecurityCreditGroup >> printOn: aStream [
	super printOn: aStream.
	aStream nextPutAll: ' ('; print: self size; nextPutAll: ' credits)'
]
