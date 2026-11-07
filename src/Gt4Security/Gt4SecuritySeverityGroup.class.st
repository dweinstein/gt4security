Class {
	#name : 'Gt4SecuritySeverityGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecuritySeverityGroup class >> withAll: aCollection [
	^ self new addItems: aCollection; yourself
]

{ #category : 'derived' }
Gt4SecuritySeverityGroup >> displayLabel [
	^ self primary ifNotNil: [ :p | p displayLabel ] ifNil: [ '' ]
]

{ #category : 'printing' }
Gt4SecuritySeverityGroup >> gtDisplayOn: aStream [
	self isEmpty
		ifTrue: [ aStream nextPutAll: '(no severity)' ]
		ifFalse: [ aStream nextPutAll: self displayLabel ]
]

{ #category : 'gt - views' }
Gt4SecuritySeverityGroup >> gtSeveritiesFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Severities';
		priority: 1;
		items: [ self items ];
		column: 'Type' text: [ :each | each type ifNil: [ '' ] ] weight: 1;
		column: 'Score' text: [ :each | each formattedScore ifNil: [ '' ] ] weight: 1;
		column: 'Label' text: [ :each | each label ifNil: [ '' ] ] weight: 1;
		column: 'Vector' text: [ :each | each vectorString ifNil: [ '' ] ] weight: 3
]

{ #category : 'derived' }
Gt4SecuritySeverityGroup >> label [
	"Severity label from the primary entry."
	^ self primary ifNotNil: [ :p | p label ]
]

{ #category : 'testing' }
Gt4SecuritySeverityGroup >> notEmpty [
	^ self isEmpty not
]

{ #category : 'derived' }
Gt4SecuritySeverityGroup >> numericScore [
	"Numeric score from the primary severity entry."
	^ self primary ifNotNil: [ :p | p numericScore ]
]

{ #category : 'filtering' }
Gt4SecuritySeverityGroup >> ofType: aTypeString [
	^ self select: [ :each | each type = aTypeString ]
]

{ #category : 'derived' }
Gt4SecuritySeverityGroup >> primary [
	"First severity entry, or nil if empty."
	^ self isEmpty ifTrue: [ nil ] ifFalse: [ self items first ]
]

{ #category : 'printing' }
Gt4SecuritySeverityGroup >> printOn: aStream [
	super printOn: aStream.
	aStream nextPutAll: ' ('; print: self size; nextPutAll: ' severity entries)'
]
