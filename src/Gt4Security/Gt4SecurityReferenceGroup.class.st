"
Inspectable group of {{gtClass:Gt4SecurityReference}} using {{gtClass:TGtGroupWithItems}}.

Type-preserving filters: ofType:, advisories, patches, exploits, fromHost:.

GT views: References (columned list with type/host/URL), By type (drill-through), By host (drill-through — useful for spotting which vendors own the canonical advisory).
"
Class {
	#name : 'Gt4SecurityReferenceGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security-Domain',
	#package : 'Gt4Security',
	#tag : 'Domain'
}

{ #category : 'instance creation' }
Gt4SecurityReferenceGroup class >> withAll: aCollection [
	^ self new addItems: aCollection; yourself
]

{ #category : 'filtering' }
Gt4SecurityReferenceGroup >> advisories [
	^ self select: [ :each | each isAdvisory ]
]

{ #category : 'filtering' }
Gt4SecurityReferenceGroup >> exploits [
	^ self select: [ :each | each isExploit ]
]

{ #category : 'filtering' }
Gt4SecurityReferenceGroup >> fromHost: aHostString [
	^ self select: [ :each | each host = aHostString ]
]

{ #category : 'gt - views' }
Gt4SecurityReferenceGroup >> gtByHostFor: aView [
	<gtView>
	^ aView columnedList
		title: 'By host';
		priority: 3;
		items: [
			(self items
				inject: Dictionary new
				into: [ :acc :each |
					| h |
					h := each host.
					acc at: h put: ((acc at: h ifAbsent: [ 0 ]) + 1).
					acc ])
				associations
				sort: [ :a :b | a value > b value ] ];
		column: 'Host' text: [ :assoc | assoc key ] weight: 2;
		column: 'Count' text: [ :assoc | assoc value printString ] weight: 1;
		send: [ :assoc | self fromHost: assoc key ]
]

{ #category : 'gt - views' }
Gt4SecurityReferenceGroup >> gtByTypeFor: aView [
	<gtView>
	^ aView columnedList
		title: 'By type';
		priority: 2;
		items: [
			(self items
				inject: Dictionary new
				into: [ :acc :each |
					| t |
					t := each type ifNil: [ '(none)' ].
					acc at: t put: ((acc at: t ifAbsent: [ 0 ]) + 1).
					acc ])
				associations
				sort: [ :a :b | a value > b value ] ];
		column: 'Type' text: [ :assoc | assoc key ] weight: 2;
		column: 'Count' text: [ :assoc | assoc value printString ] weight: 1;
		send: [ :assoc | self ofType: assoc key ]
]

{ #category : 'printing' }
Gt4SecurityReferenceGroup >> gtDisplayOn: aStream [
	aStream print: self size; nextPutAll: ' references'
]

{ #category : 'gt - views' }
Gt4SecurityReferenceGroup >> gtReferencesFor: aView [
	<gtView>
	^ aView columnedList
		title: 'References';
		priority: 1;
		items: [ self items ];
		column: 'Type' text: [ :each | each type ifNil: [ '' ] ] weight: 1;
		column: 'Host' text: [ :each | each host ] weight: 1.5;
		column: 'URL' text: [ :each | each url ifNil: [ '' ] ] weight: 4
]

{ #category : 'testing' }
Gt4SecurityReferenceGroup >> notEmpty [
	^ self isEmpty not
]

{ #category : 'filtering' }
Gt4SecurityReferenceGroup >> ofType: aTypeString [
	^ self select: [ :each | each type = aTypeString ]
]

{ #category : 'filtering' }
Gt4SecurityReferenceGroup >> patches [
	^ self select: [ :each | each isPatch ]
]

{ #category : 'printing' }
Gt4SecurityReferenceGroup >> printOn: aStream [
	super printOn: aStream.
	aStream nextPutAll: ' ('; print: self size; nextPutAll: ' references)'
]
