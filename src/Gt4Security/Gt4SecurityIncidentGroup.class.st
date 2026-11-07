"
Inspectable group of {{gtClass:Gt4SecurityIncident}} instances. Uses {{gtClass:TGtGroupWithItems}}.

Type-preserving filters: platform:, android, ios, category:, year:, active, matching:.

GT views: Incidents (columned list sorted by year desc), By category (drill-through), By platform (drill-through), Timeline (year histogram, drill-through).
"
Class {
	#name : 'Gt4SecurityIncidentGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security-Incidents',
	#package : 'Gt4Security',
	#tag : 'Incidents'
}

{ #category : 'instance creation' }
Gt4SecurityIncidentGroup class >> withAll: aCollection [
	^ self new addItems: aCollection; yourself
]

{ #category : 'filtering' }
Gt4SecurityIncidentGroup >> active [
	^ self select: [ :each | each isActive ]
]

{ #category : 'filtering' }
Gt4SecurityIncidentGroup >> android [
	^ self platform: 'Android'
]

{ #category : 'filtering' }
Gt4SecurityIncidentGroup >> category: aCategoryString [
	"Type-preserving filter by incident category."
	^ self select: [ :each | each category = aCategoryString ]
]

{ #category : 'gt - views' }
Gt4SecurityIncidentGroup >> gtByCategoryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'By category';
		priority: 2;
		items: [
			| buckets |
			buckets := Dictionary new.
			self items do: [ :each |
				| cat |
				cat := each category ifNil: [ '(unknown)' ].
				buckets at: cat put: ((buckets at: cat ifAbsent: [ 0 ]) + 1) ].
			buckets associations sort: [ :a :b | a value > b value ] ];
		column: 'Category' text: [ :assoc | assoc key ] weight: 2;
		column: 'Count' text: [ :assoc | assoc value printString ] weight: 1;
		send: [ :assoc | self category: assoc key ]
]

{ #category : 'gt - views' }
Gt4SecurityIncidentGroup >> gtByPlatformFor: aView [
	<gtView>
	^ aView columnedList
		title: 'By platform';
		priority: 3;
		items: [
			| buckets |
			buckets := Dictionary new.
			self items do: [ :each |
				each platforms do: [ :p |
					buckets at: p put: ((buckets at: p ifAbsent: [ 0 ]) + 1) ] ].
			buckets associations sort: [ :a :b | a value > b value ] ];
		column: 'Platform' text: [ :assoc | assoc key ] weight: 2;
		column: 'Count' text: [ :assoc | assoc value printString ] weight: 1;
		send: [ :assoc | self platform: assoc key ]
]

{ #category : 'printing' }
Gt4SecurityIncidentGroup >> gtDisplayOn: aStream [
	aStream
		print: self size;
		nextPutAll: ' incidents'
]

{ #category : 'gt - views' }
Gt4SecurityIncidentGroup >> gtIncidentsFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Incidents';
		priority: 1;
		items: [ self items sorted: [ :a :b | a year > b year ] ];
		column: 'Name' text: [ :each | each name ifNil: [ '' ] ] weight: 2;
		column: 'Year' text: [ :each | each year ifNil: [ '' ] ifNotNil: [ :y | y printString ] ] weight: 0.5;
		column: 'Platforms' text: [ :each | ', ' join: each platforms ] weight: 1;
		column: 'Category' text: [ :each | each category ifNil: [ '' ] ] weight: 1;
		column: 'Installs' text: [ :each | each affectedInstalls ifNil: [ '' ] ] weight: 1;
		column: 'Status' text: [ :each | each status ifNil: [ '' ] ] weight: 0.7
]

{ #category : 'gt - views' }
Gt4SecurityIncidentGroup >> gtTimelineFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Timeline';
		priority: 4;
		items: [
			| buckets |
			buckets := Dictionary new.
			self items do: [ :each |
				each year ifNotNil: [ :y |
					buckets at: y put: ((buckets at: y ifAbsent: [ 0 ]) + 1) ] ].
			buckets associations sort: [ :a :b | a key > b key ] ];
		column: 'Year' text: [ :assoc | assoc key printString ] weight: 1;
		column: 'Count' text: [ :assoc | assoc value printString ] weight: 1;
		column: '' text: [ :assoc | String new: (assoc value min: 40) withAll: $# ] weight: 3;
		send: [ :assoc | self year: assoc key ]
]

{ #category : 'filtering' }
Gt4SecurityIncidentGroup >> ios [
	^ self platform: 'iOS'
]

{ #category : 'filtering' }
Gt4SecurityIncidentGroup >> matching: aSubstring [
	"Case-insensitive search across name, vendor, description."
	| needle |
	needle := aSubstring asLowercase.
	^ self select: [ :each |
		((each name ifNil: [ '' ]) asLowercase includesSubstring: needle)
			or: [ ((each vendor ifNil: [ '' ]) asLowercase includesSubstring: needle)
			or: [ ((each description ifNil: [ '' ]) asLowercase includesSubstring: needle) ] ] ]
]

{ #category : 'testing' }
Gt4SecurityIncidentGroup >> notEmpty [
	^ self isEmpty not
]

{ #category : 'filtering' }
Gt4SecurityIncidentGroup >> platform: aPlatformString [
	"Type-preserving filter: keep only incidents affecting the given platform."
	^ self select: [ :each | each platforms includes: aPlatformString ]
]

{ #category : 'printing' }
Gt4SecurityIncidentGroup >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (';
		print: self size;
		nextPutAll: ' incidents)'
]

{ #category : 'filtering' }
Gt4SecurityIncidentGroup >> year: anInteger [
	^ self select: [ :each | each year = anInteger ]
]
