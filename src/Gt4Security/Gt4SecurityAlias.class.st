Class {
	#name : 'Gt4SecurityAlias',
	#superclass : 'Object',
	#instVars : [
		'id'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityAlias class >> id: aString [
	^ self new id: aString; yourself
]

{ #category : 'gt - views' }
Gt4SecurityAlias >> gtLookupActionFor: anAction [
	<gtAction>
	id ifNil: [ ^ anAction noAction ].
	^ anAction button
		icon: BrGlamorousVectorIcons browse;
		tooltip: 'Look up this alias in OSV';
		priority: 10;
		action: [ :aButton |
			| result |
			result := self lookup.
			result ifNotNil: [ aButton phlow spawnObject: result ] ]
]

{ #category : 'gt - views' }
Gt4SecurityAlias >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Alias';
		priority: 1;
		items: [ { 'ID' -> id. 'Scheme' -> self scheme } ];
		column: 'Property' text: [ :a | a key ] weight: 1;
		column: 'Value' text: [ :a | a value ifNil: [ '' ] ] weight: 3
]

{ #category : 'accessing' }
Gt4SecurityAlias >> id [
	^ id
]

{ #category : 'accessing' }
Gt4SecurityAlias >> id: aString [
	id := aString
]

{ #category : 'derived' }
Gt4SecurityAlias >> isCve [
	^ self scheme = 'CVE'
]

{ #category : 'derived' }
Gt4SecurityAlias >> isGhsa [
	^ self scheme = 'GHSA'
]

{ #category : 'derived' }
Gt4SecurityAlias >> isMalicious [
	^ self scheme = 'MAL'
]

{ #category : 'lookup' }
Gt4SecurityAlias >> lookup [
	"Look up this alias via OSV (handles CVE-*, GHSA-*, MAL-*, ASB-A-*, etc.)."
	id ifNil: [ ^ nil ].
	^ [ Gt4SecurityOsvClient new vulnerabilityById: id ]
		on: Error do: [ :e | nil ]
]

{ #category : 'printing' }
Gt4SecurityAlias >> printOn: aStream [
	aStream nextPutAll: (id ifNil: [ '(no id)' ])
]

{ #category : 'derived' }
Gt4SecurityAlias >> scheme [
	"Prefix scheme: CVE, GHSA, MAL, ASB-A, BIT, etc."
	id ifNil: [ ^ 'UNKNOWN' ].
	(id indexOf: $-) = 0 ifTrue: [ ^ id ].
	^ id copyFrom: 1 to: (id indexOf: $-) - 1
]
