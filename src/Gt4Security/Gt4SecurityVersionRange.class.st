"
Wraps an OSV affected[].ranges[] entry — a (type, events) pair describing version coverage.

The OSV schema encodes version constraints as an ordered event list, not a closed interval. Each event is a single-key dict like {introduced: X}, {fixed: X}, {last_affected: X}, or {limit: X}. A typical npm record has `[{introduced: 4.0.0}, {fixed: 5.0.9}]` meaning ""affects 4.0.0 <= v < 5.0.9"".

The `type` slot carries the OSV range type ('SEMVER', 'ECOSYSTEM', 'GIT'). For GIT ranges, versions are commit SHAs.

Events are stored as `Association(key -> value)` in source order so a single range can carry multiple introduced/fixed transitions (e.g., 4.0.0 introduced, 4.2.0 fixed, 4.3.0 reintroduced, 4.4.0 fixed again).

See `summary` for the human-readable rendering used by `Gt4SecurityAffectedEntry>>#versionRangeSummary`.
"
Class {
	#name : 'Gt4SecurityVersionRange',
	#superclass : 'Object',
	#instVars : [
		'type',
		'events',
		'rawDict'
	],
	#category : 'Gt4Security-Domain',
	#package : 'Gt4Security',
	#tag : 'Domain'
}

{ #category : 'instance creation' }
Gt4SecurityVersionRange class >> fromDictionary: aDictionary [
	"Parse an OSV range: {type, events: [{introduced: X} | {fixed: X} | {last_affected: X} | {limit: X}]}.
	Events are kept as Association(key -> value) in stable order."
	| rawEvents |
	rawEvents := aDictionary at: 'events' ifAbsent: [ #() ].
	^ self new
		type: (aDictionary at: 'type' ifAbsent: [ nil ]);
		events: (rawEvents collect: [ :each |
			| assoc |
			assoc := each associations
				detect: [ :a | a value notNil ]
				ifNone: [ nil -> nil ].
			assoc key -> assoc value ]) asArray;
		rawDict: aDictionary;
		yourself
]

{ #category : 'accessing' }
Gt4SecurityVersionRange >> events [
	^ events
]

{ #category : 'accessing' }
Gt4SecurityVersionRange >> events: anArray [
	events := anArray
]

{ #category : 'derived' }
Gt4SecurityVersionRange >> fixedVersions [
	"All versions listed in 'fixed' events."
	^ (events select: [ :e | e key = 'fixed' ]) collect: [ :e | e value ]
]

{ #category : 'printing' }
Gt4SecurityVersionRange >> gtDisplayOn: aStream [
	aStream
		nextPutAll: (type ifNil: [ '?' ]);
		nextPutAll: ': ';
		nextPutAll: self summary
]

{ #category : 'gt - views' }
Gt4SecurityVersionRange >> gtEventsFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Events';
		priority: 1;
		items: [ events ];
		column: 'Event' text: [ :e | e key ] weight: 1;
		column: 'Version' text: [ :e | e value ifNil: [ '' ] ] weight: 2
]

{ #category : 'derived' }
Gt4SecurityVersionRange >> introducedVersions [
	"All versions listed in 'introduced' events."
	^ (events select: [ :e | e key = 'introduced' ]) collect: [ :e | e value ]
]

{ #category : 'derived' }
Gt4SecurityVersionRange >> lastAffectedVersions [
	^ (events select: [ :e | e key = 'last_affected' ]) collect: [ :e | e value ]
]

{ #category : 'derived' }
Gt4SecurityVersionRange >> limitVersions [
	^ (events select: [ :e | e key = 'limit' ]) collect: [ :e | e value ]
]

{ #category : 'printing' }
Gt4SecurityVersionRange >> printOn: aStream [
	super printOn: aStream.
	aStream nextPutAll: ' ('; nextPutAll: self summary; nextPut: $)
]

{ #category : 'accessing' }
Gt4SecurityVersionRange >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityVersionRange >> rawDict: aDictionary [
	rawDict := aDictionary
]

{ #category : 'derived' }
Gt4SecurityVersionRange >> summary [
	"Human-readable summary, e.g. '>= 4.0.0, < 5.0.9' or '>= 0 (all)'.
	Uses >=/< for introduced/fixed, <= for last_affected."
	| parts introduced fixed lastAffected |
	parts := OrderedCollection new.
	introduced := self introducedVersions.
	fixed := self fixedVersions.
	lastAffected := self lastAffectedVersions.
	introduced do: [ :v |
		v = '0'
			ifTrue: [ parts add: '>= 0' ]
			ifFalse: [ parts add: '>= ' , v ] ].
	fixed do: [ :v | parts add: '< ' , v ].
	lastAffected do: [ :v | parts add: '<= ' , v ].
	parts isEmpty ifTrue: [ ^ '(all versions)' ].
	^ ', ' join: parts
]

{ #category : 'accessing' }
Gt4SecurityVersionRange >> type [
	^ type
]

{ #category : 'accessing' }
Gt4SecurityVersionRange >> type: aString [
	type := aString
]
