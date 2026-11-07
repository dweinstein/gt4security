Class {
	#name : 'Gt4SecurityCisaKev',
	#superclass : 'Object',
	#instVars : [
		'exploitAddedDate',
		'actionDueDate',
		'requiredAction',
		'vulnerabilityName'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityCisaKev class >> fromNvdCve: aCveDict [
	"Build a Gt4SecurityCisaKev from an NVD cve dict, or nil if the CVE isn't in the KEV catalog.
	CISA KEV presence is indicated by cisaExploitAdd being non-nil."
	| added |
	added := aCveDict at: 'cisaExploitAdd' ifAbsent: [ nil ].
	added ifNil: [ ^ nil ].
	^ self new
		exploitAddedDate: added;
		actionDueDate: (aCveDict at: 'cisaActionDue' ifAbsent: [ nil ]);
		requiredAction: (aCveDict at: 'cisaRequiredAction' ifAbsent: [ nil ]);
		vulnerabilityName: (aCveDict at: 'cisaVulnerabilityName' ifAbsent: [ nil ]);
		yourself
]

{ #category : 'accessing' }
Gt4SecurityCisaKev >> actionDueDate [
	^ actionDueDate
]

{ #category : 'accessing' }
Gt4SecurityCisaKev >> actionDueDate: aString [
	actionDueDate := aString
]

{ #category : 'accessing' }
Gt4SecurityCisaKev >> exploitAddedDate [
	^ exploitAddedDate
]

{ #category : 'accessing' }
Gt4SecurityCisaKev >> exploitAddedDate: aString [
	exploitAddedDate := aString
]

{ #category : 'printing' }
Gt4SecurityCisaKev >> gtDisplayOn: aStream [
	aStream nextPutAll: 'CISA KEV: '.
	exploitAddedDate ifNotNil: [ aStream nextPutAll: 'added '; nextPutAll: exploitAddedDate ].
	actionDueDate ifNotNil: [ aStream nextPutAll: ', patch by '; nextPutAll: actionDueDate ]
]

{ #category : 'gt - views' }
Gt4SecurityCisaKev >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'CISA KEV entry';
		priority: 1;
		items: [ {
			'Vulnerability name' -> (vulnerabilityName ifNil: [ '(none)' ]).
			'Added to KEV catalog' -> (exploitAddedDate ifNil: [ '(unknown)' ]).
			'Patch deadline (federal)' -> (actionDueDate ifNil: [ '(unknown)' ]).
			'Required action' -> (requiredAction ifNil: [ '(none)' ]) } ];
		column: 'Property' text: [ :a | a key ] weight: 2;
		column: 'Value' text: [ :a | a value ] weight: 5
]

{ #category : 'printing' }
Gt4SecurityCisaKev >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (added ';
		nextPutAll: (exploitAddedDate ifNil: [ '?' ]);
		nextPutAll: ', due ';
		nextPutAll: (actionDueDate ifNil: [ '?' ]);
		nextPut: $)
]

{ #category : 'accessing' }
Gt4SecurityCisaKev >> requiredAction [
	^ requiredAction
]

{ #category : 'accessing' }
Gt4SecurityCisaKev >> requiredAction: aString [
	requiredAction := aString
]

{ #category : 'accessing' }
Gt4SecurityCisaKev >> vulnerabilityName [
	^ vulnerabilityName
]

{ #category : 'accessing' }
Gt4SecurityCisaKev >> vulnerabilityName: aString [
	vulnerabilityName := aString
]
