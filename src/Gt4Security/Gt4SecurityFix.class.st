Class {
	#name : 'Gt4SecurityFix',
	#superclass : 'Object',
	#instVars : [
		'url',
		'rawDict'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityFix class >> fromUrl: aString [
	"OSV ecosystem_specific fixes are bare URL strings."
	^ self new
		url: aString;
		rawDict: (Dictionary new at: 'url' put: aString; yourself);
		yourself
]

{ #category : 'querying' }
Gt4SecurityFix >> commitHash [
	"Parse the git commit hash from googlesource/github-style URLs (…/+/<hash> or …/commit/<hash>). Nil if not parseable."
	| idx rest |
	url ifNil: [ ^ nil ].
	idx := url indexOfSubCollection: '/+/'.
	idx > 0 ifTrue: [
		rest := url copyFrom: idx + 3 to: url size.
		^ (rest indexOf: $/) = 0
			ifTrue: [ rest ]
			ifFalse: [ rest copyFrom: 1 to: (rest indexOf: $/) - 1 ] ].
	idx := url indexOfSubCollection: '/commit/'.
	idx > 0 ifTrue: [
		rest := url copyFrom: idx + 8 to: url size.
		^ (rest indexOf: $/) = 0
			ifTrue: [ rest ]
			ifFalse: [ rest copyFrom: 1 to: (rest indexOf: $/) - 1 ] ].
	^ nil
]

{ #category : 'gt - actions' }
Gt4SecurityFix >> gtOpenInBrowserActionFor: anAction [
	<gtAction>
	url ifNil: [ ^ anAction noAction ].
	^ anAction button
		tooltip: 'Open commit in browser';
		icon: BrGlamorousVectorIcons browse;
		action: [ WebBrowser openOn: url ]
]

{ #category : 'gt - views' }
Gt4SecurityFix >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 1;
		items: [ {
			'Repo' -> (self repoPath ifNil: [ '(unparseable)' ]).
			'Commit' -> (self commitHash ifNil: [ '(unparseable)' ]).
			'Short hash' -> (self shortHash ifNil: [ '-' ]).
			'URL' -> (url ifNil: [ '(none)' ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 4
]

{ #category : 'printing' }
Gt4SecurityFix >> printOn: aStream [
	aStream nextPutAll: 'Fix('.
	self shortHash ifNotNil: [ :h | aStream nextPutAll: h ] ifNil: [ aStream nextPutAll: (url ifNil: [ '?' ]) ].
	aStream nextPut: $)
]

{ #category : 'accessing' }
Gt4SecurityFix >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityFix >> rawDict: aDict [
	rawDict := aDict
]

{ #category : 'querying' }
Gt4SecurityFix >> repoPath [
	"Extract repo path from googlesource URL — e.g. 'kernel/common' for android.googlesource.com/kernel/common/+/<hash>. Nil if not parseable."
	| idx host rest slashIdx |
	url ifNil: [ ^ nil ].
	idx := url indexOfSubCollection: '://'.
	idx = 0 ifTrue: [ ^ nil ].
	rest := url copyFrom: idx + 3 to: url size.
	slashIdx := rest indexOf: $/.
	slashIdx = 0 ifTrue: [ ^ nil ].
	host := rest copyFrom: 1 to: slashIdx - 1.
	rest := rest copyFrom: slashIdx + 1 to: rest size.
	idx := rest indexOfSubCollection: '/+/'.
	idx > 0 ifTrue: [ ^ rest copyFrom: 1 to: idx - 1 ].
	idx := rest indexOfSubCollection: '/commit/'.
	idx > 0 ifTrue: [ ^ rest copyFrom: 1 to: idx - 1 ].
	^ nil
]

{ #category : 'querying' }
Gt4SecurityFix >> shortHash [
	"First 12 chars of the commit hash, or nil."
	^ self commitHash ifNotNil: [ :h | h copyFrom: 1 to: (h size min: 12) ]
]

{ #category : 'accessing' }
Gt4SecurityFix >> url [
	^ url
]

{ #category : 'accessing' }
Gt4SecurityFix >> url: aString [
	url := aString
]
