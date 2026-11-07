Class {
	#name : 'Gt4SecurityStrategySpan',
	#superclass : 'Object',
	#instVars : [
		'strategy',
		'description',
		'ecosystems',
		'query',
		'cost',
		'startedAt',
		'endedAt',
		'durationMs',
		'calls',
		'bytes'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityStrategySpan class >> fromStartEntry: anEntry [
	"Seed a span from a strategyStart history event. The recorder now stores the live
	strategy instance under 'strategy', so we capture the domain object directly rather
	than just its class name."
	^ self new
		strategy: (anEntry at: 'strategy');
		description: (anEntry at: 'description' ifAbsent: [ '' ]);
		ecosystems: (anEntry at: 'ecosystems' ifAbsent: [ #() ]);
		query: (anEntry at: 'query' ifAbsent: [ nil ]);
		cost: (anEntry at: 'cost' ifAbsent: [ 0 ]);
		startedAt: (anEntry at: 'at');
		yourself
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> bytes [
	^ bytes
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> bytes: anInteger [
	bytes := anInteger
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> bytesDisplay [
	^ Gt4SecurityFormat humanBytes: bytes
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> calls [
	^ calls
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> calls: anInteger [
	calls := anInteger
]

{ #category : 'recording' }
Gt4SecurityStrategySpan >> closeWithEndEntry: anEntry [
	"Finalize a span by stamping endedAt and durationMs from the strategyEnd event."
	| endedAtTime |
	endedAtTime := anEntry at: 'at'.
	self
		endedAt: endedAtTime;
		durationMs: (endedAtTime - self startedAt) asMilliSeconds
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> cost [
	^ cost
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> cost: anInteger [
	cost := anInteger
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> description [
	^ description ifNil: [ '' ]
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> description: aString [
	description := aString
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> durationDisplay [
	^ Gt4SecurityFormat humanMs: self durationMs
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> durationMs [
	^ durationMs ifNil: [ 0 ]
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> durationMs: anInteger [
	durationMs := anInteger
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> ecosystems [
	^ ecosystems
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> ecosystems: aCollection [
	ecosystems := aCollection ifNil: [ #() ]
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> ecosystemsDisplay [
	"Comma-joined ecosystem names; '—' for empty. Saves the column block from inlining."
	^ ecosystems isEmpty
		ifTrue: [ '—' ]
		ifFalse: [ ', ' join: (ecosystems collect: [ :each | each asString ]) ]
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> endedAt [
	^ endedAt
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> endedAt: aDateAndTime [
	endedAt := aDateAndTime
]

{ #category : 'printing' }
Gt4SecurityStrategySpan >> gtDisplayOn: aStream [
	"Inspector title — short, no class-name doubling. Pattern:
	  '<Strategy> · <calls> calls · <bytes> · <duration>'"
	aStream nextPutAll: (self strategyName ifNil: [ '<unknown>' ]) asString.
	aStream nextPutAll: ' · '; print: calls; nextPutAll: ' calls'.
	aStream nextPutAll: ' · '; nextPutAll: self bytesDisplay.
	aStream nextPutAll: ' · '; nextPutAll: self durationDisplay
]

{ #category : 'gt-views' }
Gt4SecurityStrategySpan >> gtQueryFor: aView [
	"Forward into the Gt4SecurityFeedQuery domain object so the user can drill from a span
	row back into the structured query (window, ecosystems, etc.). Use an explicit view:
	so the forward lands on the query's gtSummaryFor: columned list rather than an
	unhelpful default that renders the printString as plain text."
	<gtView>
	query ifNil: [ ^ aView empty ].
	^ aView forward
		title: 'Query';
		priority: 20;
		object: [ query ];
		view: #gtSummaryFor:
]

{ #category : 'gt-views' }
Gt4SecurityStrategySpan >> gtStrategyFor: aView [
	"Forward into the live Gt4SecurityFeedStrategy instance so the user can drill from a
	span into the strategy's own summary (description, tiebreak priority, peers). Use an
	explicit view: so the forward lands on the strategy's gtSummaryFor: rather than the
	first-by-priority default."
	<gtView>
	strategy ifNil: [ ^ aView empty ].
	^ aView forward
		title: 'Strategy';
		priority: 30;
		object: [ strategy ];
		view: #gtSummaryFor:
]

{ #category : 'gt-views' }
Gt4SecurityStrategySpan >> gtSummaryFor: aView [
	"Field-level rollup of what this strategy did. Two-column key/value list backed by
	summaryRows — clicking a row spawns the inspector on the underlying value (strategy
	class, query, ecosystems collection, DateAndTime, etc.) thanks to send:."
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 5;
		items: [ self summaryRows ];
		column: 'Field' text: [ :row | row first ] weight: 0.4;
		column: 'Value' text: [ :row | row third ] weight: 1;
		send: [ :row | row second ]
]

{ #category : 'initialization' }
Gt4SecurityStrategySpan >> initialize [
	super initialize.
	ecosystems := #().
	cost := 0.
	calls := 0.
	bytes := 0
]

{ #category : 'printing' }
Gt4SecurityStrategySpan >> printOn: aStream [
	"Debug-friendly print: starts with the standard 'a Gt4SecurityStrategySpan' from super,
	then appends a compact summary in parens."
	super printOn: aStream.
	aStream nextPutAll: '('.
	self strategyName ifNotNil: [ :n | aStream nextPutAll: n asString; space ].
	aStream
		print: calls; nextPutAll: ' calls, ';
		nextPutAll: self bytesDisplay; nextPutAll: ', ';
		nextPutAll: self durationDisplay;
		nextPutAll: ')'
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> query [
	^ query
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> query: anObject [
	query := anObject
]

{ #category : 'recording' }
Gt4SecurityStrategySpan >> recordHttpEntry: anEntry [
	"Increment the rolled-up call/byte counts from a nested http history entry."
	calls := calls + 1.
	bytes := bytes + (anEntry at: 'bytes' ifAbsent: [ 0 ])
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> startedAt [
	^ startedAt
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> startedAt: aDateAndTime [
	startedAt := aDateAndTime
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> strategy [
	"The live Gt4SecurityFeedStrategy instance that ran for this span."
	^ strategy
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> strategy: aStrategyInstance [
	strategy := aStrategyInstance
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> strategyClass [
	"Class binding of the strategy that ran — derived from the live instance."
	^ strategy ifNotNil: [ :s | s class ]
]

{ #category : 'accessing' }
Gt4SecurityStrategySpan >> strategyName [
	"Symbol name of the strategy class — derived from the live strategy instance, falls
	back to nil when no instance was recorded."
	^ strategy ifNotNil: [ :s | s class name ]
]

{ #category : 'printing' }
Gt4SecurityStrategySpan >> summaryRows [
	"Field/value/display rows for the Summary gt-view. Each row is a 3-tuple
	{ label. clickValue. displayText. } — clickValue is preserved as the underlying
	domain object so columned-list send: can spawn its own inspector, while displayText
	is what gets rendered in the Value column."
	^ {
		{ 'Strategy'. strategy. self strategyName ifNil: [ '—' ] ifNotNil: [ :n | n asString ] }.
		{ 'Description'. self description. self description }.
		{ 'Ecosystems'. ecosystems. self ecosystemsDisplay }.
		{ 'Query'. query. query ifNil: [ '—' ] ifNotNil: [ query gtDisplayString ] }.
		{ 'Est. cost'. cost. cost asString }.
		{ 'HTTP calls'. calls. calls asString }.
		{ 'Bytes'. bytes. self bytesDisplay }.
		{ 'Duration'. self durationMs. self durationDisplay }.
		{ 'Started'. startedAt. Gt4SecurityFormat humanTime: startedAt }.
		{ 'Ended'. endedAt. Gt4SecurityFormat humanTime: endedAt } }
]
