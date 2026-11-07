"
Rows-only window strategy that streams modified_id.csv with early termination.

Applies to any scope=#window with needFullRecords=false. Does NOT touch the disk cache: opens a streaming ZnClient GET, reads lines one at a time through a UTF-8 decoded character stream, and closes the socket as soon as a timestamp older than the since cutoff appears. This works because the feed is sorted strictly newest-first (0 violations across 836,880 rows verified April 2026).

Cost: roughly 500 KB per day in the window, capped at the full file size (~42 MB). For windows shorter than ~90 days this is the bandwidth-optimal rows path; for longer windows the cached path tends to win.
"
Class {
	#name : 'Gt4SecurityStreamWindowStrategy',
	#superclass : 'Gt4SecurityFeedStrategy',
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'examples' }
Gt4SecurityStreamWindowStrategy class >> exampleApplicableForRowsWindow [
	<gtExample>
	| client ctx s |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	s := self new.
	self assert: (s canExecute: (Gt4SecurityFeedQuery windowSince: Date today - 7 days inEcosystem: 'npm') inContext: ctx).
	self assert: (s canExecute: (Gt4SecurityFeedQuery hydratedWindowSince: Date today - 1 days inEcosystem: 'Pub') inContext: ctx) not.
	^ s
]

{ #category : 'examples' }
Gt4SecurityStreamWindowStrategy class >> exampleCostScalesWithWindowSize [
	<gtExample>
	| client ctx s c1 c7 c90 |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	s := self new.
	c1 := s costFor: (Gt4SecurityFeedQuery windowSince: Date today - 1 days) inContext: ctx.
	c7 := s costFor: (Gt4SecurityFeedQuery windowSince: Date today - 7 days) inContext: ctx.
	c90 := s costFor: (Gt4SecurityFeedQuery windowSince: Date today - 90 days) inContext: ctx.
	self assert: c1 < c7.
	self assert: c7 < c90.
	^ { c1. c7. c90 }
]

{ #category : 'protocol' }
Gt4SecurityStreamWindowStrategy >> canExecute: aQuery inContext: aContext [
	"Rows-only window queries. Always applicable — streams directly from the network, no cache needed."
	^ aQuery scope = #window and: [ aQuery needFullRecords not ]
]

{ #category : 'cost' }
Gt4SecurityStreamWindowStrategy >> costFor: aQuery inContext: aContext [
	"Empirically ~500 KB per day in the window, capped at the full file size. The feed is sorted
	newest-first, so the connection closes as soon as we see a row older than the cutoff."
	| days bytes |
	aQuery since ifNil: [ ^ Gt4SecurityFeedCostModel modifiedIdsFullBytes ].
	days := (DateAndTime now - aQuery since asDateAndTime) asDays asInteger max: 1.
	bytes := (days * Gt4SecurityFeedCostModel modifiedIdsBytesPerDay)
		min: Gt4SecurityFeedCostModel modifiedIdsFullBytes.
	^ bytes
]

{ #category : 'accessing' }
Gt4SecurityStreamWindowStrategy >> description [
	^ 'streaming modified_id.csv with early termination'
]

{ #category : 'protocol' }
Gt4SecurityStreamWindowStrategy >> doExecute: aQuery on: aClient inContext: aContext [
	| rows ecoSet |
	rows := OrderedCollection new.
	ecoSet := aQuery ecosystems ifNotNil: [ :e | e asSet ].
	aClient streamModifiedIdsSince: aQuery since do: [ :row |
		(ecoSet isNil or: [ ecoSet includes: (row at: 'ecosystem') ])
			ifTrue: [ rows add: row ] ].
	^ rows
]

{ #category : 'ranking' }
Gt4SecurityStreamWindowStrategy >> tiebreakPriority [
	"Second choice for windowed-rows queries — used when the CSV cache is unavailable."
	^ 50
]
