"
Abstract base class for OSV feed fetch strategies.

Each concrete subclass answers three polymorphic questions:
- canExecute: aQuery inContext: aContext  ->  Boolean applicability
- costFor: aQuery inContext: aContext  ->  Integer (estimated bytes over the wire; selector picks the lowest)
- execute: aQuery on: aClient inContext: aContext  ->  caller-visible result (shape depends on query scope)

#description returns a human-readable name (defaults to the class name). #printOn: delegates to #description so a strategy instance inspects nicely in GT. #subclassResponsibility marks the three abstract protocol methods.

Concrete strategies live in the same tag: {{gtClass:Gt4SecuritySingleIdStrategy}}, {{gtClass:Gt4SecurityFullEcosystemZipStrategy}}, {{gtClass:Gt4SecurityCachedCsvWindowStrategy}}, {{gtClass:Gt4SecurityStreamWindowStrategy}}, {{gtClass:Gt4SecurityHydratedWindowStrategy}}.
"
Class {
	#name : 'Gt4SecurityFeedStrategy',
	#superclass : 'Object',
	#classInstVars : [
		'uniqueInstance'
	],
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'instances' }
Gt4SecurityFeedStrategy class >> default [
	"Canonical per-class singleton. Strategies are stateless — the instance just dispatches
	behavior — so reusing one instance per concrete class is cheaper and makes selector lists
	identity-comparable. The class-instance var 'uniqueInstance' lives on each concrete
	subclass independently thanks to class-instance semantics."
	^ uniqueInstance ifNil: [ uniqueInstance := self new ]
]

{ #category : 'protocol' }
Gt4SecurityFeedStrategy >> canExecute: aQuery inContext: aContext [
	"Does this strategy apply to the given query in the current runtime context?"
	^ self subclassResponsibility
]

{ #category : 'protocol' }
Gt4SecurityFeedStrategy >> costFor: aQuery inContext: aContext [
	"Estimated bytes over the wire (roughly). Selector picks the cheapest applicable strategy.
	Near-zero values are used for revalidation paths that likely resolve to 304."
	^ self subclassResponsibility
]

{ #category : 'describing' }
Gt4SecurityFeedStrategy >> description [
	"Human-readable name used for logging / inspection. Every concrete strategy must define
	its own phrase — the class name alone is too coarse for the strategy trace view."
	^ self subclassResponsibility
]

{ #category : 'protocol' }
Gt4SecurityFeedStrategy >> doExecute: aQuery on: aClient inContext: aContext [
	"Concrete work — subclasses override. Run by execute:on:inContext: within a recording span."
	^ self subclassResponsibility
]

{ #category : 'protocol' }
Gt4SecurityFeedStrategy >> execute: aQuery on: aClient inContext: aContext [
	"Template method: record start, run the subclass-specific doExecute:, record end, return result.
	Recording means strategy choice is structured first-class metadata on the client history,
	not something views must reconstruct from HTTP request strings."
	| startedAt result |
	startedAt := aClient
		recordStrategyStart: self
		forQuery: aQuery
		cost: (self costFor: aQuery inContext: aContext).
	result := [ self doExecute: aQuery on: aClient inContext: aContext ]
		ensure: [ aClient recordStrategyEnd: self startedAt: startedAt ].
	^ result
]

{ #category : 'printing' }
Gt4SecurityFeedStrategy >> gtDisplayOn: aStream [
	"Inspector title for a strategy instance — 'Class · description'."
	aStream
		nextPutAll: self class name asString;
		nextPutAll: ' · ';
		nextPutAll: self description
]

{ #category : 'gt-views' }
Gt4SecurityFeedStrategy >> gtSummaryFor: aView [
	"Field-level summary of a feed-strategy instance — description, tiebreak priority, peer
	strategies. Used as the landing tab when a Gt4SecurityStrategySpan forwards into its
	strategy."
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 5;
		items: [ self summaryRows ];
		column: 'Field' text: [ :row | row first ] weight: 0.4;
		column: 'Value' text: [ :row | row third ] weight: 1;
		send: [ :row | row second ]
]

{ #category : 'printing' }
Gt4SecurityFeedStrategy >> printOn: aStream [
	aStream nextPutAll: self description
]

{ #category : 'printing' }
Gt4SecurityFeedStrategy >> summaryRows [
	"Field/value/display rows for the gtSummary view. Click-through values are preserved as
	domain objects (the class binding, the peer collection)."
	| peers |
	peers := self class superclass subclasses reject: [ :each | each = self class ].
	^ {
		{ 'Class'. self class. self class name }.
		{ 'Description'. self description. self description }.
		{ 'Tiebreak priority'. self tiebreakPriority. self tiebreakPriority asString }.
		{ 'Peer strategies'. peers. peers size asString , ' (' , (', ' join: (peers collect: [ :c | c name ])) , ')' } }
]

{ #category : 'ranking' }
Gt4SecurityFeedStrategy >> tiebreakPriority [
	"Lower = preferred on cost ties. Integers 1..999 (so cost * 1000 + priority stays monotone
	with cost). Subclasses override to encode preference when two strategies produce the same
	cost estimate (e.g. both short-circuit via If-Modified-Since)."
	^ 100
]
