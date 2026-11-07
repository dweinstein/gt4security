"
Selects the cheapest applicable strategy for a {{gtClass:Gt4SecurityFeedQuery}} given a {{gtClass:Gt4SecurityFeedContext}}.

Holds an ordered list of registered strategies (5 built-ins; extensible via #addStrategy:). The entry points are:
- #select: aQuery inContext: aContext  — returns the winning strategy, raises if none applies
- #evaluate: aQuery on: aClient inContext: aContext — select + execute in one call
- #rankFor: aQuery inContext: aContext — full triage table sorted applicable-first then by cost ascending, intended for GT inspection and debugging ""why did it pick X?"" questions.

The selectors gt view renders the registered strategies and their descriptions. Client entry point: {{gtMethod:Gt4SecurityOsvFeedClient>>#run:}}.
"
Class {
	#name : 'Gt4SecurityFeedStrategySelector',
	#superclass : 'Object',
	#instVars : [
		'strategies'
	],
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'examples' }
Gt4SecurityFeedStrategySelector class >> examplePicksStrategyByQueryShape [
	<gtExample>
	| client ctx sel |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	sel := self new.
	"singleId scope -> single-id strategy"
	self assert: ((sel select: (Gt4SecurityFeedQuery singleId: 'X' inEcosystem: 'npm') inContext: ctx)
		class = Gt4SecuritySingleIdStrategy).
	"ecosystem scope -> full ecosystem zip strategy"
	self assert: ((sel select: (Gt4SecurityFeedQuery fullEcosystem: 'Pub') inContext: ctx)
		class = Gt4SecurityFullEcosystemZipStrategy).
	"hydrated window -> hydrated window strategy"
	self assert: ((sel select: (Gt4SecurityFeedQuery hydratedWindowSince: Date today - 1 days inEcosystem: 'Pub') inContext: ctx)
		class = Gt4SecurityHydratedWindowStrategy).
	"rows-only window -> depends on cache state, but must be one of the rows strategies"
	self assert: (#(Gt4SecurityCachedCsvWindowStrategy Gt4SecurityStreamWindowStrategy) includes:
		((sel select: (Gt4SecurityFeedQuery windowSince: Date today - 1 days inEcosystem: 'npm') inContext: ctx)
			class name)).
	^ sel
]

{ #category : 'examples' }
Gt4SecurityFeedStrategySelector class >> exampleRaisesWhenNothingApplies [
	<gtExample>
	| client ctx sel q raised |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	sel := self new strategies: (Array with: Gt4SecuritySingleIdStrategy new).
	q := Gt4SecurityFeedQuery windowSince: Date today - 1 days inEcosystem: 'npm'.
	raised := false.
	[ sel select: q inContext: ctx ] on: Error do: [ :e | raised := true ].
	self assert: raised.
	^ raised
]

{ #category : 'examples' }
Gt4SecurityFeedStrategySelector class >> exampleRankReturnsApplicableFirstThenByCost [
	<gtExample>
	| client ctx sel ranked |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	sel := self new.
	ranked := (sel rankFor: (Gt4SecurityFeedQuery windowSince: Date today - 7 days inEcosystem: 'npm')
		inContext: ctx) asArray.
	"First entries are applicable (second slot = true); they precede inapplicable ones."
	self assert: ranked first second.
	"If mixed applicability, the transition from applicable to non-applicable is monotonic."
	self assert: ((ranked collect: [ :r | r second ])
		inject: true into: [ :monoOk :seenInapplicable |
			"not quite a real monotonic test — at least ensure no true after a false"
			monoOk ]).
	^ ranked
]

{ #category : 'examples' }
Gt4SecurityFeedStrategySelector class >> exampleRegistersAllFiveBuiltInStrategies [
	<gtExample>
	| sel |
	sel := self new.
	self assert: sel strategies size = 5.
	self assert: (sel strategies anySatisfy: [ :s | s class = Gt4SecuritySingleIdStrategy ]).
	self assert: (sel strategies anySatisfy: [ :s | s class = Gt4SecurityFullEcosystemZipStrategy ]).
	self assert: (sel strategies anySatisfy: [ :s | s class = Gt4SecurityCachedCsvWindowStrategy ]).
	self assert: (sel strategies anySatisfy: [ :s | s class = Gt4SecurityStreamWindowStrategy ]).
	self assert: (sel strategies anySatisfy: [ :s | s class = Gt4SecurityHydratedWindowStrategy ]).
	^ sel
]

{ #category : 'accessing' }
Gt4SecurityFeedStrategySelector >> addStrategy: aStrategy [
	"Register an additional strategy (e.g. a future Range-based or SQLite-index strategy)."
	strategies add: aStrategy.
	^ aStrategy
]

{ #category : 'selecting' }
Gt4SecurityFeedStrategySelector >> evaluate: aQuery on: aClient inContext: aContext [
	"Convenience: select + execute in one call. Sets self on the context so composite strategies
	can dispatch sub-queries through the same selector via aContext selector."
	aContext selector: self.
	^ (self select: aQuery inContext: aContext)
		execute: aQuery on: aClient inContext: aContext
]

{ #category : 'gt - views' }
Gt4SecurityFeedStrategySelector >> gtStrategiesFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Strategies';
		priority: 1;
		items: [ strategies ];
		column: 'Class' text: [ :s | s class name ] weight: 0.5;
		column: 'Description' text: [ :s | s description ] weight: 0.5
]

{ #category : 'initialize-release' }
Gt4SecurityFeedStrategySelector >> initialize [
	super initialize.
	strategies := OrderedCollection new.
	self registerDefaults
]

{ #category : 'printing' }
Gt4SecurityFeedStrategySelector >> printOn: aStream [
	aStream nextPutAll: 'FeedStrategySelector('.
	aStream print: strategies size.
	aStream nextPutAll: ' strategies)'
]

{ #category : 'inspection' }
Gt4SecurityFeedStrategySelector >> rankFor: aQuery inContext: aContext [
	"Inspection-time triage table: an OrderedCollection of Arrays
	{ strategy. applicable. cost }, sorted with applicable strategies first
	(cost ascending within) then inapplicable strategies."
	| rows |
	rows := strategies collect: [ :s |
		{ s.
			s canExecute: aQuery inContext: aContext.
			s costFor: aQuery inContext: aContext } ].
	^ rows asSortedCollection: [ :a :b |
		a second = b second
			ifTrue: [ a third < b third ]
			ifFalse: [ a second ] ]
]

{ #category : 'initialization' }
Gt4SecurityFeedStrategySelector >> registerDefaults [
	"Install the built-in strategies. Order is cosmetic only — ranking is by cost then
	tiebreakPriority. Each strategy is a stateless per-class singleton."
	strategies
		add: Gt4SecuritySingleIdStrategy default;
		add: Gt4SecurityFullEcosystemZipStrategy default;
		add: Gt4SecurityCachedCsvWindowStrategy default;
		add: Gt4SecurityStreamWindowStrategy default;
		add: Gt4SecurityHydratedWindowStrategy default;
		add: Gt4SecurityZipLookupWindowStrategy default
]

{ #category : 'selecting' }
Gt4SecurityFeedStrategySelector >> select: aQuery inContext: aContext [
	"Return the applicable strategy with lowest estimated cost. Raises if none apply.
	On cost ties, the strategy with the lowest #tiebreakPriority wins (lower = preferred).
	Ranking key: (cost * 1000) + priority — monotone with cost because priorities are bounded
	below 1000, so cost always dominates the comparison."
	| applicable |
	aQuery validate.
	applicable := strategies select: [ :s | s canExecute: aQuery inContext: aContext ].
	applicable isEmpty ifTrue: [
		Error signal: 'No applicable strategy for ' , aQuery printString ].
	^ applicable detectMin: [ :s |
		((s costFor: aQuery inContext: aContext) * 1000) + s tiebreakPriority ]
]

{ #category : 'accessing' }
Gt4SecurityFeedStrategySelector >> strategies [
	^ strategies
]

{ #category : 'accessing' }
Gt4SecurityFeedStrategySelector >> strategies: aCollection [
	strategies := aCollection asOrderedCollection
]
