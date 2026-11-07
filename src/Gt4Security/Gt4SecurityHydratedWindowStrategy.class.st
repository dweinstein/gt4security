"
Window strategy that returns fully-hydrated vulnerability records.

Applies to scope=#window with needFullRecords=true. Pipelines a rows-producing sub-strategy (picked by {{gtMethod:Gt4SecurityHydratedWindowStrategy>>#rowsStrategyFor:}} — {{gtClass:Gt4SecurityCachedCsvWindowStrategy}} when the CSV cache is revalidatable, {{gtClass:Gt4SecurityStreamWindowStrategy}} otherwise) with a parallel per-ID fetch via {{gtMethod:Gt4SecurityOsvFeedClient>>#fetchVulnsFromRows:concurrency:}}.

Cost model: rows-source cost + estimated per-ID transfer. Empirical baseline: ~800 rows/day on modified_id.csv, ~10 KB per vulnerability JSON. Selector will prefer this over {{gtClass:Gt4SecurityFullEcosystemZipStrategy}} for most windowed queries since only the modified-window rows need per-ID fetching.
"
Class {
	#name : 'Gt4SecurityHydratedWindowStrategy',
	#superclass : 'Gt4SecurityFeedStrategy',
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'examples' }
Gt4SecurityHydratedWindowStrategy class >> exampleApplicableOnlyForHydratedWindow [
	<gtExample>
	| client ctx s |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	s := self new.
	self assert: (s canExecute: (Gt4SecurityFeedQuery hydratedWindowSince: Date today - 1 days inEcosystem: 'Pub') inContext: ctx).
	self assert: (s canExecute: (Gt4SecurityFeedQuery windowSince: Date today - 1 days inEcosystem: 'Pub') inContext: ctx) not.
	^ s
]

{ #category : 'examples' }
Gt4SecurityHydratedWindowStrategy class >> exampleRowsStrategyPicksCachedWhenAvailable [
	<gtExample>
	| s warmClient coldClient warmCtx coldCtx |
	s := self new.
	warmClient := Gt4SecurityOsvFeedClient new.
	warmCtx := Gt4SecurityFeedContext for: warmClient.
	coldClient := Gt4SecurityOsvFeedClient new.
	coldClient cacheDirectory: (FileLocator temp asFileReference / ('gt4sec-hydrated-ex-cold-' , UUID new asString)).
	coldCtx := Gt4SecurityFeedContext for: coldClient.
	self assert: ((s rowsStrategyFor: coldCtx) isKindOf: Gt4SecurityStreamWindowStrategy).
	warmCtx isCsvCacheAvailable ifTrue: [
		self assert: ((s rowsStrategyFor: warmCtx) isKindOf: Gt4SecurityCachedCsvWindowStrategy) ].
	^ s
]

{ #category : 'protocol' }
Gt4SecurityHydratedWindowStrategy >> canExecute: aQuery inContext: aContext [
	^ aQuery scope = #window and: [ aQuery needFullRecords ]
]

{ #category : 'ranking' }
Gt4SecurityHydratedWindowStrategy >> costFor: aQuery inContext: aContext [
	"Rows cost + per-id hydration cost. Rows cost matches stream-window (or the revalidate
	handshake if the CSV cache is fresh). Hydration is ~10 KB per id across an estimated
	~800 modifications per day aggregate — scaled down by ecosystemRowShareFactor when the
	query targets a specific ecosystem set, since the aggregate 800/day is spread across
	~20 ecosystems."
	| days rowsCost ecoCount perDay estimatedRows |
	days := aQuery since
		ifNil: [ Gt4SecurityFeedCostModel defaultWindowDays ]
		ifNotNil: [ (DateAndTime now - aQuery since asDateAndTime) asDays asInteger max: 1 ].
	rowsCost := aContext isCsvCacheAvailable
		ifTrue: [ Gt4SecurityFeedCostModel revalidateHandshakeBytes ]
		ifFalse: [ (days * Gt4SecurityFeedCostModel modifiedIdsBytesPerDay)
			min: Gt4SecurityFeedCostModel modifiedIdsFullBytes ].
	ecoCount := aQuery ecosystems ifNil: [ 0 ] ifNotNil: [ :e | e size ].
	perDay := ecoCount = 0
		ifTrue: [ Gt4SecurityFeedCostModel modifiedIdsRowsPerDay ]
		ifFalse: [ (Gt4SecurityFeedCostModel modifiedIdsRowsPerDay
			* ecoCount / Gt4SecurityFeedCostModel ecosystemRowShareFactor) ceiling max: 1 ].
	estimatedRows := days * perDay.
	^ rowsCost + (estimatedRows * Gt4SecurityFeedCostModel perIdFetchBytes)
]

{ #category : 'accessing' }
Gt4SecurityHydratedWindowStrategy >> description [
	^ 'windowed rows + parallel per-id fetch'
]

{ #category : 'executing' }
Gt4SecurityHydratedWindowStrategy >> doExecute: aQuery on: aClient inContext: aContext [
	"Build an inner rows-only window query and dispatch it through the selector on the context,
	which picks the cheapest applicable rows-producing strategy (typically CachedCsvWindow when
	the CSV cache exists, else StreamWindow). Fall back to the local rowsStrategyFor: heuristic
	if no selector is attached (e.g. a strategy invoked directly for testing). The inner call
	records its own strategy span, so strategyTraceRows surfaces the composition."
	| rowsQuery rowsStrategy rows vulns |
	rowsQuery := Gt4SecurityFeedQuery new
		scope: #window;
		since: aQuery since;
		ecosystems: aQuery ecosystems;
		needFullRecords: false;
		yourself.
	rowsStrategy := aContext selector
		ifNotNil: [ :s | s select: rowsQuery inContext: aContext ]
		ifNil: [ self rowsStrategyFor: aContext ].
	rows := rowsStrategy execute: rowsQuery on: aClient inContext: aContext.
	vulns := aClient fetchVulnsFromRows: rows concurrency: aQuery concurrency.
	^ Gt4SecurityVulnerabilityGroup withAll: vulns
]

{ #category : 'executing' }
Gt4SecurityHydratedWindowStrategy >> rowsStrategyFor: aContext [
	"Pick the cheapest rows-producing strategy. Prefer cache revalidation when we have one."
	^ aContext isCsvCacheAvailable
		ifTrue: [ Gt4SecurityCachedCsvWindowStrategy default ]
		ifFalse: [ Gt4SecurityStreamWindowStrategy default ]
]

{ #category : 'ranking' }
Gt4SecurityHydratedWindowStrategy >> tiebreakPriority [
	"Heaviest — rows + per-id hydration. Distinct scope (needFullRecords) usually keeps it out
	of tie situations, but we rank it last."
	^ 60
]
