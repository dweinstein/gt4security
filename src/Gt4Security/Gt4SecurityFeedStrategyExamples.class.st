"
Live end-to-end examples for the OSV feed Strategy pattern.

Exercises each of the five registered strategies and the selectors rank/evaluate
paths against the real OSV CDN at storage.googleapis.com. All examples are tagged
<noTest> so they are skipped during automated test sweeps but remain runnable from
the inspector. Behavioral assertions (applicability, cost monotonicity, constructor
validation) live next to each strategy class itself as offline examples.

Run from an inspector to see the live network flow; each example returns an
inspectable result so you can drill into vulnerabilities, rows, strategy rank tables,
or history on the feed client.
"
Class {
	#name : 'Gt4SecurityFeedStrategyExamples',
	#superclass : 'Object',
	#category : 'Gt4Security-Examples',
	#package : 'Gt4Security',
	#tag : 'Examples'
}

{ #category : 'examples - window rows' }
Gt4SecurityFeedStrategyExamples >> cachedCsvWindowOneDayNpm [
	"Live: rows for the last day of npm via {{gtClass:Gt4SecurityCachedCsvWindowStrategy}}.
	Revalidates the modified_id.csv cache (304 if warm) then scans locally for npm timestamps."
	<gtExample>
	<noTest>
	<return: #OrderedCollection>
	| client ctx strategy query rows |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	strategy := Gt4SecurityCachedCsvWindowStrategy new.
	query := Gt4SecurityFeedQuery windowSince: Date today - 1 days inEcosystem: 'npm'.
	self assert: (strategy canExecute: query inContext: ctx).
	rows := strategy execute: query on: client inContext: ctx.
	self assert: rows class equals: OrderedCollection.
	rows do: [ :row |
		self assert: (row at: 'ecosystem') equals: 'npm'.
		self assert: (row at: 'timestamp') >= ((Date today - 1 days) asDateAndTime printString copyFrom: 1 to: 10) ].
	^ rows
]

{ #category : 'examples - client run:' }
Gt4SecurityFeedStrategyExamples >> clientRunEntryPointForHydratedMobileWindow [
	"Live: end-to-end via the {{gtMethod:Gt4SecurityOsvFeedClient>>#run:}} entry point.
	1-day mobile window with moderate concurrency. Exercises query construction, selector,
	strategy dispatch, and result hydration."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerabilityGroup>
	| client query result |
	client := Gt4SecurityOsvFeedClient new.
	query := (Gt4SecurityFeedQuery mobileWindowSince: Date today - 1 days)
		concurrency: 16;
		yourself.
	result := client run: query.
	self assert: result class equals: Gt4SecurityVulnerabilityGroup.
	^ result
]

{ #category : 'examples - ecosystem' }
Gt4SecurityFeedStrategyExamples >> fullEcosystemZipCostDropsWithWarmCache [
	"Live: verify the cost model — warm (cache + sidecar) << cold (no cache), using Pub.
	Formerly Gt4SecurityFullEcosystemZipStrategy class>>#exampleCostsLessWhenCacheRevalidatable;
	migrated here because it hits the live feed."
	<gtExample>
	<noTest>
	<return: #Association>
	| warmClient warmCtx coldClient coldCtx strategy query warmCost coldCost |
	warmClient := Gt4SecurityOsvFeedClient new.
	warmCtx := Gt4SecurityFeedContext for: warmClient.
	strategy := Gt4SecurityFullEcosystemZipStrategy new.
	query := Gt4SecurityFeedQuery fullEcosystem: 'Pub'.
	(warmCtx isEcosystemZipCacheAvailable: 'Pub')
		ifFalse: [ warmClient downloadEcosystemZip: 'Pub' ].
	coldClient := Gt4SecurityOsvFeedClient new.
	coldClient cacheDirectory: (FileLocator temp asFileReference / ('gt4sec-cold-' , UUID new asString)).
	coldCtx := Gt4SecurityFeedContext for: coldClient.
	warmCost := strategy costFor: query inContext: warmCtx.
	coldCost := strategy costFor: query inContext: coldCtx.
	self assert: warmCost < 10000.
	self assert: coldCost > 1000000.
	self assert: warmCost < coldCost.
	^ 'warm' -> warmCost -> coldCost
]

{ #category : 'examples - ecosystem' }
Gt4SecurityFeedStrategyExamples >> fullEcosystemZipViaStrategy [
	"Live: Pub all.zip via {{gtClass:Gt4SecurityFullEcosystemZipStrategy}}.
	Pub is small (~20 KB) and cache-friendly for quick verification of the whole pipeline."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerabilityGroup>
	| client ctx strategy query result |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	strategy := Gt4SecurityFullEcosystemZipStrategy new.
	query := Gt4SecurityFeedQuery fullEcosystem: 'Pub'.
	self assert: (strategy canExecute: query inContext: ctx).
	result := strategy execute: query on: client inContext: ctx.
	self assert: result class equals: Gt4SecurityVulnerabilityGroup.
	self assert: result items notEmpty.
	^ result
]

{ #category : 'examples - hydrated window' }
Gt4SecurityFeedStrategyExamples >> hydratedWindowNinetyDaysPub [
	"Live: 90-day Pub window hydrated to full vulnerabilities via {{gtClass:Gt4SecurityHydratedWindowStrategy}}.
	Pipelines rows scan (cached or stream) + parallel per-ID fetch."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerabilityGroup>
	| client ctx strategy query result |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	strategy := Gt4SecurityHydratedWindowStrategy new.
	query := (Gt4SecurityFeedQuery hydratedWindowSince: Date today - 90 days inEcosystem: 'Pub')
		concurrency: 4;
		yourself.
	self assert: (strategy canExecute: query inContext: ctx).
	result := strategy execute: query on: client inContext: ctx.
	self assert: result class equals: Gt4SecurityVulnerabilityGroup.
	result items do: [ :v | self assert: v id notNil ].
	^ result
]

{ #category : 'examples - selector' }
Gt4SecurityFeedStrategyExamples >> selectorPicksCheapestForSevenDayNpmRows [
	"Live: show the selectors triage table for a representative rows-only query.
	With a warm CSV cache, CachedCsvWindow wins on bytes (1 KB vs Stream ~3.5 MB for 7d).
	With a cold cache, Stream wins (~3.5 MB vs 42 MB full CSV download)."
	<gtExample>
	<noTest>
	<return: #Dictionary>
	| client ctx sel query winner ranked |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	sel := Gt4SecurityFeedStrategySelector new.
	query := Gt4SecurityFeedQuery windowSince: Date today - 7 days inEcosystem: 'npm'.
	winner := sel select: query inContext: ctx.
	ranked := (sel rankFor: query inContext: ctx) asArray collect: [ :row |
		row first description , ' (applicable=' , row second displayString
			, ' cost=' , row third displayString , ')' ].
	self assert: (#(Gt4SecurityCachedCsvWindowStrategy Gt4SecurityStreamWindowStrategy)
		includes: winner class name).
	^ Dictionary new
		at: 'winner' put: winner description;
		at: 'ranked' put: ranked;
		yourself
]

{ #category : 'examples - single id' }
Gt4SecurityFeedStrategyExamples >> singleIdFetchViaStrategy [
	"Live: fetch a single npm vulnerability JSON via {{gtClass:Gt4SecuritySingleIdStrategy}}."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerability>
	| client ctx strategy query result |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	strategy := Gt4SecuritySingleIdStrategy new.
	query := Gt4SecurityFeedQuery singleId: 'GHSA-7xr2-q9vf-x4r5' inEcosystem: 'npm'.
	self assert: (strategy canExecute: query inContext: ctx).
	result := strategy execute: query on: client inContext: ctx.
	self assert: result class equals: Gt4SecurityVulnerability.
	self assert: result id equals: 'GHSA-7xr2-q9vf-x4r5'.
	^ result
]

{ #category : 'examples - window rows' }
Gt4SecurityFeedStrategyExamples >> streamingVersusCachedReturnsSameRows [
	"Live: same 1-day npm window via both rows-producing strategies — the row sets should agree.
	This is the regression signal for either path silently diverging from the other."
	<gtExample>
	<noTest>
	<return: #Dictionary>
	| client ctx cached stream query cachedRows streamRows cachedIds streamIds |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	cached := Gt4SecurityCachedCsvWindowStrategy new.
	stream := Gt4SecurityStreamWindowStrategy new.
	query := Gt4SecurityFeedQuery windowSince: Date today - 1 days inEcosystem: 'npm'.
	cachedRows := cached execute: query on: client inContext: ctx.
	streamRows := stream execute: query on: client inContext: ctx.
	cachedIds := (cachedRows collect: [ :r | r at: 'id' ]) asSet.
	streamIds := (streamRows collect: [ :r | r at: 'id' ]) asSet.
	self assert: cachedIds equals: streamIds.
	^ Dictionary new
		at: 'cached-count' put: cachedRows size;
		at: 'stream-count' put: streamRows size;
		at: 'ids-equal' put: (cachedIds = streamIds);
		yourself
]

{ #category : 'examples - window rows' }
Gt4SecurityFeedStrategyExamples >> streamingWindowOneDayNpm [
	"Live: rows for the last day of npm via {{gtClass:Gt4SecurityStreamWindowStrategy}}.
	Streams modified_id.csv with early termination; does NOT touch the disk cache."
	<gtExample>
	<noTest>
	<return: #OrderedCollection>
	| client ctx strategy query rows |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	strategy := Gt4SecurityStreamWindowStrategy new.
	query := Gt4SecurityFeedQuery windowSince: Date today - 1 days inEcosystem: 'npm'.
	self assert: (strategy canExecute: query inContext: ctx).
	rows := strategy execute: query on: client inContext: ctx.
	self assert: rows class equals: OrderedCollection.
	self assert: ((client history last at: 'request') includesSubstring: 'stream').
	^ rows
]
