"
A runtime-facts adapter over a {{gtClass:Gt4SecurityOsvFeedClient}}.

Exposes cheap boolean predicates (isCsvCacheAvailable, isEcosystemZipCacheAvailable:, isLargeEcosystem:) and small reads (cachedCsvSize, cachedModifiedIdsLastModified) that strategies and the selector use to evaluate applicability and cost WITHOUT triggering expensive I/O. No network or zip parsing happens through this class — it only inspects sidecar files and counter tables on the client.

Strategies treat FeedContext as read-only; they never mutate the client state through it.
"
Class {
	#name : 'Gt4SecurityFeedContext',
	#superclass : 'Object',
	#instVars : [
		'client',
		'selector'
	],
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'examples' }
Gt4SecurityFeedContext class >> exampleContextReflectsCache [
	<gtExample>
	| client ctx |
	client := Gt4SecurityOsvFeedClient new.
	ctx := self for: client.
	self assert: (ctx respondsTo: #isCsvCacheAvailable).
	self assert: ctx client == client.
	self assert: ctx summaryRows notEmpty.
	^ ctx
]

{ #category : 'instance creation' }
Gt4SecurityFeedContext class >> for: aClient [
	^ self new on: aClient
]

{ #category : 'queries' }
Gt4SecurityFeedContext >> cachedCsvSize [
	| target |
	target := client cachePathForModifiedIds.
	^ target exists ifTrue: [ target size ] ifFalse: [ 0 ]
]

{ #category : 'queries' }
Gt4SecurityFeedContext >> cachedModifiedIdsLastModified [
	"Return the stored Last-Modified header from the sidecar, or nil."
	| sidecar |
	sidecar := client cachePathForModifiedIdsLastModified.
	^ sidecar exists ifTrue: [ sidecar contents trimBoth ] ifFalse: [ nil ]
]

{ #category : 'accessing' }
Gt4SecurityFeedContext >> client [
	^ client
]

{ #category : 'accessing' }
Gt4SecurityFeedContext >> client: aClient [
	client := aClient
]

{ #category : 'gt - views' }
Gt4SecurityFeedContext >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 1;
		items: [ self summaryRows ];
		column: 'Fact' text: [ :row | row first ] weight: 0.5;
		column: 'Value' text: [ :row | row second displayString ] weight: 0.5
]

{ #category : 'queries' }
Gt4SecurityFeedContext >> isCsvCacheAvailable [
	"Cache file and its sidecar both exist — so a conditional GET can be made (likely cheap 304)."
	^ client cachePathForModifiedIds exists
		and: [ client cachePathForModifiedIdsLastModified exists ]
]

{ #category : 'queries' }
Gt4SecurityFeedContext >> isEcosystemZipCacheAvailable: anEcosystemString [
	"Zip + sidecar both present — so a conditional GET can be made."
	^ (client cachePathForEcosystemZip: anEcosystemString) exists
		and: [ (client cachePathForEcosystemZipLastModified: anEcosystemString) exists ]
]

{ #category : 'queries' }
Gt4SecurityFeedContext >> isEcosystemZipCached: anEcosystemString [
	^ (client cachePathForEcosystemZip: anEcosystemString) exists
]

{ #category : 'queries' }
Gt4SecurityFeedContext >> isLargeEcosystem: anEcosystemString [
	^ client isLargeEcosystem: anEcosystemString
]

{ #category : 'initialize-release' }
Gt4SecurityFeedContext >> on: aClient [
	client := aClient.
	^ self
]

{ #category : 'accessing' }
Gt4SecurityFeedContext >> selector [
	"The selector currently orchestrating strategy execution. Set by
	Gt4SecurityFeedStrategySelector>>#evaluate:on:inContext: so composite strategies
	(e.g. HydratedWindow) can dispatch inner sub-queries through the same ranking logic
	instead of hard-coding a choice."
	^ selector
]

{ #category : 'accessing' }
Gt4SecurityFeedContext >> selector: aSelector [
	selector := aSelector
]

{ #category : 'private' }
Gt4SecurityFeedContext >> summaryRows [
	^ {
		{ 'csv-cache-exists'. client cachePathForModifiedIds exists }.
		{ 'csv-cache-bytes'. self cachedCsvSize }.
		{ 'csv-sidecar-exists'. client cachePathForModifiedIdsLastModified exists }.
		{ 'csv-last-modified'. self cachedModifiedIdsLastModified }.
		{ 'cache-revalidatable'. self isCsvCacheAvailable } }
]
