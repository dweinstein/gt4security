"
Strategy that fetches a single vulnerability JSON document.

Applies only to queries with scope=#singleId. Cost is a flat ~10 KB (typical JSON size; HTTP/TLS overhead dominates). #execute: delegates to {{gtMethod:Gt4SecurityOsvFeedClient>>#fetchEcosystem:id:}} and returns a {{gtClass:Gt4SecurityVulnerability}}.
"
Class {
	#name : 'Gt4SecuritySingleIdStrategy',
	#superclass : 'Gt4SecurityFeedStrategy',
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'examples' }
Gt4SecuritySingleIdStrategy class >> exampleHandlesSingleIdOnly [
	<gtExample>
	| client ctx s |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	s := self new.
	self assert: (s canExecute: (Gt4SecurityFeedQuery singleId: 'X' inEcosystem: 'npm') inContext: ctx).
	self assert: (s canExecute: (Gt4SecurityFeedQuery fullEcosystem: 'Pub') inContext: ctx) not.
	^ s
]

{ #category : 'protocol' }
Gt4SecuritySingleIdStrategy >> canExecute: aQuery inContext: aContext [
	^ aQuery scope = #singleId
]

{ #category : 'cost' }
Gt4SecuritySingleIdStrategy >> costFor: aQuery inContext: aContext [
	"One JSON doc — a few KB typically."
	^ Gt4SecurityFeedCostModel singleIdFetchBytes
]

{ #category : 'accessing' }
Gt4SecuritySingleIdStrategy >> description [
	^ 'single-id fetch'
]

{ #category : 'protocol' }
Gt4SecuritySingleIdStrategy >> doExecute: aQuery on: aClient inContext: aContext [
	^ aClient fetchEcosystem: aQuery ecosystems first id: aQuery id
]

{ #category : 'ranking' }
Gt4SecuritySingleIdStrategy >> tiebreakPriority [
	"Narrowest scope — unambiguously the right choice when applicable."
	^ 10
]
