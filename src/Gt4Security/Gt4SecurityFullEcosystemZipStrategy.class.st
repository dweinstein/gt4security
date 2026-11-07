"
Strategy that downloads and parses an ecosystems all.zip.

Applies only to scope=#ecosystem. Refuses cold large-ecosystem downloads (npm, Debian, Ubuntu, AlmaLinux, Rocky, Red Hat, SUSE) unless acceptLargeDownload: is set on the query. For multi-ecosystem queries, iterates each ecosystem and merges the results into a single {{gtClass:Gt4SecurityVulnerabilityGroup}}.

Cost model:
- ~1 KB per ecosystem when its zip is already cached (304 revalidation handshake)
- ~10 MB per ecosystem for small ones cold
- ~100 MB per ecosystem for large ones cold
This makes the selector rank revalidation-friendly queries far below cold ones.
"
Class {
	#name : 'Gt4SecurityFullEcosystemZipStrategy',
	#superclass : 'Gt4SecurityFeedStrategy',
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'examples' }
Gt4SecurityFullEcosystemZipStrategy class >> exampleRefusesLargeColdWithoutAccept [
	<gtExample>
	| client ctx s q |
	client := Gt4SecurityOsvFeedClient new.
	ctx := Gt4SecurityFeedContext for: client.
	s := self new.
	q := Gt4SecurityFeedQuery fullEcosystem: 'npm'.
	"npm is large. If not cached, not applicable."
	(ctx isEcosystemZipCached: 'npm') ifFalse: [
		self assert: (s canExecute: q inContext: ctx) not.
		q acceptLargeDownload: true.
		self assert: (s canExecute: q inContext: ctx) ].
	^ s
]

{ #category : 'protocol' }
Gt4SecurityFullEcosystemZipStrategy >> canExecute: aQuery inContext: aContext [
	"Handles scope=#ecosystem. Refuses to start a large download unless the zip is already cached
	or the caller opted in via acceptLargeDownload: true."
	aQuery scope = #ecosystem ifFalse: [ ^ false ].
	aQuery ecosystems ifNil: [ ^ false ].
	aQuery ecosystems do: [ :eco |
		(aQuery acceptLargeDownload not
			and: [ (aContext isEcosystemZipCached: eco) not
			and: [ aContext isLargeEcosystem: eco ] ])
				ifTrue: [ ^ false ] ].
	^ true
]

{ #category : 'cost' }
Gt4SecurityFullEcosystemZipStrategy >> costFor: aQuery inContext: aContext [
	"Revalidation = ~1 KB (304 handshake). Cold download = ~10 MB for small ecosystems,
	~100 MB for large ones. See Gt4SecurityFeedCostModel for the tunable constants."
	| bytes |
	bytes := 0.
	aQuery ecosystems do: [ :eco |
		(aContext isEcosystemZipCacheAvailable: eco)
			ifTrue: [ bytes := bytes + Gt4SecurityFeedCostModel revalidateHandshakeBytes ]
			ifFalse: [
				bytes := bytes + ((aContext isLargeEcosystem: eco)
					ifTrue: [ Gt4SecurityFeedCostModel largeEcosystemZipBytes ]
					ifFalse: [ Gt4SecurityFeedCostModel smallEcosystemZipBytes ]) ] ].
	^ bytes
]

{ #category : 'accessing' }
Gt4SecurityFullEcosystemZipStrategy >> description [
	^ 'full ecosystem zip download + parse'
]

{ #category : 'protocol' }
Gt4SecurityFullEcosystemZipStrategy >> doExecute: aQuery on: aClient inContext: aContext [
	| merged |
	aQuery ecosystems size = 1 ifTrue: [
		^ aClient
			ecosystemFull: aQuery ecosystems first
			acceptLargeDownload: aQuery acceptLargeDownload ].
	merged := OrderedCollection new.
	aQuery ecosystems do: [ :eco |
		merged addAll: (aClient
			ecosystemFull: eco
			acceptLargeDownload: aQuery acceptLargeDownload) items ].
	^ Gt4SecurityVulnerabilityGroup withAll: merged
]

{ #category : 'ranking' }
Gt4SecurityFullEcosystemZipStrategy >> tiebreakPriority [
	"Distinct scope (ecosystem) — unlikely to tie, but mid-range if it does."
	^ 30
]
