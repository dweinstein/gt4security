"
HTTP client for OSV.dev (api.osv.dev/v1) — the unified open-source vulnerability database covering Android (ingested from Android Security Bulletins), npm, Maven, PyPI, Pub (Flutter), crates.io, and others. Also includes OSSF Malicious Packages reports (MAL-*).

No authentication required. No rate limits documented. Tracks request/response history per client instance.

Main entry points:
- queryEcosystem:package: — primary query, returns a Gt4SecurityVulnerabilityGroup
- queryAndroidPackage: — shortcut for the Android ecosystem
- queryMaliciousEcosystem:package: — filter to MAL-* entries
- vulnerabilityById: — GET /vulns/{id}

Follows the ZnClient + NeoJSONReader pattern (see Gt4CloudflareClient).
"
Class {
	#name : 'Gt4SecurityOsvClient',
	#superclass : 'Object',
	#instVars : [
		'baseUrl',
		'history'
	],
	#category : 'Gt4Security-Clients',
	#package : 'Gt4Security',
	#tag : 'Clients'
}

{ #category : 'defaults' }
Gt4SecurityOsvClient class >> defaultBaseUrl [
	^ 'https://api.osv.dev/v1' asZnUrl
]

{ #category : 'accessing' }
Gt4SecurityOsvClient >> baseUrl [
	^ baseUrl
]

{ #category : 'accessing' }
Gt4SecurityOsvClient >> baseUrl: anObject [
	baseUrl := anObject asZnUrl
]

{ #category : 'private' }
Gt4SecurityOsvClient >> checkForErrors: aClient [
	aClient isSuccess ifFalse: [
		Error signal: 'OSV API error: ' , aClient response statusLine printString ].
	^ aClient contents
]

{ #category : 'private' }
Gt4SecurityOsvClient >> get: anEndpoint [
	| aClient |
	aClient := self initializeClient.
	aClient url: baseUrl / anEndpoint.
	aClient entity: nil.
	aClient get.
	history add: (aClient request -> aClient response).
	^ self checkForErrors: aClient
]

{ #category : 'gt - views' }
Gt4SecurityOsvClient >> gtCallsFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Calls';
		priority: 5;
		items: [ history reversed ];
		column: 'URL' text: [ :pair | pair key url ] weight: 3;
		column: 'Method' text: [ :pair | pair key method ] weight: 1;
		column: 'Status' text: [ :pair |
			pair value
				ifNil: [ 'no response' ]
				ifNotNil: [ :r | r statusLine printString ] ] weight: 2
]

{ #category : 'gt - views' }
Gt4SecurityOsvClient >> gtClearHistoryActionFor: anAction [
	<gtAction>
	^ anAction button
		icon: BrGlamorousVectorIcons cancel;
		tooltip: 'Clear history';
		priority: 80;
		action: [ :aButton :aTab |
			history removeAll.
			aTab viewContentElement phlow update ]
]

{ #category : 'gt - views' }
Gt4SecurityOsvClient >> gtConfigurationFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Configuration';
		priority: 1;
		items: [ {
			'Base URL' -> baseUrl printString.
			'History' -> (history size asString , ' calls') } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'accessing' }
Gt4SecurityOsvClient >> history [
	^ history
]

{ #category : 'initialization' }
Gt4SecurityOsvClient >> initialize [
	super initialize.
	baseUrl := self class defaultBaseUrl.
	history := OrderedCollection new
]

{ #category : 'private' }
Gt4SecurityOsvClient >> initializeClient [
	| aClient |
	aClient := ZnClient new.
	aClient forJsonREST.
	aClient timeout: 60.
	^ aClient
]

{ #category : 'private' }
Gt4SecurityOsvClient >> post: anEndpoint withEntity: aDictionary [
	| aClient |
	aClient := self initializeClient.
	aClient url: baseUrl / anEndpoint.
	aClient contents: aDictionary.
	aClient post.
	history add: (aClient request -> aClient response).
	^ self checkForErrors: aClient
]

{ #category : 'printing' }
Gt4SecurityOsvClient >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (';
		print: history size;
		nextPutAll: ' calls)'
]

{ #category : 'api' }
Gt4SecurityOsvClient >> queryAndroidPackage: aPackageNameString [
	"Convenience shortcut — Android ecosystem query.
	Example Android package names: 'platform/frameworks/base', ':linux_kernel:'.
	See https://google.github.io/osv.dev/schema/#affectedpackage-field"
	^ self queryEcosystem: 'Android' package: aPackageNameString
]

{ #category : 'api' }
Gt4SecurityOsvClient >> queryEcosystem: anEcosystemString package: aPackageNameString [
	"POST /v1/query with a package descriptor. Returns a Gt4SecurityVulnerabilityGroup."
	| entity response vulns |
	entity := Dictionary new.
	entity at: 'package' put: (Dictionary new
		at: 'name' put: aPackageNameString;
		at: 'ecosystem' put: anEcosystemString;
		yourself).
	response := self post: 'query' withEntity: entity.
	vulns := response at: 'vulns' ifAbsent: [ #() ].
	^ Gt4SecurityVulnerabilityGroup withAll:
		(vulns collect: [ :each | Gt4SecurityVulnerability fromOsvDictionary: each ])
]

{ #category : 'api' }
Gt4SecurityOsvClient >> queryMaliciousEcosystem: anEcosystemString package: aPackageNameString [
	"Query OSV for a package and return only the malicious-package entries (MAL-*).
	OSV mixes malicious records into the regular query response, so we delegate and filter."
	^ (self queryEcosystem: anEcosystemString package: aPackageNameString) malicious
]

{ #category : 'api' }
Gt4SecurityOsvClient >> vulnerabilityById: anIdString [
	"GET /v1/vulns/{id}. Returns a Gt4SecurityVulnerability. Example ids: 'ASB-A-123456789', 'CVE-2024-0001', 'GHSA-xxxx'."
	| response |
	response := self get: 'vulns/' , anIdString.
	^ Gt4SecurityVulnerability fromOsvDictionary: response
]
