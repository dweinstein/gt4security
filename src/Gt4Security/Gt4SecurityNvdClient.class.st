"
HTTP client for NVD CVE API v2 (services.nvd.nist.gov/rest/json/cves/2.0). Authoritative CPE-based vulnerability data for iOS, iPadOS, firmware, and device vendors (Samsung, Qualcomm, Apple) that OSV does not cover well.

Rate limited per-instance: 6 seconds between calls without an API key, 1 second with one. Get a free key at https://nvd.nist.gov/developers/request-an-api-key and pass via `withApiKey:` or `apiKey:`.

NVD quirks handled by this client:
- Combined virtualMatchString + date-range queries return 404 for zero matches (not 200 with empty vulnerabilities). Treated as empty result, not error.
- CVSS v2 stores baseSeverity at the metric entry level, not inside cvssData. Parser handles both.
- No server-side sort — results default to ascending by published. Convenience methods sort client-side.

Main entry points:
- cveById: — single lookup
- cvesForVirtualCpe:limit: — CPE family match
- cvesForVirtualCpe:publishedSince:until:limit: — new disclosures for a product
- latestIosCves / latestIosCvesSince: — convenience for the common iOS case
"
Class {
	#name : 'Gt4SecurityNvdClient',
	#superclass : 'Object',
	#instVars : [
		'baseUrl',
		'apiKey',
		'history',
		'lastRequestTime'
	],
	#category : 'Gt4Security-Clients',
	#package : 'Gt4Security',
	#tag : 'Clients'
}

{ #category : 'defaults' }
Gt4SecurityNvdClient class >> defaultBaseUrl [
	^ 'https://services.nvd.nist.gov/rest/json/cves/2.0' asZnUrl
]

{ #category : 'instance creation' }
Gt4SecurityNvdClient class >> withApiKey: aString [
	"NVD allows 50 req / 30s with an API key (vs. 5 req / 30s without).
	Get a free key at https://nvd.nist.gov/developers/request-an-api-key"
	^ self new apiKey: aString
]

{ #category : 'accessing' }
Gt4SecurityNvdClient >> apiKey [
	^ apiKey
]

{ #category : 'accessing' }
Gt4SecurityNvdClient >> apiKey: aString [
	apiKey := aString
]

{ #category : 'accessing' }
Gt4SecurityNvdClient >> baseUrl [
	^ baseUrl
]

{ #category : 'accessing' }
Gt4SecurityNvdClient >> baseUrl: anObject [
	baseUrl := anObject asZnUrl
]

{ #category : 'private' }
Gt4SecurityNvdClient >> checkForErrors: aClient [
	"Handle NVD response quirks:
	- nil response = connection failure
	- 404 = valid query with zero results (NVD quirk with CPE + date combos)
	- non-2xx = real error
	Then parse JSON ourselves (we don't use forJsonREST)."
	aClient response ifNil: [
		Error signal: 'NVD API error: no response (connection failed?)' ].
	aClient response code = 404 ifTrue: [
		^ Dictionary new
			at: 'vulnerabilities' put: #();
			at: 'totalResults' put: 0;
			yourself ].
	aClient isSuccess ifFalse: [
		Error signal: 'NVD API error: ' , aClient response statusLine printString ].
	^ NeoJSONReader fromString: aClient contents
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cveById: anIdString [
	"Look up a single CVE by id (e.g. 'CVE-2024-23222'). Returns a Gt4SecurityVulnerability or nil."
	| response vulns |
	response := self getWithParams: { 'cveId' -> anIdString }.
	vulns := response at: 'vulnerabilities' ifAbsent: [ #() ].
	vulns isEmpty ifTrue: [ ^ nil ].
	^ Gt4SecurityVulnerability fromNvdDictionary: vulns first
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cveCountPublishedSince: aStartDate until: anEndDate [
	"Total number of CVEs first published in the window, without fetching them all."
	| response |
	response := self getWithParams: {
		'pubStartDate' -> (self nvdDateString: aStartDate).
		'pubEndDate' -> (self nvdDateString: anEndDate).
		'resultsPerPage' -> '1' }.
	^ response at: 'totalResults' ifAbsent: [ 0 ]
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cvesForCpe: aCpeString [
	"Query CVEs matching a specific CPE 2.3 string. Returns an OrderedCollection of Gt4SecurityVulnerability."
	^ self cvesForCpe: aCpeString limit: 100
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cvesForCpe: aCpeString limit: anInteger [
	"Exact CPE match. Example: 'cpe:2.3:o:apple:iphone_os:17.2.1:*:*:*:*:*:*:*'."
	| response |
	response := self getWithParams: {
		'cpeName' -> aCpeString.
		'resultsPerPage' -> anInteger asString }.
	^ Gt4SecurityVulnerabilityGroup withAll:
		((response at: 'vulnerabilities' ifAbsent: [ #() ]) collect: [ :each |
			Gt4SecurityVulnerability fromNvdDictionary: each ])
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cvesForVirtualCpe: aCpeString [
	"Broader CPE family match via virtualMatchString. Example: 'cpe:2.3:o:apple:iphone_os'."
	^ self cvesForVirtualCpe: aCpeString limit: 100
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cvesForVirtualCpe: aCpeString limit: anInteger [
	"Broader CPE family match — matches any version/edition under the given prefix."
	| response |
	response := self getWithParams: {
		'virtualMatchString' -> aCpeString.
		'resultsPerPage' -> anInteger asString }.
	^ Gt4SecurityVulnerabilityGroup withAll:
		((response at: 'vulnerabilities' ifAbsent: [ #() ]) collect: [ :each |
			Gt4SecurityVulnerability fromNvdDictionary: each ])
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cvesForVirtualCpe: aCpeString modifiedSince: aStartDate until: anEndDate limit: anInteger [
	"CPE family match + lastMod window. Returns a group sorted by modified desc via a sortedBy view
	on the result (group sort is type-preserving only for filters, not for sorts)."
	| response group |
	response := self getWithParams: {
		'virtualMatchString' -> aCpeString.
		'lastModStartDate' -> (self nvdDateString: aStartDate).
		'lastModEndDate' -> (self nvdDateString: anEndDate).
		'resultsPerPage' -> anInteger asString }.
	group := Gt4SecurityVulnerabilityGroup withAll:
		((response at: 'vulnerabilities' ifAbsent: [ #() ]) collect: [ :each |
			Gt4SecurityVulnerability fromNvdDictionary: each ]).
	group items sort: [ :a :b | (a modified ifNil: [ '' ]) > (b modified ifNil: [ '' ]) ].
	^ group
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cvesForVirtualCpe: aCpeString publishedSince: aStartDate until: anEndDate limit: anInteger [
	"CPE family match + pub window. Returns a group with items sorted by published desc."
	| response group |
	response := self getWithParams: {
		'virtualMatchString' -> aCpeString.
		'pubStartDate' -> (self nvdDateString: aStartDate).
		'pubEndDate' -> (self nvdDateString: anEndDate).
		'resultsPerPage' -> anInteger asString }.
	group := Gt4SecurityVulnerabilityGroup withAll:
		((response at: 'vulnerabilities' ifAbsent: [ #() ]) collect: [ :each |
			Gt4SecurityVulnerability fromNvdDictionary: each ]).
	group items sort: [ :a :b | (a published ifNil: [ '' ]) > (b published ifNil: [ '' ]) ].
	^ group
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cvesModifiedSince: aStartDate until: anEndDate [
	"Windowed incremental sync. NVD requires both endpoints and caps the window at 120 days. Paginates through every page."
	^ Gt4SecurityVulnerabilityGroup withAll:
		((self pagedVulnerabilitiesWithParams: {
			'lastModStartDate' -> (self nvdDateString: aStartDate).
			'lastModEndDate' -> (self nvdDateString: anEndDate) })
			collect: [ :each | Gt4SecurityVulnerability fromNvdDictionary: each ])
]

{ #category : 'api' }
Gt4SecurityNvdClient >> cvesPublishedSince: aStartDate until: anEndDate [
	"All CVEs first published in the window. NVD requires both endpoints and caps the window at 120 days. Paginates through every page."
	^ Gt4SecurityVulnerabilityGroup withAll:
		((self pagedVulnerabilitiesWithParams: {
			'pubStartDate' -> (self nvdDateString: aStartDate).
			'pubEndDate' -> (self nvdDateString: anEndDate) })
			collect: [ :each | Gt4SecurityVulnerability fromNvdDictionary: each ])
]

{ #category : 'rate limiting' }
Gt4SecurityNvdClient >> enforceRateLimit [
	"Block until at least rateLimitDelaySeconds has elapsed since the last request."
	| elapsed required |
	lastRequestTime ifNotNil: [
		elapsed := (DateAndTime now - lastRequestTime) asSeconds.
		required := self rateLimitDelaySeconds.
		elapsed < required ifTrue: [
			(Delay forSeconds: required - elapsed) wait ] ].
	lastRequestTime := DateAndTime now
]

{ #category : 'private' }
Gt4SecurityNvdClient >> getWithParams: aListOfAssocs [
	"GET the NVD CVEs endpoint with the given query parameters."
	| aClient |
	self enforceRateLimit.
	aClient := self initializeClient.
	aClient url: baseUrl.
	aListOfAssocs do: [ :pair |
		aClient queryAt: pair key put: pair value ].
	aClient entity: nil.
	aClient get.
	history add: (aClient request -> aClient response).
	^ self checkForErrors: aClient
]

{ #category : 'gt - views' }
Gt4SecurityNvdClient >> gtCallsFor: aView [
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
Gt4SecurityNvdClient >> gtClearHistoryActionFor: anAction [
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
Gt4SecurityNvdClient >> gtConfigurationFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Configuration';
		priority: 1;
		items: [ {
			'Base URL' -> baseUrl printString.
			'API key' -> (apiKey
				ifNil: [ '(none — rate limited to 5 req / 30s)' ]
				ifNotNil: [ (apiKey first: (4 min: apiKey size)) , '...' ]).
			'Rate limit' -> (self rateLimitDelaySeconds asString , 's between requests').
			'History' -> (history size asString , ' calls').
			'Last request' -> (lastRequestTime
				ifNil: [ '(never)' ]
				ifNotNil: [ lastRequestTime printString ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'accessing' }
Gt4SecurityNvdClient >> history [
	^ history
]

{ #category : 'initialization' }
Gt4SecurityNvdClient >> initialize [
	super initialize.
	baseUrl := self class defaultBaseUrl.
	history := OrderedCollection new
]

{ #category : 'private' }
Gt4SecurityNvdClient >> initializeClient [
	"Raw ZnClient without forJsonREST — we parse JSON ourselves in checkForErrors:
	because NVD returns 404 with empty body for valid-but-zero-result queries,
	which forJsonREST chokes on."
	| aClient |
	aClient := ZnClient new.
	aClient timeout: 60.
	aClient accept: ZnMimeType applicationJson.
	apiKey ifNotNil: [ :key | aClient headerAt: 'apiKey' put: key ].
	^ aClient
]

{ #category : 'api' }
Gt4SecurityNvdClient >> latestIosCves [
	"Convenience: the most recently-modified Apple iOS CVEs (default: last 30 days, 50 results)."
	^ self latestIosCvesSince: Date today - 30 days
]

{ #category : 'api' }
Gt4SecurityNvdClient >> latestIosCvesSince: aStartDate [
	"Apple iPhone OS CVEs published since the given date, newest-first. Up to 50 results.
	Uses pubStartDate (new disclosures), not lastModStartDate. For 'anything touched since',
	call cvesForVirtualCpe:modifiedSince:until:limit: directly."
	^ self
		cvesForVirtualCpe: 'cpe:2.3:o:apple:iphone_os'
		publishedSince: aStartDate
		until: Date today + 1 day
		limit: 50
]

{ #category : 'private' }
Gt4SecurityNvdClient >> nvdDateString: aDateOrDateTime [
	"Format as 'YYYY-MM-DDTHH:MM:SS.sss' — NVD's required form for lastModStartDate / lastModEndDate.
	A plain Date becomes midnight UTC."
	| dt |
	dt := aDateOrDateTime asDateAndTime.
	^ String streamContents: [ :s |
		s
			print: dt year;
			nextPutAll: '-';
			nextPutAll: (self pad2: dt monthIndex);
			nextPutAll: '-';
			nextPutAll: (self pad2: dt dayOfMonth);
			nextPutAll: 'T';
			nextPutAll: (self pad2: dt hour);
			nextPutAll: ':';
			nextPutAll: (self pad2: dt minute);
			nextPutAll: ':';
			nextPutAll: (self pad2: dt second);
			nextPutAll: '.000' ]
]

{ #category : 'private' }
Gt4SecurityNvdClient >> pad2: anInteger [
	^ anInteger < 10
		ifTrue: [ '0' , anInteger printString ]
		ifFalse: [ anInteger printString ]
]

{ #category : 'private' }
Gt4SecurityNvdClient >> pagedVulnerabilitiesWithParams: aListOfAssocs [
	"Fetch every page of a CVE query, advancing startIndex until totalResults is covered.
	Relies on enforceRateLimit in getWithParams: to stay within NVD limits."
	| all startIndex total vulns response |
	all := OrderedCollection new.
	startIndex := 0.
	[ response := self getWithParams: aListOfAssocs , {
			'resultsPerPage' -> '2000'.
			'startIndex' -> startIndex printString }.
	vulns := response at: 'vulnerabilities' ifAbsent: [ #() ].
	all addAll: vulns.
	total := response at: 'totalResults' ifAbsent: [ 0 ].
	startIndex := startIndex + vulns size.
	vulns notEmpty and: [ startIndex < total ] ] whileTrue.
	^ all
]

{ #category : 'printing' }
Gt4SecurityNvdClient >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (';
		nextPutAll: (apiKey isNil ifTrue: [ 'no key' ] ifFalse: [ 'keyed' ]);
		nextPutAll: ', ';
		print: history size;
		nextPutAll: ' calls)'
]

{ #category : 'rate limiting' }
Gt4SecurityNvdClient >> rateLimitDelaySeconds [
	"NVD recommends 6s without an API key (5 req/30s) or 0.6s with one (50 req/30s).
	We round up to 1s for safety when a key is present."
	^ apiKey isNil
		ifTrue: [ 6 ]
		ifFalse: [ 1 ]
]
