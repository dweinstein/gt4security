"
Live <gtExample> methods exercising {{gtClass:Gt4SecurityNvdClient}}. All marked <noTest>. Covers CVE id lookup, virtual CPE queries, CVSS v2 parsing regression, and latestIosCvesSince:.
"
Class {
	#name : 'Gt4SecurityNvdExamples',
	#superclass : 'Object',
	#category : 'Gt4Security-Examples',
	#package : 'Gt4Security',
	#tag : 'Examples'
}

{ #category : 'examples - clients' }
Gt4SecurityNvdExamples >> client [
	<gtExample>
	<return: #Gt4SecurityNvdClient>
	| client |
	client := Gt4SecurityNvdClient new.
	self assert: client baseUrl notNil.
	self assert: client history isEmpty.
	self assert: client rateLimitDelaySeconds equals: 6.
	^ client
]

{ #category : 'examples - demo' }
Gt4SecurityNvdExamples >> demoSafariCve [
	"CVE-2024-23222: a well-known WebKit type-confusion bug exploited in the wild. Showcases the vulnerability Summary, Affected (with CPE parsing), References (clickable), and Aliases (navigable) views."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerability>
	^ Gt4SecurityNvdClient new cveById: 'CVE-2024-23222'
]

{ #category : 'examples - live' }
Gt4SecurityNvdExamples >> latestIosCves [
	"Live: the most recently published Apple iPhone OS CVEs (last 90 days, up to 50).
	Demonstrates combining virtualMatchString with pubStartDate for a 'new disclosures' feed,
	plus the required client-side sort (NVD v2 has no server sort — default is ascending by published)."
	<gtExample>
	<noTest>
	<return: #OrderedCollection>
	| client vulns |
	client := self client.
	vulns := client latestIosCvesSince: Date today - 90 days.
	self assert: vulns notEmpty.
	self assert: (vulns allSatisfy: [ :v | v id beginsWith: 'CVE-' ]).
	self assert: (vulns allSatisfy: [ :v | v primaryEcosystem isNil ]).
	self assert: (vulns allSatisfy: [ :v | v hasCpeAffected ]).
	self assert: (vulns size < 2 or: [
		(1 to: vulns size - 1) allSatisfy: [ :i |
			(vulns at: i) published >= (vulns at: i + 1) published ] ]).
	^ vulns
]

{ #category : 'examples - live' }
Gt4SecurityNvdExamples >> lookupAppleSafariCve [
	"Live GET of a well-known iOS/Safari CVE by id. Asserts it parses into the shared Gt4SecurityVulnerability domain."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerability>
	| client vuln |
	client := self client.
	vuln := client cveById: 'CVE-2024-23222'.
	self assert: vuln notNil.
	self assert: vuln id equals: 'CVE-2024-23222'.
	"NVD entries carry no OSV ecosystem; they are CPE-based."
	self assert: vuln primaryEcosystem isNil.
	self assert: vuln hasCpeAffected.
	self assert: vuln severity notEmpty.
	self assert: (vuln severity first at: 'baseScore') equals: 8.8.
	self assert: vuln affected notEmpty.
	^ vuln
]

{ #category : 'examples - parsing' }
Gt4SecurityNvdExamples >> parseCvssV2FromOldCve [
	"Regression example for the CVSS v2 shape fix — baseSeverity lives at the metric entry level, not inside cvssData."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerability>
	| client vuln |
	client := self client.
	vuln := client cveById: 'CVE-2007-2399'.
	self assert: vuln notNil.
	self assert: (vuln severity first at: 'type') equals: 'CVSS_V2.0'.
	self assert: (vuln severity first at: 'baseSeverity') equals: 'HIGH'.
	^ vuln
]

{ #category : 'examples - live' }
Gt4SecurityNvdExamples >> queryIphoneOsVirtualCpe [
	"Live virtualMatchString query for Apple iPhone OS. Asserts we get a non-empty result set with CVE- ids."
	<gtExample>
	<noTest>
	<return: #OrderedCollection>
	| client vulns |
	client := self client.
	vulns := client cvesForVirtualCpe: 'cpe:2.3:o:apple:iphone_os' limit: 5.
	self assert: vulns notEmpty.
	self assert: (vulns allSatisfy: [ :v | v id beginsWith: 'CVE-' ]).
	"NVD entries carry no OSV ecosystem; they are CPE-based."
	self assert: (vulns allSatisfy: [ :v | v primaryEcosystem isNil ]).
	self assert: (vulns allSatisfy: [ :v | v hasCpeAffected ]).
	^ vulns
]
