"
Examples for malicious-package detection via {{gtClass:Gt4SecurityOsvClient}} and the isMalicious predicate on {{gtClass:Gt4SecurityVulnerability}}. Includes one synthetic regression (detectViaDatabaseSpecific) and several live lookups against real MAL-* records.
"
Class {
	#name : 'Gt4SecurityMaliciousExamples',
	#superclass : 'Object',
	#category : 'Gt4Security-Examples',
	#package : 'Gt4Security',
	#tag : 'Examples'
}

{ #category : 'examples - demo' }
Gt4SecurityMaliciousExamples >> demoMaliciousPackage [
	"MAL-2022-4301: an npm typosquat of libidn2 catalogued by OSSF. Showcases the Malicious? flag, Malicious Origins tab, and the isMalicious detection pipeline."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerability>
	^ Gt4SecurityOsvClient new vulnerabilityById: 'MAL-2022-4301'
]

{ #category : 'examples - synthetic' }
Gt4SecurityMaliciousExamples >> detectViaDatabaseSpecific [
	<gtExample>
	<return: #Gt4SecurityVulnerability>
	| vuln |
	vuln := Gt4SecurityVulnerability new
		id: 'GHSA-abcd-1234-efgh';
		aliases: #();
		severity: (Gt4SecuritySeverityGroup withAll: #());
		affected: (Gt4SecurityAffectedGroup withAll: #());
		references: (Gt4SecurityReferenceGroup withAll: #());
		rawJson: (Dictionary new
			at: 'database_specific' put: (Dictionary new
				at: 'malicious-packages-origins' put: { Dictionary new at: 'source' put: 'osv-ossf'; yourself };
				yourself);
			yourself);
		yourself.
	self assert: vuln isMalicious.
	self assert: vuln maliciousOrigins size equals: 1.
	^ vuln
]

{ #category : 'examples - live' }
Gt4SecurityMaliciousExamples >> lookupKnownMalById [
	"Live lookup of a MAL- record. libidn2 is an npm typosquat catalogued by OSSF Malicious Packages."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerability>
	| vuln |
	vuln := Gt4SecurityOsvClient new vulnerabilityById: 'MAL-2022-4301'.
	self assert: vuln id equals: 'MAL-2022-4301'.
	self assert: vuln isMalicious.
	self assert: vuln maliciousOrigins notEmpty.
	self assert: vuln primaryEcosystem equals: 'npm'.
	^ vuln
]

{ #category : 'examples - live' }
Gt4SecurityMaliciousExamples >> mixedQuerySplitsByKind [
	"Regression: a regular query for a package with malicious records returns both kinds,
	and the group's malicious/benign filters partition them cleanly."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerabilityGroup>
	| group |
	group := Gt4SecurityOsvClient new queryEcosystem: 'npm' package: 'libidn2'.
	self assert: group notEmpty.
	self assert: (group size = (group malicious size + group benign size)).
	self assert: group malicious notEmpty.
	^ group
]

{ #category : 'examples - live' }
Gt4SecurityMaliciousExamples >> queryNpmMaliciousPackage [
	"Live query for a known-bad npm package name. Should return exactly one MAL record."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerabilityGroup>
	| group |
	group := Gt4SecurityOsvClient new
		queryMaliciousEcosystem: 'npm'
		package: 'libidn2'.
	self assert: group class equals: Gt4SecurityVulnerabilityGroup.
	self assert: group notEmpty.
	self assert: (group allSatisfy: [ :v | v isMalicious ]).
	^ group
]
