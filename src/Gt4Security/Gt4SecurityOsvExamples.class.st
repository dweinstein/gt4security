"
Live <gtExample> methods exercising {{gtClass:Gt4SecurityOsvClient}}. All marked <noTest> so they are skipped in automated test sweeps — run manually from the inspector.
"
Class {
	#name : 'Gt4SecurityOsvExamples',
	#superclass : 'Object',
	#category : 'Gt4Security-Examples',
	#package : 'Gt4Security',
	#tag : 'Examples'
}

{ #category : 'examples - clients' }
Gt4SecurityOsvExamples >> client [
	<gtExample>
	<return: #Gt4SecurityOsvClient>
	| client |
	client := Gt4SecurityOsvClient new.
	self assert: client baseUrl notNil.
	self assert: client history isEmpty.
	^ client
]

{ #category : 'examples - live' }
Gt4SecurityOsvExamples >> lookupAndroidBulletinById [
	"Live GET /vulns/{id} for a known Android Security Bulletin entry."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityVulnerability>
	| client vuln |
	client := self client.
	vuln := client vulnerabilityById: 'ASB-A-111893654'.
	self assert: vuln id equals: 'ASB-A-111893654'.
	self assert: vuln primaryEcosystem equals: 'Android'.
	self assert: vuln affected notEmpty.
	self assert: vuln rawJson notNil.
	^ vuln
]

{ #category : 'examples - live' }
Gt4SecurityOsvExamples >> queryAndroidLinuxKernel [
	"Live query against api.osv.dev for Android kernel CVEs. Asserts we get a non-empty collection of Android-ecosystem vulnerabilities."
	<gtExample>
	<noTest>
	<return: #OrderedCollection>
	| client vulns |
	client := self client.
	vulns := client queryAndroidPackage: ':linux_kernel:'.
	self assert: vulns notEmpty.
	self assert: (vulns allSatisfy: [ :v | v primaryEcosystem = 'Android' ]).
	self assert: client history size equals: 1.
	^ vulns
]

{ #category : 'examples - live' }
Gt4SecurityOsvExamples >> queryMavenAndroidLibrary [
	"Live query for a Maven package typically bundled in Android apps.
	OkHttp is widely embedded by Android apps via Gradle / AAR."
	<gtExample>
	<noTest>
	<return: #OrderedCollection>
	| client vulns |
	client := self client.
	vulns := client queryEcosystem: 'Maven' package: 'com.squareup.okhttp3:okhttp'.
	self assert: vulns notEmpty.
	^ vulns
]
