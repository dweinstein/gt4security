"
Examples for {{gtClass:Gt4SecurityQuery}} and {{gtClass:Gt4SecurityVulnerabilityGroup}}. Mix of synthetic (mobileQueryBuilder, groupFilters — always-on) and live (mobileLastWeek, dedupByCveId, demoMobileCveOverview, demoMobileSdkScan — marked <noTest>).
"
Class {
	#name : 'Gt4SecurityQueryExamples',
	#superclass : 'Object',
	#category : 'Gt4Security-Examples',
	#package : 'Gt4Security',
	#tag : 'Examples'
}

{ #category : 'examples - demo' }
Gt4SecurityQueryExamples >> benchmarkCsvVsZipOnPyPI [
	"Live: head-to-head benchmark comparing the two fetch paths on PyPI (22 MB non-ZIP64 zip). Uses publishedSince cutoff of 90 days. Returns a Dictionary of {csvMs, csvRows, zipMs, zipRows, speedup}. Intended as an honest regression signal: if some change makes CSV faster than zip on non-ZIP64 ecosystems, the ratio in the returned dict will go below 1."
	<gtExample>
	<noTest>
	<return: #Dictionary>
	| csvClient zipClient csvStart csvGroup csvMs zipStart zipGroup zipMs |
	csvClient := Gt4SecurityOsvFeedClient new.
	zipClient := Gt4SecurityOsvFeedClient new.
	csvStart := DateAndTime now.
	csvGroup := csvClient
		recentModifiedSince: Date today - 90 days
		ecosystem: 'PyPI'
		concurrency: 16.
	csvMs := (DateAndTime now - csvStart) asMilliSeconds.
	zipStart := DateAndTime now.
	zipGroup := zipClient recentSince: Date today - 90 days ecosystem: 'PyPI'.
	zipMs := (DateAndTime now - zipStart) asMilliSeconds.
	^ Dictionary new
		at: 'ecosystem' put: 'PyPI';
		at: 'csvMs' put: csvMs;
		at: 'csvRows' put: csvGroup size;
		at: 'zipMs' put: zipMs;
		at: 'zipRows' put: zipGroup size;
		at: 'speedup' put: (csvMs / (zipMs max: 1)) asFloat printString , 'x (zip vs csv)';
		yourself
]

{ #category : 'examples - demo' }
Gt4SecurityQueryExamples >> cratesSecurityLast90Days [
	"Live: smaller cousin of npmSecurityLast90Days — crates.io all.zip is only ~2.5 MB, so the download is cheap."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	query feedEcosystem: 'crates.io'.
	query publishedSince: Date today - 90 days.
	^ query run
]

{ #category : 'examples - demo' }
Gt4SecurityQueryExamples >> crossEcosystemScan [
	"Scan a representative set of popular packages across the major OSV ecosystems — npm, PyPI, Maven, crates.io, RubyGems, Packagist, Go, Pub — so the 'By ecosystem' view shows a real multi-ecosystem breakdown. Useful to validate that ecosystem-dimension really is populated when queries target OSV."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	"npm"
	query package: 'axios' ecosystem: 'npm'.
	query package: 'lodash' ecosystem: 'npm'.
	query package: 'express' ecosystem: 'npm'.
	"PyPI"
	query package: 'django' ecosystem: 'PyPI'.
	query package: 'flask' ecosystem: 'PyPI'.
	query package: 'requests' ecosystem: 'PyPI'.
	"Maven"
	query package: 'org.apache.logging.log4j:log4j-core' ecosystem: 'Maven'.
	query package: 'com.fasterxml.jackson.core:jackson-databind' ecosystem: 'Maven'.
	"crates.io"
	query package: 'tokio' ecosystem: 'crates.io'.
	query package: 'openssl' ecosystem: 'crates.io'.
	"RubyGems"
	query package: 'rails' ecosystem: 'RubyGems'.
	query package: 'nokogiri' ecosystem: 'RubyGems'.
	"Packagist"
	query package: 'symfony/symfony' ecosystem: 'Packagist'.
	query package: 'laravel/framework' ecosystem: 'Packagist'.
	"Go"
	query package: 'github.com/gin-gonic/gin' ecosystem: 'Go'.
	"Pub"
	query package: 'dio' ecosystem: 'Pub'.
	query publishedSince: Date today - 720 days.
	query limit: 20.
	^ query run
]

{ #category : 'examples - live' }
Gt4SecurityQueryExamples >> dedupByCveId [
	"Regression: same CVE id should not appear twice in the merged group."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query result ids |
	query := Gt4SecurityQuery new.
	query ios.
	query limit: 50.
	result := query run.
	ids := result group items collect: [ :v | v id ].
	self assert: ids asSet size equals: ids size.
	^ result
]

{ #category : 'examples - demo' }
Gt4SecurityQueryExamples >> demoMobileCveOverview [
	"Cross-source mobile CVE overview: iOS + Android kernel, last 90 days. Showcases the group's Summary, Vulnerabilities, Timeline, and By-ecosystem views."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	query ios.
	query androidPackage: ':linux_kernel:'.
	query publishedSince: Date today - 90 days.
	query limit: 50.
	^ query run
]

{ #category : 'examples - demo' }
Gt4SecurityQueryExamples >> demoMobileSdkScan [
	"Scan common mobile SDKs and libraries across multiple ecosystems for known CVEs and malicious reports.
	Covers: native (OpenSSL, SQLite, libcurl, libwebp via NVD), Android Java (OkHttp, Retrofit, log4j, GSON via OSV Maven),
	React Native / Cordova (axios, lodash, node-forge via OSV npm), Flutter (dio, http via OSV Pub)."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	"Native libs via NVD CPE."
	query cpe: 'cpe:2.3:a:openssl:openssl'.
	query cpe: 'cpe:2.3:a:sqlite:sqlite'.
	query cpe: 'cpe:2.3:a:haxx:libcurl'.
	query cpe: 'cpe:2.3:a:webmproject:libwebp'.
	"Android Java libs via OSV."
	query package: 'com.squareup.okhttp3:okhttp' ecosystem: 'Maven'.
	query package: 'com.squareup.retrofit2:retrofit' ecosystem: 'Maven'.
	query package: 'org.apache.logging.log4j:log4j-core' ecosystem: 'Maven'.
	"RN / Cordova bundles via OSV npm."
	query package: 'axios' ecosystem: 'npm'.
	query package: 'node-forge' ecosystem: 'npm'.
	"Flutter via OSV Pub."
	query package: 'dio' ecosystem: 'Pub'.
	query publishedSince: Date today - 120 days.
	query limit: 25.
	^ query run
]

{ #category : 'examples - export' }
Gt4SecurityQueryExamples >> exportSyntheticGroupToCsv [
	"Offline: export the synthetic 3-vuln group from groupFilters to CSV; verify header + row shape."
	<gtExample>
	<return: #FileReference>
	| group fileRef lines headerCells |
	group := self groupFilters.
	fileRef := group exportToCsv.
	self assert: fileRef exists.
	self assert: fileRef size > 100.
	lines := fileRef contents lines.
	self assert: lines size equals: 4. "header + 3 vulns"
	headerCells := lines first substrings: ','.
	self assert: (headerCells includes: 'id').
	self assert: (headerCells includes: 'kind').
	self assert: (headerCells includes: 'severity_score').
	self assert: (headerCells includes: 'affected_packages').
	lines allButFirst do: [ :line |
		self assert: ((line beginsWith: 'CVE-') or: [ line beginsWith: 'ASB-' ]) ].
	^ fileRef
]

{ #category : 'as yet unclassified' }
Gt4SecurityQueryExamples >> goSecurityLast7Days [
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	query feedEcosystem: 'Go'.
	query publishedSince: Date today - 7 days.
	^ query run
]

{ #category : 'as yet unclassified' }
Gt4SecurityQueryExamples >> goSecurityLast90Days [
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	query feedEcosystem: 'Go'.
	query publishedSince: Date today - 90 days.
	^ query run
]

{ #category : 'examples - groups' }
Gt4SecurityQueryExamples >> groupFilters [
	"Exercise every filter on a synthetic group so CI doesn't depend on live data."
	<gtExample>
	<return: #Gt4SecurityVulnerabilityGroup>
	| group makeAffected makeSeverity |
	"makeAffected: eco may be nil for CPE-shaped entries (NVD-sourced), in which case name is a cpe:... string."
	makeAffected := [ :eco :name |
		Gt4SecurityAffectedGroup withAll: { Gt4SecurityAffectedEntry fromDictionary: (Dictionary new
			at: 'package' put: (eco
				ifNil: [ Dictionary new at: 'name' put: name; yourself ]
				ifNotNil: [ Dictionary new at: 'ecosystem' put: eco; at: 'name' put: name; yourself ]);
			yourself) } ].
	makeSeverity := [ :score :label |
		Gt4SecuritySeverityGroup withAll: { Gt4SecuritySeverity fromDictionary: (Dictionary new
			at: 'type' put: 'CVSS_V3.1';
			at: 'baseScore' put: score;
			at: 'baseSeverity' put: label;
			yourself) } ].
	group := Gt4SecurityVulnerabilityGroup withAll: {
		Gt4SecurityVulnerability new
			id: 'CVE-2026-0001';
			published: '2026-04-01T00:00:00Z';
			severity: (makeSeverity value: 9.8 value: 'CRITICAL');
			affected: (makeAffected value: nil value: 'cpe:2.3:o:apple:iphone_os:*');
			aliases: #();
			references: (Gt4SecurityReferenceGroup withAll: #());
			summary: 'critical iOS kernel bug';
			yourself.
		Gt4SecurityVulnerability new
			id: 'CVE-2026-0002';
			published: '2026-03-15T00:00:00Z';
			severity: (makeSeverity value: 4.3 value: 'MEDIUM');
			affected: (makeAffected value: 'Android' value: 'platform/frameworks/base');
			aliases: #();
			references: (Gt4SecurityReferenceGroup withAll: #());
			summary: 'android UI glitch';
			yourself.
		Gt4SecurityVulnerability new
			id: 'ASB-A-123';
			published: '2025-12-01T00:00:00Z';
			severity: (Gt4SecuritySeverityGroup withAll: #());
			affected: (makeAffected value: 'Android' value: ':linux_kernel:');
			aliases: #('CVE-2025-9999');
			references: (Gt4SecurityReferenceGroup withAll: #());
			summary: 'old kernel bug';
			yourself } asOrderedCollection.
	self assert: group size equals: 3.
	self assert: group highSeverity size equals: 1.
	self assert: group criticalSeverity size equals: 1.
	self assert: group withScore size equals: 2.
	self assert: (group ecosystem: 'Android') size equals: 2.
	"CPE-based (NVD-sourced) filter — replaces the old ecosystem: 'NVD-CPE' test."
	self assert: group cpeBased size equals: 1.
	self assert: group ecosystemBased size equals: 2.
	self assert: (group cpeVendor: 'apple') size equals: 1.
	self assert: (group matching: 'kernel') size equals: 2.
	self assert: (group publishedSince: '2026-01-01') size equals: 2.
	self assert: group sortedByScore first id equals: 'CVE-2026-0001'.
	self assert: group sortedByPublished first id equals: 'CVE-2026-0001'.
	^ group
]

{ #category : 'accessing' }
Gt4SecurityQueryExamples >> mobileFeedLast90Days [
	"Live: vulnerabilities modified in the last 90 days across the mobile-relevant OSV ecosystems."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	Gt4SecurityOsvFeedClient mobileEcosystems do: [ :eco |
		query feedEcosystem: eco ].
	query publishedSince: Date today - 90 days.
	^ query run
]

{ #category : 'examples - live' }
Gt4SecurityQueryExamples >> mobileLastWeek [
	"Live cross-source query: iOS CVEs + Android kernel in the last 7 days.
	Returns a Gt4SecurityQueryResult with provenance (counts, runAt)."

	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query result |
	query := Gt4SecurityQuery new.
	query ios.
	query androidPackage: ':linux_kernel:'.
	query publishedSince: Date today - 7 days.
	query limit: 50.
	result := query run.
	self assert: result class equals: Gt4SecurityQueryResult.
	self assert: result runAt notNil.
	"A quiet week may yield zero items, so avoid hard notEmpty assertions on the group."
	^ result
]

{ #category : 'examples - building' }
Gt4SecurityQueryExamples >> mobileQueryBuilder [
	<gtExample>
	<return: #Gt4SecurityQuery>
	| query |
	query := Gt4SecurityQuery new.
	query mobileOnly.
	query publishedSince: Date today - 30 days.
	query severityAtLeast: 7.0.
	self assert: query nvdCpes size equals: 1.
	self assert: query osvPackages size equals: 2.
	self assert: query severityFloor equals: 7.0.
	self assert: query publishedSince notNil.
	^ query
]

{ #category : 'csv' }
Gt4SecurityQueryExamples >> npmSecurityLast360Days [
	"Live: every npm vulnerability (GHSA + MAL-* malicious-package reports) modified in the last 90 days. Uses the CSV + per-ID feed path so no 192 MB zip download is needed. First run downloads modified_id.csv (~40 MB) and issues ~4000 individual JSON fetches in parallel; subsequent runs reuse the CSV cache."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	query feedEcosystem: 'npm'.
	query publishedSince: Date today - 360 days.
	^ query run
]

{ #category : 'running' }
Gt4SecurityQueryExamples >> npmSecurityLast365Days [
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	query feedEcosystem: 'npm'.
	query publishedSince: Date today - 365 days.
	^ query run
]

{ #category : 'csv' }
Gt4SecurityQueryExamples >> npmSecurityLast7Days [
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	query feedEcosystem: 'npm'.
	query publishedSince: Date today - 7 days.
	^ query run
]

{ #category : 'examples - demo' }
Gt4SecurityQueryExamples >> npmSecurityLast90Days [
	"Live: every npm vulnerability (GHSA + MAL-* malicious-package reports) modified in the last 90 days. Uses the CSV + per-ID feed path so no 192 MB zip download is needed. First run downloads modified_id.csv (~40 MB) and issues ~4000 individual JSON fetches in parallel; subsequent runs reuse the CSV cache."
	<gtExample>
	<noTest>
	<return: #Gt4SecurityQueryResult>
	| query |
	query := Gt4SecurityQuery new.
	query feedEcosystem: 'npm'.
	query publishedSince: Date today - 90 days.
	^ query run
]

{ #category : 'examples - search' }
Gt4SecurityQueryExamples >> queryResultSearchesAdvisoryText [
	<gtExample>
	<return: #Gt4SecurityQueryResult>
	| affected vulnerability result text |
	affected := Gt4SecurityAffectedEntry new
		ecosystem: 'npm';
		packageName: 'left-pad';
		yourself.
	vulnerability := Gt4SecurityVulnerability new
		id: 'GHSA-1234-5678-90ab';
		summary: 'Synthetic advisory for search';
		severity: (Gt4SecuritySeverityGroup withAll: #());
		aliases: (Gt4SecurityAliasGroup withAll: #('CVE-2026-0001'));
		affected: (Gt4SecurityAffectedGroup withAll: { affected });
		yourself.
	result := Gt4SecurityQueryResult new
		group: (Gt4SecurityVulnerabilityGroup withAll: { vulnerability });
		yourself.
	text := result searchTextForEntry: vulnerability.
	self assert: (text includesSubstring: 'GHSA-1234-5678-90ab').
	self assert: (text includesSubstring: 'CVE-2026-0001').
	self assert: (text includesSubstring: 'left-pad').
	^ result
]
