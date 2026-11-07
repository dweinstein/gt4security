"
Pure offline unit examples for the parsing pipeline: {{gtMethod:Gt4SecurityVulnerability class>>#fromOsvDictionary:}}, {{gtMethod:Gt4SecurityVulnerability class>>#fromNvdDictionary:}}, CPE extraction on {{gtClass:Gt4SecurityAffectedEntry}}, NVD date formatting, and isMalicious detection. No network, no <noTest> — these always run.
"
Class {
	#name : 'Gt4SecurityParsingExamples',
	#superclass : 'Object',
	#category : 'Gt4Security-Examples',
	#package : 'Gt4Security',
	#tag : 'Examples'
}

{ #category : 'examples - affected' }
Gt4SecurityParsingExamples >> affectedGroup [
	"AffectedGroup filters by ecosystem."
	<gtExample>
	| a b group |
	a := Gt4SecurityAffectedEntry fromDictionary: (Dictionary new
		at: 'package' put: (Dictionary new at: 'ecosystem' put: 'Android'; at: 'name' put: ':linux_kernel:'; yourself);
		at: 'versions' put: #(); yourself).
	b := Gt4SecurityAffectedEntry fromDictionary: (Dictionary new
		at: 'package' put: (Dictionary new at: 'ecosystem' put: 'Maven'; at: 'name' put: 'com.example:foo'; yourself);
		at: 'versions' put: #('1.0'); yourself).
	group := Gt4SecurityAffectedGroup withAll: { a. b }.
	self assert: group size equals: 2.
	self assert: (group ecosystem: 'Android') size equals: 1.
	self assert: group cpeOnly isEmpty.
	^ group
]

{ #category : 'examples - malicious detection' }
Gt4SecurityParsingExamples >> isMaliciousDetectsIdPrefix [
	<gtExample>
	| vuln |
	vuln := Gt4SecurityVulnerability new
		id: 'MAL-2026-9999';
		aliases: #();
		severity: (Gt4SecuritySeverityGroup withAll: #());
		affected: (Gt4SecurityAffectedGroup withAll: #());
		references: (Gt4SecurityReferenceGroup withAll: #());
		rawJson: Dictionary new;
		yourself.
	self assert: vuln isMalicious.
	self assert: vuln maliciousOrigins isEmpty.
	^ vuln
]

{ #category : 'examples - malicious detection' }
Gt4SecurityParsingExamples >> isMaliciousReturnsFalseForRegularCve [
	<gtExample>
	| vuln |
	vuln := Gt4SecurityVulnerability new
		id: 'CVE-2026-00001';
		aliases: #();
		severity: (Gt4SecuritySeverityGroup withAll: #());
		affected: (Gt4SecurityAffectedGroup withAll: #());
		references: (Gt4SecurityReferenceGroup withAll: #());
		rawJson: Dictionary new;
		yourself.
	self assert: vuln isMalicious not.
	^ vuln
]

{ #category : 'examples - date formatting' }
Gt4SecurityParsingExamples >> nvdDateFormatting [
	"NVD date string formatting — midnight for Date, preserves time for DateAndTime."
	<gtExample>
	| client |
	client := Gt4SecurityNvdClient new.
	self assert: (client nvdDateString: (Date year: 2026 month: 1 day: 5))
		equals: '2026-01-05T00:00:00.000'.
	self assert: (client nvdDateString: (DateAndTime year: 2026 month: 12 day: 31 hour: 23 minute: 59 second: 59))
		equals: '2026-12-31T23:59:59.000'.
	^ client
]

{ #category : 'examples - parsing' }
Gt4SecurityParsingExamples >> parseCpeAffectedEntry [
	"Parse an NVD-style CPE affected entry and verify CPE component extraction. NVD entries leave ecosystem unset — CPE is detected from the package name starting with 'cpe:'."
	<gtExample>
	| dict entry |
	dict := Dictionary new
		at: 'package' put: (Dictionary new
			at: 'name' put: 'cpe:2.3:a:apple:safari:*:*:*:*:*:*:*:*';
			yourself);
		at: 'versions' put: #('< 17.3');
		yourself.
	entry := Gt4SecurityAffectedEntry fromDictionary: dict.
	self assert: entry ecosystem isNil.
	self assert: entry isCpe.
	self assert: entry cpeVendor equals: 'apple'.
	self assert: entry cpeProduct equals: 'safari'.
	self assert: entry cpeVersion equals: '*'.
	self assert: entry displayName equals: 'apple/safari'.
	self assert: entry versionRangeSummary equals: '< 17.3'.
	^ entry
]

{ #category : 'examples - osv' }
Gt4SecurityParsingExamples >> parseMaliciousCwesFromAffected [
	"MAL-* records typically carry CWE info only in per-affected database_specific.cwes — osvCwesFrom: should promote them to the top-level cwes group with descriptions intact."
	<gtExample>
	| dict vuln cwe |
	dict := Dictionary new
		at: 'id' put: 'MAL-test';
		at: 'affected' put: { Dictionary new
			at: 'package' put: (Dictionary new at: 'ecosystem' put: 'npm'; at: 'name' put: 'x'; yourself);
			at: 'database_specific' put: (Dictionary new
				at: 'cwes' put: { Dictionary new
					at: 'cweId' put: 'CWE-506';
					at: 'name' put: 'Embedded Malicious Code';
					at: 'description' put: 'The product contains code that appears to be malicious in nature.';
					yourself };
				yourself);
			yourself };
		at: 'references' put: #();
		at: 'severity' put: #();
		yourself.
	vuln := Gt4SecurityVulnerability fromOsvDictionary: dict.
	self assert: vuln cwes size equals: 1.
	cwe := vuln cwes items first.
	self assert: cwe id equals: 'CWE-506'.
	self assert: cwe description equals: 'The product contains code that appears to be malicious in nature.'.
	^ vuln
]

{ #category : 'examples - cisa kev' }
Gt4SecurityParsingExamples >> parseNvdCveWithCisaKev [
	"Parse a synthetic NVD CVE with CISA KEV fields populated. isInKev should be true; cisaKev should have all fields."
	<gtExample>
	| dict vuln |
	dict := Dictionary new
		at: 'cve' put: (Dictionary new
			at: 'id' put: 'CVE-2026-KEV-1';
			at: 'published' put: '2026-01-01T00:00:00.000';
			at: 'lastModified' put: '2026-01-15T00:00:00.000';
			at: 'descriptions' put: { Dictionary new at: 'lang' put: 'en'; at: 'value' put: 'Actively exploited test bug'; yourself };
			at: 'metrics' put: Dictionary new;
			at: 'references' put: #();
			at: 'configurations' put: #();
			at: 'cisaExploitAdd' put: '2026-01-10';
			at: 'cisaActionDue' put: '2026-01-31';
			at: 'cisaRequiredAction' put: 'Apply vendor patch or discontinue product use.';
			at: 'cisaVulnerabilityName' put: 'Test Vulnerability in Fake Product';
			yourself);
		yourself.
	vuln := Gt4SecurityVulnerability fromNvdDictionary: dict.
	self assert: vuln isInKev.
	self assert: vuln cisaKev exploitAddedDate equals: '2026-01-10'.
	self assert: vuln cisaKev actionDueDate equals: '2026-01-31'.
	self assert: vuln cisaKev vulnerabilityName equals: 'Test Vulnerability in Fake Product'.
	^ vuln
]

{ #category : 'examples - nvd parsing' }
Gt4SecurityParsingExamples >> parseNvdCveWithCvssV2 [
	"Parse a synthetic NVD item with only CVSS v2 metrics — baseSeverity at entry level, not inside cvssData."
	<gtExample>
	| dict vuln |
	dict := Dictionary new
		at: 'cve' put: (Dictionary new
			at: 'id' put: 'CVE-2015-00001';
			at: 'published' put: '2015-06-01T00:00:00.000';
			at: 'lastModified' put: '2020-01-01T00:00:00.000';
			at: 'descriptions' put: { Dictionary new at: 'lang' put: 'en'; at: 'value' put: 'Old vuln'; yourself };
			at: 'metrics' put: (Dictionary new
				at: 'cvssMetricV2' put: { Dictionary new
					at: 'cvssData' put: (Dictionary new
						at: 'vectorString' put: 'AV:N/AC:L/Au:N/C:C/I:C/A:C';
						at: 'baseScore' put: 10.0;
						yourself);
					at: 'baseSeverity' put: 'HIGH';
					yourself };
				yourself);
			at: 'references' put: #();
			at: 'configurations' put: #();
			yourself);
		yourself.
	vuln := Gt4SecurityVulnerability fromNvdDictionary: dict.
	self assert: vuln severity primary type equals: 'CVSS_V2.0'.
	self assert: vuln severity primary baseScore equals: 10.0.
	self assert: vuln severity primary baseSeverity equals: 'HIGH'.
	^ vuln
]

{ #category : 'examples - nvd parsing' }
Gt4SecurityParsingExamples >> parseNvdCveWithCvssV31 [
	"Parse a synthetic NVD v2 response item with CVSS v3.1 metrics."
	<gtExample>
	| dict vuln |
	dict := Dictionary new
		at: 'cve' put: (Dictionary new
			at: 'id' put: 'CVE-2026-00001';
			at: 'published' put: '2026-01-15T10:30:00.000';
			at: 'lastModified' put: '2026-02-01T12:00:00.000';
			at: 'descriptions' put: {
				Dictionary new at: 'lang' put: 'en'; at: 'value' put: 'A buffer overflow in Example SDK'; yourself.
				Dictionary new at: 'lang' put: 'es'; at: 'value' put: 'Spanish desc'; yourself };
			at: 'metrics' put: (Dictionary new
				at: 'cvssMetricV31' put: { Dictionary new
					at: 'cvssData' put: (Dictionary new
						at: 'vectorString' put: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
						at: 'baseScore' put: 9.8;
						at: 'baseSeverity' put: 'CRITICAL';
						yourself);
					yourself };
				yourself);
			at: 'references' put: {
				Dictionary new at: 'url' put: 'https://example.com/advisory'; at: 'source' put: 'vendor'; at: 'tags' put: #('Patch'); yourself };
			at: 'configurations' put: { Dictionary new
				at: 'nodes' put: { Dictionary new
					at: 'cpeMatch' put: { Dictionary new
						at: 'criteria' put: 'cpe:2.3:a:example:sdk:1.0:*:*:*:*:*:*:*';
						at: 'vulnerable' put: true;
						at: 'versionEndExcluding' put: '2.0';
						yourself };
					yourself };
				yourself };
			yourself);
		yourself.
	vuln := Gt4SecurityVulnerability fromNvdDictionary: dict.
	self assert: vuln id equals: 'CVE-2026-00001'.
	self assert: vuln summary equals: 'A buffer overflow in Example SDK'.
	self assert: vuln published equals: '2026-01-15T10:30:00.000'.
	self assert: vuln modified equals: '2026-02-01T12:00:00.000'.
	"NVD CPE entries carry no OSV ecosystem — primaryEcosystem is nil; CPE detection is via isCpe/hasCpeAffected."
	self assert: vuln primaryEcosystem isNil.
	self assert: vuln hasCpeAffected.
	self assert: vuln primaryCpeVendor equals: 'example'.
	self assert: vuln severity primary baseScore equals: 9.8.
	self assert: vuln severity primary baseSeverity equals: 'CRITICAL'.
	self assert: vuln severity primary type equals: 'CVSS_V3.1'.
	self assert: vuln affected notEmpty.
	self assert: vuln references notEmpty.
	self assert: vuln references items first type equals: 'Patch'.
	self assert: vuln isMalicious not.
	^ vuln
]

{ #category : 'examples - cisa kev' }
Gt4SecurityParsingExamples >> parseNvdCveWithoutCisaKev [
	"Regression: when cisaExploitAdd is absent, cisaKev must be nil and isInKev false."
	<gtExample>
	| dict vuln |
	dict := Dictionary new
		at: 'cve' put: (Dictionary new
			at: 'id' put: 'CVE-2026-NOKEV-1';
			at: 'published' put: '2026-01-01T00:00:00.000';
			at: 'lastModified' put: '2026-01-15T00:00:00.000';
			at: 'descriptions' put: { Dictionary new at: 'lang' put: 'en'; at: 'value' put: 'Regular bug'; yourself };
			at: 'metrics' put: Dictionary new;
			at: 'references' put: #();
			at: 'configurations' put: #();
			yourself);
		yourself.
	vuln := Gt4SecurityVulnerability fromNvdDictionary: dict.
	self assert: vuln cisaKev isNil.
	self assert: vuln isInKev not.
	^ vuln
]

{ #category : 'examples - osv' }
Gt4SecurityParsingExamples >> parseOsvAdvisorySourceUrl [
	"Per-affected database_specific.source populates Gt4SecurityAffectedEntry>>#advisorySourceUrl."
	<gtExample>
	| dict entry |
	dict := Dictionary new
		at: 'package' put: (Dictionary new at: 'ecosystem' put: 'npm'; at: 'name' put: 'x'; yourself);
		at: 'database_specific' put: (Dictionary new
			at: 'source' put: 'https://github.com/ossf/malicious-packages/blob/main/osv/...';
			yourself);
		yourself.
	entry := Gt4SecurityAffectedEntry fromDictionary: dict.
	self assert: entry advisorySourceUrl equals: 'https://github.com/ossf/malicious-packages/blob/main/osv/...'.
	^ entry
]

{ #category : 'examples - osv' }
Gt4SecurityParsingExamples >> parseOsvAffectedEntry [
	"Parse an OSV-style affected entry — not a CPE, should return package name directly."
	<gtExample>
	| dict entry |
	dict := Dictionary new
		at: 'package' put: (Dictionary new
			at: 'ecosystem' put: 'Maven';
			at: 'name' put: 'com.squareup.okhttp3:okhttp';
			yourself);
		at: 'versions' put: #('4.9.0' '4.9.1');
		yourself.
	entry := Gt4SecurityAffectedEntry fromDictionary: dict.
	self assert: entry isCpe not.
	self assert: entry cpeVendor isNil.
	self assert: entry displayName equals: 'com.squareup.okhttp3:okhttp'.
	self assert: entry versionRangeSummary equals: '4.9.0, 4.9.1'.
	^ entry
]

{ #category : 'examples - osv' }
Gt4SecurityParsingExamples >> parseOsvAffectedRanges [
	"OSV affected[].ranges parses into Gt4SecurityVersionRange, and versionRangeSummary prefers ranges over the (sparse) versions array — the common shape for npm CVEs."
	<gtExample>
	| dict entry |
	dict := Dictionary new
		at: 'package' put: (Dictionary new
			at: 'ecosystem' put: 'npm';
			at: 'name' put: 'nanoid';
			yourself);
		at: 'ranges' put: { Dictionary new
			at: 'type' put: 'SEMVER';
			at: 'events' put: {
				(Dictionary new at: 'introduced' put: '4.0.0'; yourself).
				(Dictionary new at: 'fixed' put: '5.0.9'; yourself) };
			yourself };
		yourself.
	entry := Gt4SecurityAffectedEntry fromDictionary: dict.
	self assert: entry ranges size equals: 1.
	self assert: entry ranges first type equals: 'SEMVER'.
	self assert: entry ranges first introducedVersions asArray equals: #('4.0.0').
	self assert: entry ranges first fixedVersions asArray equals: #('5.0.9').
	self assert: entry versionRangeSummary equals: '>= 4.0.0, < 5.0.9'.
	^ entry
]

{ #category : 'examples - osv parsing' }
Gt4SecurityParsingExamples >> parseOsvAndroidVulnerability [
	"Parse a synthetic OSV Android vulnerability dictionary."
	<gtExample>
	| dict vuln |
	dict := Dictionary new
		at: 'id' put: 'ASB-A-999999999';
		at: 'summary' put: 'Test Android kernel bug';
		at: 'details' put: 'Detailed description of the bug';
		at: 'published' put: '2026-03-01T00:00:00Z';
		at: 'modified' put: '2026-04-01T00:00:00Z';
		at: 'aliases' put: #('CVE-2026-99999');
		at: 'severity' put: { Dictionary new at: 'type' put: 'CVSS_V3'; at: 'score' put: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'; yourself };
		at: 'affected' put: { Dictionary new
			at: 'package' put: (Dictionary new at: 'ecosystem' put: 'Android'; at: 'name' put: ':linux_kernel:'; yourself);
			at: 'versions' put: #('5.10' '5.15');
			yourself };
		at: 'references' put: { Dictionary new at: 'type' put: 'ADVISORY'; at: 'url' put: 'https://example.com/advisory'; yourself };
		yourself.
	vuln := Gt4SecurityVulnerability fromOsvDictionary: dict.
	self assert: vuln id equals: 'ASB-A-999999999'.
	self assert: vuln summary equals: 'Test Android kernel bug'.
	self assert: vuln published equals: '2026-03-01T00:00:00Z'.
	self assert: vuln aliases items first id equals: 'CVE-2026-99999'.
	self assert: vuln primaryEcosystem equals: 'Android'.
	self assert: vuln primarySeverityScore notEmpty.
	self assert: vuln affected size equals: 1.
	self assert: vuln references size equals: 1.
	self assert: vuln isMalicious not.
	^ vuln
]

{ #category : 'examples - osv' }
Gt4SecurityParsingExamples >> parseOsvGithubMetadata [
	"Top-level database_specific GitHub curation fields populate Gt4SecurityGithubMetadata; records without any such key leave it nil."
	<gtExample>
	| ghsaDict ghsa malDict mal |
	ghsaDict := Dictionary new
		at: 'id' put: 'GHSA-test';
		at: 'affected' put: #();
		at: 'references' put: #();
		at: 'severity' put: #();
		at: 'database_specific' put: (Dictionary new
			at: 'github_reviewed' put: true;
			at: 'github_reviewed_at' put: '2024-12-09T22:42:43Z';
			at: 'nvd_published_at' put: '2024-12-09T02:15:19Z';
			at: 'severity' put: 'MODERATE';
			yourself);
		yourself.
	ghsa := Gt4SecurityVulnerability fromOsvDictionary: ghsaDict.
	self assert: ghsa githubMetadata notNil.
	self assert: ghsa githubMetadata isReviewed.
	self assert: ghsa githubMetadata severityLabel equals: 'MODERATE'.

	malDict := Dictionary new
		at: 'id' put: 'MAL-test';
		at: 'affected' put: #();
		at: 'references' put: #();
		at: 'severity' put: #();
		yourself.
	mal := Gt4SecurityVulnerability fromOsvDictionary: malDict.
	self assert: mal githubMetadata isNil.
	^ ghsa
]

{ #category : 'examples - osv' }
Gt4SecurityParsingExamples >> parseOsvRelatedField [
	"Top-level `related` parses into the related group, distinct from aliases."
	<gtExample>
	| dict vuln |
	dict := Dictionary new
		at: 'id' put: 'GHSA-test-1234';
		at: 'aliases' put: #('CVE-2024-12345');
		at: 'related' put: #('CGA-abcd-efgh-ijkl');
		at: 'affected' put: #();
		at: 'references' put: #();
		at: 'severity' put: #();
		yourself.
	vuln := Gt4SecurityVulnerability fromOsvDictionary: dict.
	self assert: vuln aliases size equals: 1.
	self assert: vuln aliases idStrings asArray equals: #('CVE-2024-12345').
	self assert: vuln related size equals: 1.
	self assert: vuln related idStrings asArray equals: #('CGA-abcd-efgh-ijkl').
	^ vuln
]

{ #category : 'examples - reference' }
Gt4SecurityParsingExamples >> parseReference [
	"Reference domain object extracts type, URL, host from a dict."
	<gtExample>
	| dict ref |
	dict := Dictionary new at: 'type' put: 'ADVISORY'; at: 'url' put: 'https://support.apple.com/en-us/118479'; yourself.
	ref := Gt4SecurityReference fromDictionary: dict.
	self assert: ref type equals: 'ADVISORY'.
	self assert: ref url equals: 'https://support.apple.com/en-us/118479'.
	self assert: ref host equals: 'support.apple.com'.
	self assert: ref isAdvisory.
	self assert: ref isPatch not.
	^ ref
]

{ #category : 'examples - reference' }
Gt4SecurityParsingExamples >> referenceGroup [
	"Group filter chain works end to end."
	<gtExample>
	| group advisories |
	group := Gt4SecurityReferenceGroup withAll: {
		Gt4SecurityReference fromDictionary: (Dictionary new at: 'type' put: 'ADVISORY'; at: 'url' put: 'https://a.example.com/1'; yourself).
		Gt4SecurityReference fromDictionary: (Dictionary new at: 'type' put: 'Patch'; at: 'url' put: 'https://github.com/fix'; yourself).
		Gt4SecurityReference fromDictionary: (Dictionary new at: 'type' put: 'ADVISORY'; at: 'url' put: 'https://b.example.com/2'; yourself) }.
	self assert: group size equals: 3.
	advisories := group advisories.
	self assert: advisories class equals: Gt4SecurityReferenceGroup.
	self assert: advisories size equals: 2.
	self assert: group patches size equals: 1.
	^ group
]
