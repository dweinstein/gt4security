"
Known-answer tests for the CVSS calculator — vectors with verified reference scores for V2, V3.0, V3.1, V4.0. Plus two comparison examples. All offline. Used to guard against scoring regressions.
"
Class {
	#name : 'Gt4SecurityCvssExamples',
	#superclass : 'Object',
	#category : 'Gt4Security-Examples',
	#package : 'Gt4Security',
	#tag : 'Examples'
}

{ #category : 'examples - comparison' }
Gt4SecurityCvssExamples >> compareTwoV31Vectors [
	"Two different V3.1 vectors — metric diff highlights what makes one worse."
	<gtExample>
	| comp |
	comp := Gt4SecurityCvssComparison fromVectorStrings: {
		'Safari (8.8)' -> 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'.
		'Info disc (5.9)' -> 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' }.
	self assert: comp entries size equals: 2.
	self assert: comp allMetricAbbreviations size equals: 8.
	self assert: comp maxScore equals: 8.8.
	^ comp
]

{ #category : 'examples - comparison' }
Gt4SecurityCvssExamples >> compareVersions [
	"Same logical vulnerability scored across V2, V3.1, V4.0 — shows how scoring diverges."
	<gtExample>
	| comp |
	comp := Gt4SecurityCvssComparison fromVectorStrings: {
		'V2 (RCE)' -> 'AV:N/AC:L/Au:N/C:C/I:C/A:C'.
		'V3.1 (RCE)' -> 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'.
		'V4.0 (RCE)' -> 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }.
	self assert: comp entries size equals: 3.
	self assert: (comp entries first value baseScore between: 9.0 and: 10.0).
	^ comp
]

{ #category : 'examples - v2' }
Gt4SecurityCvssExamples >> v2CriticalRemoteExec [
	"AV:N/AC:M/Au:N/C:C/I:C/A:C = 9.3 HIGH (V2 has no CRITICAL label)"
	<gtExample>
	| vec |
	vec := Gt4SecurityCvssVector fromString: 'AV:N/AC:M/Au:N/C:C/I:C/A:C'.
	self assert: vec baseScore equals: 9.3.
	self assert: vec severityLabel equals: 'CRITICAL'.
	^ vec
]

{ #category : 'examples - v2' }
Gt4SecurityCvssExamples >> v2HighDoS [
	"CVE-2002-0392: AV:N/AC:L/Au:N/C:N/I:N/A:C = 7.8 HIGH"
	<gtExample>
	| vec |
	vec := Gt4SecurityCvssVector fromString: 'AV:N/AC:L/Au:N/C:N/I:N/A:C'.
	self assert: vec version equals: '2.0'.
	self assert: vec baseScore equals: 7.8.
	self assert: vec severityLabel equals: 'HIGH'.
	self assert: vec metrics size equals: 6.
	^ vec
]

{ #category : 'examples - v3' }
Gt4SecurityCvssExamples >> v30SameFormulaAsV31 [
	"V3.0 and V3.1 use the same formula — same vector should produce the same score."
	<gtExample>
	| v30 v31 |
	v30 := Gt4SecurityCvssVector fromString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'.
	v31 := Gt4SecurityCvssVector fromString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'.
	self assert: v30 version equals: '3.0'.
	self assert: v31 version equals: '3.1'.
	self assert: v30 baseScore equals: v31 baseScore.
	^ v31
]

{ #category : 'examples - v3' }
Gt4SecurityCvssExamples >> v31CurveBallCve [
	"CVE-2020-0601 (CurveBall): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = 8.1 HIGH"
	<gtExample>
	| vec |
	vec := Gt4SecurityCvssVector fromString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N'.
	self assert: vec version equals: '3.1'.
	self assert: vec baseScore equals: 8.1.
	self assert: vec severityLabel equals: 'HIGH'.
	^ vec
]

{ #category : 'examples - v3' }
Gt4SecurityCvssExamples >> v31DoSOnly [
	"Network DoS, no confidentiality/integrity: 7.5 HIGH"
	<gtExample>
	| vec |
	vec := Gt4SecurityCvssVector fromString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'.
	self assert: vec baseScore equals: 7.5.
	^ vec
]

{ #category : 'examples - v3' }
Gt4SecurityCvssExamples >> v31InfoDisclosure [
	"High-complexity info disclosure: 5.9 MEDIUM"
	<gtExample>
	| vec |
	vec := Gt4SecurityCvssVector fromString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'.
	self assert: vec baseScore equals: 5.9.
	self assert: vec severityLabel equals: 'MEDIUM'.
	^ vec
]

{ #category : 'examples - v3' }
Gt4SecurityCvssExamples >> v31SafariTypeConfusion [
	"CVE-2024-23222 (Safari): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8 HIGH"
	<gtExample>
	| vec |
	vec := Gt4SecurityCvssVector fromString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'.
	self assert: vec baseScore equals: 8.8.
	self assert: vec severityLabel equals: 'HIGH'.
	^ vec
]

{ #category : 'examples - v3' }
Gt4SecurityCvssExamples >> v31ScopeChangedMax [
	"Max V3.1 with scope changed: 10.0 CRITICAL"
	<gtExample>
	| vec |
	vec := Gt4SecurityCvssVector fromString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'.
	self assert: vec baseScore equals: 10.0.
	self assert: vec severityLabel equals: 'CRITICAL'.
	^ vec
]

{ #category : 'examples - v4' }
Gt4SecurityCvssExamples >> v40AllImpactZero [
	"V4 with all impact metrics None → score 0.0"
	<gtExample>
	| vec |
	vec := Gt4SecurityCvssVector fromString: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'.
	self assert: vec baseScore equals: 0.0.
	^ vec
]

{ #category : 'examples - v4' }
Gt4SecurityCvssExamples >> v40AxiosVector [
	"Real V4 vector from OSV axios entry. Computed score should be reasonable (HIGH range)."
	<gtExample>
	| vec |
	vec := Gt4SecurityCvssVector fromString: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:L/SA:L'.
	self assert: vec version equals: '4.0'.
	self assert: vec baseScore notNil.
	self assert: (vec baseScore between: 7.0 and: 10.0).
	self assert: vec severityLabel equals: 'HIGH'.
	self assert: vec metrics size equals: 11.
	^ vec
]
