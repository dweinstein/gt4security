"
GHSA curation metadata mined from an OSV record's top-level `database_specific`.

Present when OSV-SVC-* / GHSA-* sources enrich the record with GitHub review state and NVD cross-linking timestamps. Nil for records without any of these fields (e.g., MAL-* entries, bare OSV).

Slots:
- reviewed — `github_reviewed` flag. True when the GHSA Review team has vetted the advisory.
- reviewedAt — ISO 8601 timestamp of the last GHSA review.
- nvdPublishedAt — ISO 8601 NVD publication time, when known.
- severityLabel — textual severity from GHSA (HIGH / CRITICAL / ...), independent of the CVSS severity array.

Parsed via `fromOsvDatabaseSpecific:` — returns nil if none of the relevant keys are present so callers can treat ""no metadata"" as `ifNotNil:`.
"
Class {
	#name : 'Gt4SecurityGithubMetadata',
	#superclass : 'Object',
	#instVars : [
		'reviewed',
		'reviewedAt',
		'nvdPublishedAt',
		'severityLabel',
		'rawDict'
	],
	#category : 'Gt4Security-Domain',
	#package : 'Gt4Security',
	#tag : 'Domain'
}

{ #category : 'instance creation' }
Gt4SecurityGithubMetadata class >> fromOsvDatabaseSpecific: aDictionaryOrNil [
	"Return a metadata object if at least one GitHub-curation key is present, else nil."
	| relevantKeys present |
	aDictionaryOrNil ifNil: [ ^ nil ].
	relevantKeys := #('github_reviewed' 'github_reviewed_at' 'nvd_published_at' 'severity').
	present := relevantKeys anySatisfy: [ :k | aDictionaryOrNil includesKey: k ].
	present ifFalse: [ ^ nil ].
	^ self new
		reviewed: (aDictionaryOrNil at: 'github_reviewed' ifAbsent: [ nil ]);
		reviewedAt: (aDictionaryOrNil at: 'github_reviewed_at' ifAbsent: [ nil ]);
		nvdPublishedAt: (aDictionaryOrNil at: 'nvd_published_at' ifAbsent: [ nil ]);
		severityLabel: (aDictionaryOrNil at: 'severity' ifAbsent: [ nil ]);
		rawDict: aDictionaryOrNil;
		yourself
]

{ #category : 'gt - views' }
Gt4SecurityGithubMetadata >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 1;
		items: [ {
			'GHSA reviewed?' -> (reviewed ifNil: [ '(unknown)' ] ifNotNil: [ reviewed asString ]).
			'GHSA reviewed at' -> (reviewedAt ifNil: [ '(none)' ]).
			'NVD published at' -> (nvdPublishedAt ifNil: [ '(none)' ]).
			'Severity label' -> (severityLabel ifNil: [ '(none)' ]) } ];
		column: 'Property' text: [ :a | a key ] weight: 1;
		column: 'Value' text: [ :a | a value asString ] weight: 2
]

{ #category : 'testing' }
Gt4SecurityGithubMetadata >> isReviewed [
	^ reviewed = true
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> nvdPublishedAt [
	^ nvdPublishedAt
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> nvdPublishedAt: aString [
	nvdPublishedAt := aString
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> rawDict: aDictionary [
	rawDict := aDictionary
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> reviewed [
	^ reviewed
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> reviewed: aBoolean [
	reviewed := aBoolean
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> reviewedAt [
	^ reviewedAt
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> reviewedAt: aString [
	reviewedAt := aString
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> severityLabel [
	^ severityLabel
]

{ #category : 'accessing' }
Gt4SecurityGithubMetadata >> severityLabel: aString [
	severityLabel := aString
]
