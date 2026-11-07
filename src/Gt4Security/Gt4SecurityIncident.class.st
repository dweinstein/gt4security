"
Mobile security incident that is NOT tracked in any CVE database — espionage SDKs, typosquat malware, supply chain compromises, vendor policy violations, etc. Examples: Pushwoosh (Russian push SDK embedded in US gov apps), SpinOk (Android spyware in 421M installs), EngageLab SDK intent redirection vuln, CocoaPods Trunk takeover.

Fields: name, vendor, year, platforms (iOS / Android / both), category (espionage / spyware / supply chain / ...), description, sourceUrl (primary advisory), affectedInstalls (free-text), status (active / patched / removed).

Use {{gtClass:Gt4SecurityIncidentGroup}} for inspectable groups of these. The canonical 21-entry catalog is built by {{gtMethod:Gt4SecurityIncidentExamples>>#allIncidents}}.
"
Class {
	#name : 'Gt4SecurityIncident',
	#superclass : 'Object',
	#instVars : [
		'name',
		'vendor',
		'year',
		'platforms',
		'category',
		'description',
		'sourceUrl',
		'affectedInstalls',
		'status'
	],
	#category : 'Gt4Security-Incidents',
	#package : 'Gt4Security',
	#tag : 'Incidents'
}

{ #category : 'accessing' }
Gt4SecurityIncident >> affectedInstalls [
	^ affectedInstalls
]

{ #category : 'accessing' }
Gt4SecurityIncident >> affectedInstalls: aString [
	affectedInstalls := aString
]

{ #category : 'derived' }
Gt4SecurityIncident >> affectsAndroid [
	^ platforms includes: 'Android'
]

{ #category : 'derived' }
Gt4SecurityIncident >> affectsIos [
	^ platforms includes: 'iOS'
]

{ #category : 'accessing' }
Gt4SecurityIncident >> category [
	^ category
]

{ #category : 'accessing' }
Gt4SecurityIncident >> category: aString [
	category := aString
]

{ #category : 'accessing' }
Gt4SecurityIncident >> description [
	^ description
]

{ #category : 'accessing' }
Gt4SecurityIncident >> description: aString [
	description := aString
]

{ #category : 'gt - views' }
Gt4SecurityIncident >> gtDescriptionFor: aView [
	<gtView>
	description ifNil: [ ^ aView empty ].
	^ aView textEditor
		title: 'Description';
		priority: 2;
		text: [ description ]
]

{ #category : 'printing' }
Gt4SecurityIncident >> gtDisplayOn: aStream [
	aStream nextPutAll: (name ifNil: [ '(unknown)' ])
]

{ #category : 'gt - views' }
Gt4SecurityIncident >> gtOpenSourceActionFor: anAction [
	<gtAction>
	^ anAction button
		icon: BrGlamorousVectorIcons browse;
		tooltip: 'Open source in browser';
		priority: 10;
		action: [ :aButton |
			sourceUrl ifNotNil: [ :url |
				WebBrowser openOn: url ] ]
]

{ #category : 'gt - views' }
Gt4SecurityIncident >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 1;
		items: [ {
			'Name' -> (name ifNil: [ '(unknown)' ]).
			'Vendor' -> (vendor ifNil: [ '(unknown)' ]).
			'Year' -> (year ifNil: [ '?' ] ifNotNil: [ year printString ]).
			'Platforms' -> (', ' join: platforms).
			'Category' -> (category ifNil: [ '(unknown)' ]).
			'Affected installs' -> (affectedInstalls ifNil: [ '(unknown)' ]).
			'Status' -> (status ifNil: [ '(unknown)' ]).
			'Source' -> (sourceUrl ifNil: [ '(none)' ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'initialization' }
Gt4SecurityIncident >> initialize [
	super initialize.
	platforms := #().
	status := 'active'
]

{ #category : 'derived' }
Gt4SecurityIncident >> isActive [
	^ status = 'active'
]

{ #category : 'accessing' }
Gt4SecurityIncident >> name [
	^ name
]

{ #category : 'accessing' }
Gt4SecurityIncident >> name: aString [
	name := aString
]

{ #category : 'accessing' }
Gt4SecurityIncident >> platforms [
	^ platforms
]

{ #category : 'accessing' }
Gt4SecurityIncident >> platforms: anArray [
	platforms := anArray
]

{ #category : 'printing' }
Gt4SecurityIncident >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (';
		nextPutAll: (name ifNil: [ '?' ]);
		nextPutAll: ', ';
		print: (year ifNil: [ 0 ]);
		nextPutAll: ', ';
		nextPutAll: (category ifNil: [ '?' ]);
		nextPutAll: ')'
]

{ #category : 'accessing' }
Gt4SecurityIncident >> sourceUrl [
	^ sourceUrl
]

{ #category : 'accessing' }
Gt4SecurityIncident >> sourceUrl: aString [
	sourceUrl := aString
]

{ #category : 'accessing' }
Gt4SecurityIncident >> status [
	^ status
]

{ #category : 'accessing' }
Gt4SecurityIncident >> status: aString [
	status := aString
]

{ #category : 'accessing' }
Gt4SecurityIncident >> vendor [
	^ vendor
]

{ #category : 'accessing' }
Gt4SecurityIncident >> vendor: aString [
	vendor := aString
]

{ #category : 'accessing' }
Gt4SecurityIncident >> year [
	^ year
]

{ #category : 'accessing' }
Gt4SecurityIncident >> year: anInteger [
	year := anInteger
]
