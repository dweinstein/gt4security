"
Wraps a single {type, url} reference entry from a {{gtClass:Gt4SecurityVulnerability}} — links to advisories, patches, exploits, news articles, etc.

Common types: ADVISORY, FIX/Patch, Exploit, Third Party Advisory, Release Notes, Mitigation, Mailing List. Types vary between OSV and NVD sources.

Fields: type, url, rawDict. Derived: isAdvisory, isPatch, isExploit, host (extracted from URL).

Includes a gtOpenInBrowserActionFor: toolbar button — one-click open the URL in the system browser.
"
Class {
	#name : 'Gt4SecurityReference',
	#superclass : 'Object',
	#instVars : [
		'type',
		'url',
		'rawDict'
	],
	#category : 'Gt4Security-Domain',
	#package : 'Gt4Security',
	#tag : 'Domain'
}

{ #category : 'instance creation' }
Gt4SecurityReference class >> fromDictionary: aDictionary [
	^ self new
		type: (aDictionary at: 'type' ifAbsent: [ nil ]);
		url: (aDictionary at: 'url' ifAbsent: [ nil ]);
		rawDict: aDictionary;
		yourself
]

{ #category : 'printing' }
Gt4SecurityReference >> gtDisplayOn: aStream [
	aStream
		nextPutAll: (type ifNil: [ 'REF' ]);
		nextPutAll: ' · ';
		nextPutAll: self host
]

{ #category : 'gt - views' }
Gt4SecurityReference >> gtOpenInBrowserActionFor: anAction [
	<gtAction>
	url ifNil: [ ^ anAction noAction ].
	^ anAction button
		icon: BrGlamorousVectorIcons browse;
		tooltip: 'Open in browser';
		priority: 10;
		action: [ :aButton | WebBrowser openOn: url ]
]

{ #category : 'gt - views' }
Gt4SecurityReference >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Reference';
		priority: 1;
		items: [ {
			'Type' -> (type ifNil: [ '(none)' ]).
			'Host' -> self host.
			'URL' -> (url ifNil: [ '(none)' ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'derived' }
Gt4SecurityReference >> host [
	"Extract the host name from the URL — useful for grouping."
	url ifNil: [ ^ '(no url)' ].
	^ ([ url asZnUrl host ] on: Error do: [ :e | '(invalid url)' ]) ifNil: [ '(no host)' ]
]

{ #category : 'derived' }
Gt4SecurityReference >> isAdvisory [
	^ type = 'ADVISORY'
]

{ #category : 'derived' }
Gt4SecurityReference >> isExploit [
	^ type = 'Exploit'
]

{ #category : 'derived' }
Gt4SecurityReference >> isPatch [
	^ type = 'FIX' or: [ type = 'Patch' ]
]

{ #category : 'printing' }
Gt4SecurityReference >> printOn: aStream [
	super printOn: aStream.
	aStream
		nextPutAll: ' (';
		nextPutAll: (type ifNil: [ '?' ]);
		nextPutAll: ': ';
		nextPutAll: self host;
		nextPut: $)
]

{ #category : 'accessing' }
Gt4SecurityReference >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityReference >> rawDict: aDictionary [
	rawDict := aDictionary
]

{ #category : 'accessing' }
Gt4SecurityReference >> type [
	^ type
]

{ #category : 'accessing' }
Gt4SecurityReference >> type: aString [
	type := aString
]

{ #category : 'accessing' }
Gt4SecurityReference >> url [
	^ url
]

{ #category : 'accessing' }
Gt4SecurityReference >> url: aString [
	url := aString
]
