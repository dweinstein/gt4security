Class {
	#name : 'Gt4SecurityFormat',
	#superclass : 'Object',
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'formatting' }
Gt4SecurityFormat class >> humanBytes: anInteger [
	"Render a byte count with a binary-prefix unit (KB / MB / GB) chosen so the magnitude
	stays in [1, 1024). Plain '0 B' when zero, '—' for nil."
	| value units idx |
	anInteger ifNil: [ ^ '—' ].
	anInteger = 0 ifTrue: [ ^ '0 B' ].
	value := anInteger asFloat.
	units := #('B' 'KB' 'MB' 'GB' 'TB' 'PB').
	idx := 1.
	[ value >= 1024 and: [ idx < units size ] ] whileTrue: [
		value := value / 1024.0.
		idx := idx + 1 ].
	^ String streamContents: [ :s |
		idx = 1
			ifTrue: [ s print: anInteger; space; nextPutAll: 'B' ]
			ifFalse: [ s nextPutAll: (value printShowingDecimalPlaces: 1); space; nextPutAll: (units at: idx) ] ]
]

{ #category : 'formatting' }
Gt4SecurityFormat class >> humanDuration: aDuration [
	"Render a Duration as the same compact ms-based form used elsewhere — '312 ms',
	'2.40 s', '1m 9s'. Pharo's Duration>>humanReadablePrintString is too verbose for
	summary cells ('22 seconds 628 milliseconds 722 microseconds')."
	aDuration ifNil: [ ^ '—' ].
	^ self humanMs: aDuration asMilliSeconds
]

{ #category : 'formatting' }
Gt4SecurityFormat class >> humanMs: anInteger [
	"Render a millisecond count as ms / s / m s — choose the unit by magnitude."
	anInteger ifNil: [ ^ '—' ].
	anInteger = 0 ifTrue: [ ^ '0 ms' ].
	anInteger < 1000 ifTrue: [ ^ anInteger asString , ' ms' ].
	anInteger < 60000 ifTrue: [
		^ (anInteger / 1000.0 printShowingDecimalPlaces: 2) , ' s' ].
	^ String streamContents: [ :s |
		s print: anInteger // 60000;
			nextPutAll: 'm ';
			print: (anInteger \\ 60000) // 1000;
			nextPutAll: 's' ]
]

{ #category : 'formatting' }
Gt4SecurityFormat class >> humanTime: aDateAndTime [
	"Render a DateAndTime as the local hh:mm:ss without the noisy ISO offset. '—' for nil."
	aDateAndTime ifNil: [ ^ '—' ].
	^ String streamContents: [ :s |
		| t |
		t := aDateAndTime asTime.
		s
			print: t hour; nextPut: $:;
			nextPutAll: (t minute printPaddedWith: $0 to: 2); nextPut: $:;
			nextPutAll: (t second printPaddedWith: $0 to: 2) ]
]

{ #category : 'formatting' }
Gt4SecurityFormat class >> humanTimespan: aTimespan [
	"Render a Timespan / DateAndTime / Date as 'since 29 Jan 2026 (1d)' / 'since 29 Jan 2026'.
	'—' for nil. Used in summary views where raw Timespan printString
	('a Timespan(2026-01-29T00:00:00-04:00D1:00:00:00)') is too noisy."
	aTimespan ifNil: [ ^ '—' ].
	(aTimespan isKindOf: Timespan)
		ifTrue: [
			| days |
			days := aTimespan duration days.
			^ String streamContents: [ :s |
				s nextPutAll: 'since '; nextPutAll: aTimespan asDate printString.
				days > 0 ifTrue: [
					s nextPutAll: ' ('; print: days; nextPutAll: 'd)' ] ] ].
	(aTimespan isKindOf: DateAndTime)
		ifTrue: [ ^ 'since ' , aTimespan asDate printString ].
	(aTimespan isKindOf: Date)
		ifTrue: [ ^ 'since ' , aTimespan printString ].
	^ aTimespan printString
]
