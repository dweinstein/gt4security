"
Inspectable group of {{gtClass:Gt4SecurityAffectedEntry}} using {{gtClass:TGtGroupWithItems}}.

Type-preserving filters: ecosystem:, cpeOnly, matching:.

GT views: Affected (columned list), By ecosystem (drill-through).
"
Class {
	#name : 'Gt4SecurityAffectedGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security-Domain',
	#package : 'Gt4Security',
	#tag : 'Domain'
}

{ #category : 'instance creation' }
Gt4SecurityAffectedGroup class >> withAll: aCollection [
	^ self new addItems: aCollection; yourself
]

{ #category : 'filtering' }
Gt4SecurityAffectedGroup >> cpeOnly [
	^ self select: [ :each | each isCpe ]
]

{ #category : 'filtering' }
Gt4SecurityAffectedGroup >> ecosystem: anEcosystemString [
	^ self select: [ :each | each ecosystem = anEcosystemString ]
]

{ #category : 'gt - views' }
Gt4SecurityAffectedGroup >> gtAffectedFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Affected';
		priority: 1;
		items: [ self items ];
		column: 'Ecosystem' text: [ :each | each ecosystem ifNil: [ '' ] ] weight: 1;
		column: 'Package' text: [ :each | each displayName ] weight: 2;
		column: 'Versions' text: [ :each | each versionRangeSummary ] weight: 2
]

{ #category : 'gt - views' }
Gt4SecurityAffectedGroup >> gtByConfigurationFor: aView [
	<gtView>
	"Only meaningful for NVD-sourced vulns (OSV entries have nil configurationIndex)."
	| annotated |
	annotated := self items select: [ :e | e configurationIndex notNil ].
	annotated isEmpty ifTrue: [ ^ aView empty ].
	^ aView columnedList
		title: 'By configuration';
		priority: 3;
		items: [
			(annotated
				inject: Dictionary new
				into: [ :acc :each |
					| key |
					key := 'config[' , each configurationIndex printString ,
						'] / node[' , (each nodeIndex ifNil: [ '?' ]) printString , ']'.
					(acc at: key ifAbsent: [ acc at: key put: OrderedCollection new ]) add: each.
					acc ])
				associations sort: [ :a :b | a key < b key ] ];
		column: 'Configuration' text: [ :assoc | assoc key ] weight: 2;
		column: 'Count' text: [ :assoc | assoc value size printString ] weight: 1;
		send: [ :assoc | self species withAll: assoc value ]
]

{ #category : 'gt - views' }
Gt4SecurityAffectedGroup >> gtByEcosystemFor: aView [
	<gtView>
	^ aView columnedList
		title: 'By ecosystem';
		priority: 2;
		items: [
			(self items
				inject: Dictionary new
				into: [ :acc :each |
					| eco |
					eco := each ecosystem ifNil: [ '(unknown)' ].
					acc at: eco put: ((acc at: eco ifAbsent: [ 0 ]) + 1).
					acc ])
				associations
				sort: [ :a :b | a value > b value ] ];
		column: 'Ecosystem' text: [ :assoc | assoc key ] weight: 2;
		column: 'Count' text: [ :assoc | assoc value printString ] weight: 1;
		send: [ :assoc | self ecosystem: assoc key ]
]

{ #category : 'printing' }
Gt4SecurityAffectedGroup >> gtDisplayOn: aStream [
	aStream print: self size; nextPutAll: ' affected packages'
]

{ #category : 'filtering' }
Gt4SecurityAffectedGroup >> matching: aSubstring [
	"Substring match on package name or CPE product."
	| needle |
	needle := aSubstring asLowercase.
	^ self select: [ :each |
		(each packageName ifNil: [ '' ]) asLowercase includesSubstring: needle ]
]

{ #category : 'testing' }
Gt4SecurityAffectedGroup >> notEmpty [
	^ self isEmpty not
]

{ #category : 'printing' }
Gt4SecurityAffectedGroup >> printOn: aStream [
	super printOn: aStream.
	aStream nextPutAll: ' ('; print: self size; nextPutAll: ' affected packages)'
]
