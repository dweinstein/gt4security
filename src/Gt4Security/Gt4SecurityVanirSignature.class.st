Class {
	#name : 'Gt4SecurityVanirSignature',
	#superclass : 'Object',
	#instVars : [
		'id',
		'signatureType',
		'signatureVersion',
		'source',
		'deprecated',
		'target',
		'digest',
		'rawDict'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityVanirSignature class >> fromDictionary: aDictionary [
	^ self new
		id: (aDictionary at: 'id' ifAbsent: [ nil ]);
		signatureType: (aDictionary at: 'signature_type' ifAbsent: [ nil ]);
		signatureVersion: (aDictionary at: 'signature_version' ifAbsent: [ nil ]);
		source: (aDictionary at: 'source' ifAbsent: [ nil ]);
		deprecated: (aDictionary at: 'deprecated' ifAbsent: [ nil ]);
		target: (aDictionary at: 'target' ifAbsent: [ Dictionary new ]);
		digest: (aDictionary at: 'digest' ifAbsent: [ Dictionary new ]);
		rawDict: aDictionary;
		yourself
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> deprecated [
	^ deprecated
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> deprecated: aBoolean [
	deprecated := aBoolean
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> digest [
	^ digest
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> digest: aDict [
	digest := aDict
]

{ #category : 'gt - views' }
Gt4SecurityVanirSignature >> gtDigestFor: aView [
	<gtView>
	(digest isNil or: [ digest isEmpty ]) ifTrue: [ ^ aView empty ].
	^ aView columnedList
		title: 'Digest';
		priority: 2;
		items: [ digest associations ];
		column: 'Key' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value printString ] weight: 3
]

{ #category : 'gt - views' }
Gt4SecurityVanirSignature >> gtSummaryFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Summary';
		priority: 1;
		items: [ {
			'ID' -> (id ifNil: [ '(none)' ]).
			'Signature type' -> (signatureType ifNil: [ '(unknown)' ]).
			'Signature version' -> (signatureVersion ifNil: [ '(unknown)' ]).
			'Target file' -> (self targetFile ifNil: [ '(none)' ]).
			'Target function' -> (self targetFunction ifNil: [ '(none)' ]).
			'Deprecated?' -> (deprecated = true ifTrue: [ 'YES' ] ifFalse: [ 'no' ]).
			'Source' -> (source ifNil: [ '(none)' ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> id [
	^ id
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> id: aString [
	id := aString
]

{ #category : 'printing' }
Gt4SecurityVanirSignature >> printOn: aStream [
	aStream nextPutAll: 'VanirSig('.
	aStream nextPutAll: (signatureType ifNil: [ '?' ]).
	aStream nextPutAll: ' '.
	aStream nextPutAll: (self targetFile ifNil: [ id ifNil: [ '?' ] ]).
	aStream nextPut: $)
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> rawDict [
	^ rawDict
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> rawDict: aDict [
	rawDict := aDict
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> signatureType [
	^ signatureType
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> signatureType: aString [
	signatureType := aString
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> signatureVersion [
	^ signatureVersion
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> signatureVersion: aString [
	signatureVersion := aString
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> source [
	^ source
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> source: aString [
	source := aString
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> target [
	^ target
]

{ #category : 'accessing' }
Gt4SecurityVanirSignature >> target: aDict [
	target := aDict
]

{ #category : 'querying' }
Gt4SecurityVanirSignature >> targetFile [
	^ target ifNil: [ nil ] ifNotNil: [ target at: 'file' ifAbsent: [ nil ] ]
]

{ #category : 'querying' }
Gt4SecurityVanirSignature >> targetFunction [
	^ target ifNil: [ nil ] ifNotNil: [ target at: 'function' ifAbsent: [ nil ] ]
]
