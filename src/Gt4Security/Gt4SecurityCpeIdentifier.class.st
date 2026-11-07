Class {
	#name : 'Gt4SecurityCpeIdentifier',
	#superclass : 'Object',
	#instVars : [
		'vendor',
		'product',
		'version'
	],
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityCpeIdentifier class >> vendor: aVendorString product: aProductString version: aVersionString [
	^ self new
		vendor: aVendorString;
		product: aProductString;
		version: aVersionString;
		yourself
]

{ #category : 'comparing' }
Gt4SecurityCpeIdentifier >> = anObject [
	self class = anObject class ifFalse: [ ^ false ].
	^ vendor = anObject vendor
		and: [ product = anObject product
		and: [ version = anObject version ] ]
]

{ #category : 'accessing' }
Gt4SecurityCpeIdentifier >> cpePrefix [
	"NVD virtualMatchString form: cpe:2.3:a:<vendor>:<product>:<version>"
	^ String streamContents: [ :s |
		s
			nextPutAll: 'cpe:2.3:a:';
			nextPutAll: (vendor ifNil: [ '*' ]);
			nextPut: $:;
			nextPutAll: (product ifNil: [ '*' ]);
			nextPut: $:;
			nextPutAll: (version ifNil: [ '*' ]) ]
]

{ #category : 'gt - views' }
Gt4SecurityCpeIdentifier >> gtDetailsFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Details';
		priority: 1;
		items: [ {'Vendor' -> vendor.
				'Product' -> product.
				'Version' -> version.
				'CPE' -> self cpePrefix} ];
		column: 'Property' text: #key;
		column: 'Value' text: [ :each | each value ifNil: [ '-' ] ];
		send: #value
]

{ #category : 'printing' }
Gt4SecurityCpeIdentifier >> gtDisplayOn: aStream [
	"Compact in-list display: vendor:product:version triple."
	aStream
		nextPutAll: (vendor ifNil: [ '*' ]);
		nextPut: $:;
		nextPutAll: (product ifNil: [ '*' ]);
		nextPut: $:;
		nextPutAll: (version ifNil: [ '*' ])
]

{ #category : 'comparing' }
Gt4SecurityCpeIdentifier >> hash [
	^ vendor hash bitXor: (product hash bitXor: version hash)
]

{ #category : 'printing' }
Gt4SecurityCpeIdentifier >> printOn: aStream [
	aStream nextPutAll: self cpePrefix
]

{ #category : 'accessing' }
Gt4SecurityCpeIdentifier >> product [
	^ product
]

{ #category : 'accessing' }
Gt4SecurityCpeIdentifier >> product: aString [
	product := aString
]

{ #category : 'accessing' }
Gt4SecurityCpeIdentifier >> vendor [
	^ vendor
]

{ #category : 'accessing' }
Gt4SecurityCpeIdentifier >> vendor: aString [
	vendor := aString
]

{ #category : 'accessing' }
Gt4SecurityCpeIdentifier >> version [
	^ version
]

{ #category : 'accessing' }
Gt4SecurityCpeIdentifier >> version: aString [
	version := aString
]
