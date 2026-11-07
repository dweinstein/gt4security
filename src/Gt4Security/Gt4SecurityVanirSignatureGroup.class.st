Class {
	#name : 'Gt4SecurityVanirSignatureGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'gt - views' }
Gt4SecurityVanirSignatureGroup >> gtSignaturesFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Vanir signatures';
		priority: 1;
		items: [ self items ];
		column: 'Type' text: [ :sig | sig signatureType ifNil: [ '' ] ] weight: 1;
		column: 'File' text: [ :sig | sig targetFile ifNil: [ '' ] ] weight: 3;
		column: 'Function' text: [ :sig | sig targetFunction ifNil: [ '' ] ] weight: 2;
		column: 'ID' text: [ :sig | sig id ifNil: [ '' ] ] weight: 2
]
