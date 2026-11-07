Class {
	#name : 'Gt4SecurityCpeConfigurationGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'gt - views' }
Gt4SecurityCpeConfigurationGroup >> gtConfigurationsFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Configurations';
		priority: 1;
		items: [ self items ];
		column: 'Operator' text: [ :c | c operator ifNil: [ '(default OR)' ] ] weight: 1;
		column: 'Nodes' text: [ :c | (c nodes ifNil: [ #() ]) size printString ] weight: 1;
		column: 'Total matches' text: [ :c | c allCpeMatches size printString ] weight: 1;
		column: 'Products' text: [ :c |
			| prods |
			prods := ((c allCpeMatches collect: [ :m | m cpeProduct ifNil: [ '?' ] ]) asSet asSortedCollection: [ :a :b | a < b ]) asArray.
			', ' join: prods ] weight: 4
]

{ #category : 'gt - views' }
Gt4SecurityCpeConfigurationGroup >> gtTreeFor: aView [
	<gtView>
	^ aView columnedTree
		title: 'Tree';
		priority: 2;
		items: [ self items ];
		children: [ :each |
			(each isKindOf: Gt4SecurityCpeConfiguration) ifTrue: [ each nodes ifNil: [ #() ] ] ifFalse: [
				(each isKindOf: Gt4SecurityCpeNode) ifTrue: [ (each cpeMatches ifNil: [ #() ]) , (each children ifNil: [ #() ]) ] ifFalse: [ #() ] ] ];
		column: 'Kind' text: [ :each |
			(each isKindOf: Gt4SecurityCpeConfiguration) ifTrue: [ 'Configuration' ] ifFalse: [
				(each isKindOf: Gt4SecurityCpeNode) ifTrue: [ 'Node' ] ifFalse: [ 'Match' ] ] ] weight: 1;
		column: 'Operator / Criteria' text: [ :each |
			(each isKindOf: Gt4SecurityCpeConfiguration) ifTrue: [ each operator ifNil: [ '(default OR)' ] ] ifFalse: [
				(each isKindOf: Gt4SecurityCpeNode) ifTrue: [ each operator ifNil: [ 'OR' ] ] ifFalse: [ each criteria ifNil: [ '' ] ] ] ] weight: 3;
		column: 'Range' text: [ :each |
			(each isKindOf: Gt4SecurityCpeMatch) ifTrue: [ each versionRangeSummary ] ifFalse: [ '' ] ] weight: 2
]
