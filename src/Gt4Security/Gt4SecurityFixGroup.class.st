Class {
	#name : 'Gt4SecurityFixGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'gt - views' }
Gt4SecurityFixGroup >> gtFixesFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Fixes';
		priority: 1;
		items: [ self items ];
		column: 'Repo' text: [ :fix | fix repoPath ifNil: [ '' ] ] weight: 2;
		column: 'Commit' text: [ :fix | fix shortHash ifNil: [ '' ] ] weight: 1;
		column: 'URL' text: [ :fix | fix url ifNil: [ '' ] ] weight: 4
]
