Class {
	#name : 'BaselineOfGt4Security',
	#superclass : 'BaselineOf',
	#category : 'BaselineOfGt4Security',
	#package : 'BaselineOfGt4Security'
}

{ #category : 'loading' }
BaselineOfGt4Security class >> loadLepiter [
	"Register this repository's lepiter/ directory with the default Lepiter database. The repository is found by the baseline package it contains, so it works whatever the clone's directory is named."

	IceRepository registry
		detect: [ :aRepository | aRepository includesPackageNamed: self name ]
		ifFound: [ :aRepository | 
			| defaultDatabase currentProperties |
			defaultDatabase := LeDatabasesRegistry defaultLogicalDatabase.
			currentProperties := defaultDatabase properties.
			currentProperties
				addRegisteredDirectory: aRepository repositoryDirectory / 'lepiter'.
			defaultDatabase reload ]
		ifNone: [ self inform: 'Repository not found.' ]
]

{ #category : 'baselines' }
BaselineOfGt4Security >> baseline: spec [
	<baseline>
	^ spec for: #common do: [ spec package: 'Gt4Security' ]
]
