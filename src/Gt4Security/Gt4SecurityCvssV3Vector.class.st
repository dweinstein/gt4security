"
CVSS v3.0 / v3.1 vector (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, C/I/A). Same formula for both versions — differ only by prefix.

Scope (S:U/S:C) changes both the impact formula and the PR weight. Uses Roundup (ceiling to 0.1). Severity labels: None (0.0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0).
"
Class {
	#name : 'Gt4SecurityCvssV3Vector',
	#superclass : 'Gt4SecurityCvssVector',
	#instVars : [
		'attackVector',
		'attackComplexity',
		'privilegesRequired',
		'userInteraction',
		'scope',
		'vConfidentiality',
		'vIntegrity',
		'vAvailability'
	],
	#category : 'Gt4Security-CVSS',
	#package : 'Gt4Security',
	#tag : 'CVSS'
}

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> attackComplexity [
	^ attackComplexity
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> attackComplexity: v [
	attackComplexity := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV3Vector >> attackComplexityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Attack Complexity (AC)'; priority: 2; accessor: #attackComplexity;
		options: #('L' 'H');
		display: [ :v | v , ' — ' , ({ 'L'->'Low'. 'H'->'High' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> attackVector [
	^ attackVector
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> attackVector: v [
	attackVector := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV3Vector >> attackVectorDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Attack Vector (AV)'; priority: 1; accessor: #attackVector;
		options: #('N' 'A' 'L' 'P');
		display: [ :v | v , ' — ' , ({ 'N'->'Network'. 'A'->'Adjacent'. 'L'->'Local'. 'P'->'Physical' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'building' }
Gt4SecurityCvssV3Vector >> buildVectorString [
	^ 'CVSS:3.1/AV:' , attackVector ,
		'/AC:' , attackComplexity ,
		'/PR:' , privilegesRequired ,
		'/UI:' , userInteraction ,
		'/S:' , scope ,
		'/C:' , vConfidentiality ,
		'/I:' , vIntegrity ,
		'/A:' , vAvailability
]

{ #category : 'parsing' }
Gt4SecurityCvssV3Vector >> parse [
	"Parse a V3.0/V3.1 vector string into typed ivars + base-class metrics collection."
	super parse.
	attackVector := self metricValue: 'AV'.
	attackComplexity := self metricValue: 'AC'.
	privilegesRequired := self metricValue: 'PR'.
	userInteraction := self metricValue: 'UI'.
	scope := self metricValue: 'S'.
	vConfidentiality := self metricValue: 'C'.
	vIntegrity := self metricValue: 'I'.
	vAvailability := self metricValue: 'A'
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> privilegesRequired [
	^ privilegesRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> privilegesRequired: v [
	privilegesRequired := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV3Vector >> privilegesRequiredDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Privileges Required (PR)'; priority: 3; accessor: #privilegesRequired;
		options: #('N' 'L' 'H');
		display: [ :v | v , ' — ' , ({ 'N'->'None'. 'L'->'Low'. 'H'->'High' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> scope [
	^ scope
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> scope: v [
	scope := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV3Vector >> scopeDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Scope (S)'; priority: 5; accessor: #scope;
		options: #('U' 'C');
		display: [ :v | v , ' — ' , ({ 'U'->'Unchanged'. 'C'->'Changed' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> userInteraction [
	^ userInteraction
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> userInteraction: v [
	userInteraction := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV3Vector >> userInteractionDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'User Interaction (UI)'; priority: 4; accessor: #userInteraction;
		options: #('N' 'R');
		display: [ :v | v , ' — ' , ({ 'N'->'None'. 'R'->'Required' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> vAvailability [
	^ vAvailability
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> vAvailability: v [
	vAvailability := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV3Vector >> vAvailabilityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Availability (A)'; priority: 8; accessor: #vAvailability;
		options: #('H' 'L' 'N');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'L'->'Low'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> vConfidentiality [
	^ vConfidentiality
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> vConfidentiality: v [
	vConfidentiality := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV3Vector >> vConfidentialityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Confidentiality (C)'; priority: 6; accessor: #vConfidentiality;
		options: #('H' 'L' 'N');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'L'->'Low'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> vIntegrity [
	^ vIntegrity
]

{ #category : 'accessing' }
Gt4SecurityCvssV3Vector >> vIntegrity: v [
	vIntegrity := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV3Vector >> vIntegrityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Integrity (I)'; priority: 7; accessor: #vIntegrity;
		options: #('H' 'L' 'N');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'L'->'Low'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]
