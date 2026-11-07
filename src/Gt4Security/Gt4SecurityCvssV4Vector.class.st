"
11-metric CVSS v4.0 vector — Attack Vector, Attack Complexity, Attack Requirements, Privileges Required, User Interaction, Vulnerable C/I/A, Subsequent C/I/A.

Table-driven scoring: maps metrics to a 6-digit MacroVector, looks up a base score in a 312-entry table, then interpolates based on per-metric severity distance. See the FIRST.org CVSS 4.0 specification for details.

Standard rounding to 1 decimal.
"
Class {
	#name : 'Gt4SecurityCvssV4Vector',
	#superclass : 'Gt4SecurityCvssVector',
	#instVars : [
		'attackVector',
		'attackComplexity',
		'attackRequirements',
		'privilegesRequired',
		'userInteraction',
		'vulnConfidentiality',
		'vulnIntegrity',
		'vulnAvailability',
		'subConfidentiality',
		'subIntegrity',
		'subAvailability'
	],
	#category : 'Gt4Security-CVSS',
	#package : 'Gt4Security',
	#tag : 'CVSS'
}

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> attackComplexity [
	^ attackComplexity
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> attackComplexity: v [
	attackComplexity := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> attackComplexityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Attack Complexity (AC)'; priority: 2; accessor: #attackComplexity;
		options: #('L' 'H');
		display: [ :v | v , ' — ' , ({ 'L'->'Low'. 'H'->'High' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> attackRequirements [
	^ attackRequirements
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> attackRequirements: v [
	attackRequirements := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> attackRequirementsDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Attack Requirements (AT)'; priority: 3; accessor: #attackRequirements;
		options: #('N' 'P');
		display: [ :v | v , ' — ' , ({ 'N'->'None'. 'P'->'Present' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> attackVector [
	^ attackVector
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> attackVector: v [
	attackVector := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> attackVectorDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Attack Vector (AV)'; priority: 1; accessor: #attackVector;
		options: #('N' 'A' 'L' 'P');
		display: [ :v | v , ' — ' , ({ 'N'->'Network'. 'A'->'Adjacent'. 'L'->'Local'. 'P'->'Physical' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'building' }
Gt4SecurityCvssV4Vector >> buildVectorString [
	^ 'CVSS:4.0/AV:' , attackVector ,
		'/AC:' , attackComplexity ,
		'/AT:' , attackRequirements ,
		'/PR:' , privilegesRequired ,
		'/UI:' , userInteraction ,
		'/VC:' , vulnConfidentiality ,
		'/VI:' , vulnIntegrity ,
		'/VA:' , vulnAvailability ,
		'/SC:' , subConfidentiality ,
		'/SI:' , subIntegrity ,
		'/SA:' , subAvailability
]

{ #category : 'parsing' }
Gt4SecurityCvssV4Vector >> parse [
	"Parse a V4.0 vector string into typed ivars + base-class metrics collection."
	super parse.
	attackVector := self metricValue: 'AV'.
	attackComplexity := self metricValue: 'AC'.
	attackRequirements := self metricValue: 'AT'.
	privilegesRequired := self metricValue: 'PR'.
	userInteraction := self metricValue: 'UI'.
	vulnConfidentiality := self metricValue: 'VC'.
	vulnIntegrity := self metricValue: 'VI'.
	vulnAvailability := self metricValue: 'VA'.
	subConfidentiality := self metricValue: 'SC'.
	subIntegrity := self metricValue: 'SI'.
	subAvailability := self metricValue: 'SA'
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> privilegesRequired [
	^ privilegesRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> privilegesRequired: v [
	privilegesRequired := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> privilegesRequiredDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Privileges Required (PR)'; priority: 4; accessor: #privilegesRequired;
		options: #('N' 'L' 'H');
		display: [ :v | v , ' — ' , ({ 'N'->'None'. 'L'->'Low'. 'H'->'High' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> subAvailability [
	^ subAvailability
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> subAvailability: v [
	subAvailability := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> subAvailabilityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Subsequent Availability (SA)'; priority: 11; accessor: #subAvailability;
		options: #('H' 'L' 'N');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'L'->'Low'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> subConfidentiality [
	^ subConfidentiality
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> subConfidentiality: v [
	subConfidentiality := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> subConfidentialityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Subsequent Confidentiality (SC)'; priority: 9; accessor: #subConfidentiality;
		options: #('H' 'L' 'N');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'L'->'Low'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> subIntegrity [
	^ subIntegrity
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> subIntegrity: v [
	subIntegrity := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> subIntegrityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Subsequent Integrity (SI)'; priority: 10; accessor: #subIntegrity;
		options: #('H' 'L' 'N');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'L'->'Low'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> userInteraction [
	^ userInteraction
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> userInteraction: v [
	userInteraction := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> userInteractionDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'User Interaction (UI)'; priority: 5; accessor: #userInteraction;
		options: #('N' 'P' 'A');
		display: [ :v | v , ' — ' , ({ 'N'->'None'. 'P'->'Passive'. 'A'->'Active' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> vulnAvailability [
	^ vulnAvailability
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> vulnAvailability: v [
	vulnAvailability := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> vulnAvailabilityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Vulnerable Availability (VA)'; priority: 8; accessor: #vulnAvailability;
		options: #('H' 'L' 'N');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'L'->'Low'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> vulnConfidentiality [
	^ vulnConfidentiality
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> vulnConfidentiality: v [
	vulnConfidentiality := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> vulnConfidentialityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Vulnerable Confidentiality (VC)'; priority: 6; accessor: #vulnConfidentiality;
		options: #('H' 'L' 'N');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'L'->'Low'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> vulnIntegrity [
	^ vulnIntegrity
]

{ #category : 'accessing' }
Gt4SecurityCvssV4Vector >> vulnIntegrity: v [
	vulnIntegrity := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV4Vector >> vulnIntegrityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Vulnerable Integrity (VI)'; priority: 7; accessor: #vulnIntegrity;
		options: #('H' 'L' 'N');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'L'->'Low'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]
