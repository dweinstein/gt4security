"
CVSS v2 vector (Access Vector, Access Complexity, Authentication, C/I/A). Formula-based scoring with standard rounding. Severity labels: Low (0-3.9), Medium (4.0-6.9), High (7.0-10.0).

Instantiate via {{gtMethod:Gt4SecurityCvssVector class>>#fromString:}} with a prefix-less vector like `AV:N/AC:L/Au:N/C:N/I:N/A:C`.
"
Class {
	#name : 'Gt4SecurityCvssV2Vector',
	#superclass : 'Gt4SecurityCvssVector',
	#instVars : [
		'accessVector',
		'accessComplexity',
		'authentication',
		'vConfidentiality',
		'vIntegrity',
		'vAvailability'
	],
	#category : 'Gt4Security-CVSS',
	#package : 'Gt4Security',
	#tag : 'CVSS'
}

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> accessComplexity [
	^ accessComplexity
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> accessComplexity: v [
	accessComplexity := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV2Vector >> accessComplexityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Access Complexity (AC)'; priority: 2; accessor: #accessComplexity;
		options: #('H' 'M' 'L');
		display: [ :v | v , ' — ' , ({ 'H'->'High'. 'M'->'Medium'. 'L'->'Low' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> accessVector [
	^ accessVector
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> accessVector: v [
	accessVector := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV2Vector >> accessVectorDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Access Vector (AV)'; priority: 1; accessor: #accessVector;
		options: #('L' 'A' 'N');
		display: [ :v | v , ' — ' , ({ 'L'->'Local'. 'A'->'Adjacent Network'. 'N'->'Network' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> authentication [
	^ authentication
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> authentication: v [
	authentication := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV2Vector >> authenticationDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Authentication (Au)'; priority: 3; accessor: #authentication;
		options: #('M' 'S' 'N');
		display: [ :v | v , ' — ' , ({ 'M'->'Multiple'. 'S'->'Single'. 'N'->'None' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'building' }
Gt4SecurityCvssV2Vector >> buildVectorString [
	^ 'AV:' , accessVector ,
		'/AC:' , accessComplexity ,
		'/Au:' , authentication ,
		'/C:' , vConfidentiality ,
		'/I:' , vIntegrity ,
		'/A:' , vAvailability
]

{ #category : 'parsing' }
Gt4SecurityCvssV2Vector >> parse [
	"Parse a V2 vector string into typed ivars + base-class metrics collection."
	super parse.
	accessVector := self metricValue: 'AV'.
	accessComplexity := self metricValue: 'AC'.
	authentication := self metricValue: 'Au'.
	vConfidentiality := self metricValue: 'C'.
	vIntegrity := self metricValue: 'I'.
	vAvailability := self metricValue: 'A'
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> vAvailability [
	^ vAvailability
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> vAvailability: v [
	vAvailability := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV2Vector >> vAvailabilityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Availability (A)'; priority: 6; accessor: #vAvailability;
		options: #('N' 'P' 'C');
		display: [ :v | v , ' — ' , ({ 'N'->'None'. 'P'->'Partial'. 'C'->'Complete' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> vConfidentiality [
	^ vConfidentiality
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> vConfidentiality: v [
	vConfidentiality := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV2Vector >> vConfidentialityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Confidentiality (C)'; priority: 4; accessor: #vConfidentiality;
		options: #('N' 'P' 'C');
		display: [ :v | v , ' — ' , ({ 'N'->'None'. 'P'->'Partial'. 'C'->'Complete' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> vIntegrity [
	^ vIntegrity
]

{ #category : 'accessing' }
Gt4SecurityCvssV2Vector >> vIntegrity: v [
	vIntegrity := v
]

{ #category : 'magritte' }
Gt4SecurityCvssV2Vector >> vIntegrityDescription [
	<magritteDescription>
	^ MASingleOptionDescription new label: 'Integrity (I)'; priority: 5; accessor: #vIntegrity;
		options: #('N' 'P' 'C');
		display: [ :v | v , ' — ' , ({ 'N'->'None'. 'P'->'Partial'. 'C'->'Complete' } asDictionary at: v ifAbsent: [ v ]) ];
		labelAptitude: [ BrGlamorousLabelAptitude new glamorousFormLabelStyle ]; beRequired
]
