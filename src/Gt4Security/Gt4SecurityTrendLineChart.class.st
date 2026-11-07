"
Line chart with visible point markers at each data point, in the style of osv.dev's malicious-package trend chart. Used by {{gtClass:Gt4SecurityVulnerabilityGroup}}'s Trend chart view.
"
Class {
	#name : 'Gt4SecurityTrendLineChart',
	#superclass : 'GtPlotterLineChart',
	#category : 'Gt4Security-Domain',
	#package : 'Gt4Security',
	#tag : 'Domain'
}

{ #category : 'instance creation' }
Gt4SecurityTrendLineChart >> newContentLineElementFor: aGroup [
	"Add a visible dot at each data point on top of the plain polyline."
	| aLine dots |
	aLine := super newContentLineElementFor: aGroup.
	dots := (self newContentLineVerticesFor: aGroup) collect: [ :aPoint |
		BlElement new
			size: 7 @ 7;
			geometry: BlCircleGeometry new;
			background: aGroup color;
			constraintsDo: [ :c |
				c ignoreByLayout.
				c ignored horizontal alignCenterAt: aPoint x.
				c ignored vertical alignCenterAt: aPoint y ] ].
	^ BlElement new
		layout: BlFrameLayout new;
		constraintsDo: [ :c | c horizontal matchParent. c vertical matchParent ];
		addChild: aLine;
		addChildren: dots;
		yourself
]
