"
Package umbrella / version marker for the Gt4Security project — a Glamorous Toolkit toolkit for tracking CVEs, malicious-package reports, and mobile-security incidents relevant to iOS and Android apps and devices.

Pull CVE and advisory data from free, fast, updated sources (OSV.dev, NVD API v2, OSSF Malicious Packages) with no scraping. Results land in moldable domain objects you can filter, drill into, and navigate from inside the live image.

See {{gtClass:Gt4SecurityQuery}} for the main cross-source query entry point, {{gtClass:Gt4SecurityOsvClient}} / {{gtClass:Gt4SecurityNvdClient}} for direct API access, and {{gtClass:Gt4SecurityCvssVector}} for CVSS scoring.
"
Class {
	#name : 'Gt4Security',
	#superclass : 'Object',
	#category : 'Gt4Security-Core',
	#package : 'Gt4Security',
	#tag : 'Core'
}

{ #category : 'accessing' }
Gt4Security class >> version [
	"Package umbrella / version marker for Gt4Security."
	^ '0.1.0'
]
