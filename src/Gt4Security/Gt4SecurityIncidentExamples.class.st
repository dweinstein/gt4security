"
Offline examples building the 21-entry catalog of known mobile security incidents (Pushwoosh, SpinOk, EngageLab, XZ Utils, CocoaPods Trunk, etc.) that are not tracked in any CVE database. The `allIncidents` factory method is the canonical source.
"
Class {
	#name : 'Gt4SecurityIncidentExamples',
	#superclass : 'Object',
	#category : 'Gt4Security-Examples',
	#package : 'Gt4Security',
	#tag : 'Examples'
}

{ #category : 'catalog' }
Gt4SecurityIncidentExamples >> allIncidents [
	"The full catalog of known mobile security incidents not tracked by CVE databases."
	^ OrderedCollection new
		add: (self incident: 'Pushwoosh' vendor: 'Pushwoosh Inc.' year: 2022 platforms: #('iOS' 'Android') category: 'espionage' description: 'Russian company masquerading as US-based; push SDK embedded in CDC, US Army apps. Reuters expose.' source: 'https://www.reuters.com/technology/exclusive-russian-software-disguised-american-finds-its-way-into-us-army-cdc-2022-11-14/' installs: 'unknown' status: 'removed');
		add: (self incident: 'Igexin' vendor: 'Igexin' year: 2017 platforms: #('Android') category: 'spyware' description: 'Chinese ad SDK downloaded spyware payloads post-install in 500+ Play Store apps. Lookout discovery.' source: 'https://blog.lookout.com/igexin-malicious-sdk' installs: '100M+' status: 'removed');
		add: (self incident: 'Mintegral / SourMint' vendor: 'Mintegral' year: 2020 platforms: #('iOS') category: 'click fraud' description: 'Chinese ad SDK intercepted ad clicks and URL scheme traffic. 1,200+ apps, 300M+ monthly installs. Snyk discovery.' source: 'https://snyk.io/blog/sourmint-malicious-code-ad-sdk-ios-apps/' installs: '300M+ monthly' status: 'active');
		add: (self incident: 'X-Mode / Outlogic' vendor: 'X-Mode Social' year: 2020 platforms: #('iOS' 'Android') category: 'data harvesting' description: 'Location data broker SDK in prayer and weather apps; sold GPS data to military contractors. Banned by Apple and Google.' source: 'https://www.vice.com/en/article/jgqm5x/us-military-location-data-xmode-locate-x' installs: 'unknown' status: 'removed');
		add: (self incident: 'OneAudience' vendor: 'OneAudience' year: 2019 platforms: #('iOS' 'Android') category: 'data harvesting' description: 'SDK harvested Facebook/Twitter session tokens and PII from apps using social login. Facebook sued.' source: 'https://about.fb.com/news/2019/11/two-more-sdks-that-shared-data-with-facebook/' installs: 'unknown' status: 'removed');
		add: (self incident: 'event-stream' vendor: 'open source' year: 2018 platforms: #('Android') category: 'supply chain' description: 'Maintainer handed off npm package to attacker who injected Bitcoin wallet stealer targeting Copay mobile wallet.' source: 'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident' installs: 'unknown' status: 'patched');
		add: (self incident: 'ua-parser-js' vendor: 'open source' year: 2021 platforms: #('Android') category: 'supply chain' description: 'Hijacked npm account published cryptominer/credential stealer in popular UA parsing lib. 7M weekly downloads.' source: 'https://github.com/nicedayr/ua-parser-js-compromised' installs: '7M weekly' status: 'patched');
		add: (self incident: 'node-ipc' vendor: 'open source' year: 2022 platforms: #('Android') category: 'sabotage' description: 'Maintainer added destructive code targeting Russian/Belarusian IPs (protestware). Wiped files on affected systems.' source: 'https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/' installs: 'unknown' status: 'patched');
		add: (self incident: 'colors / faker' vendor: 'open source' year: 2022 platforms: #('Android') category: 'sabotage' description: 'Maintainer self-sabotaged: injected infinite loops (colors) and destructive code (faker) as protestware.' source: 'https://snyk.io/blog/open-source-npm-packages-colors-702faker/' installs: 'unknown' status: 'patched');
		add: (self incident: 'axios (MAL-2026-2307)' vendor: 'open source' year: 2026 platforms: #('Android') category: 'malicious' description: 'Malicious code detected in axios npm package. Live in OSV as MAL-2026-2307.' source: 'https://osv.dev/vulnerability/MAL-2026-2307' installs: 'unknown' status: 'active');
		add: (self incident: 'Tekya / Haken' vendor: 'unknown' year: 2020 platforms: #('Android') category: 'clicker malware' description: 'Malware families hidden in 56 Play Store apps (camera/file utilities). Auto-clicked ads in background. Check Point discovery.' source: 'https://research.checkpoint.com/2020/google-play-store-tekya/' installs: '1M+' status: 'removed');
		add: (self incident: 'Baidu SDK' vendor: 'Baidu' year: 2015 platforms: #('Android') category: 'data exfil' description: 'Multiple incidents of Baidu SDKs (Maps, Search, Moplus) leaking IMEI, location, search queries. Trend Micro reports.' source: 'https://blog.trendmicro.com/trendlabs-security-intelligence/setting-the-record-straight-on-moplus-sdk-and-the-wormhole-vulnerability/' installs: '100M+' status: 'patched');
		add: (self incident: 'AirPush' vendor: 'AirPush' year: 2012 platforms: #('Android') category: 'adware' description: 'Aggressive ad SDK pushing notifications and injecting bookmarks. Embedded in thousands of free apps.' source: nil installs: 'unknown' status: 'removed');
		add: (self incident: 'SpinOk' vendor: 'unknown' year: 2023 platforms: #('Android') category: 'spyware' description: 'Marketing SDK with spyware — exfiltrated files, clipboard data. 100+ Play Store apps, 421M+ installs. Dr.Web discovery.' source: 'https://news.drweb.com/show/?i=14705' installs: '421M+' status: 'removed');
		add: (self incident: 'Goldoson' vendor: 'unknown' year: 2023 platforms: #('Android') category: 'click fraud' description: 'Third-party library performing ad click fraud and harvesting WiFi/Bluetooth/GPS data. 60+ apps, 100M downloads. McAfee discovery.' source: 'https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-apps-on-google-play/' installs: '100M+' status: 'removed');
		add: (self incident: 'Measurement Systems (Coulus Coelib)' vendor: 'Measurement Systems' year: 2022 platforms: #('Android') category: 'data harvesting' description: 'SDK harvesting phone numbers, email, GPS, clipboard, scanning home networks. Linked to US intelligence contractors. AppCensus discovery.' source: 'https://www.wsj.com/articles/apps-with-hidden-data-harvesting-software-are-banned-by-google-11649261181' installs: '60M+' status: 'removed');
		add: (self incident: 'CocoaPods Trunk' vendor: 'CocoaPods' year: 2024 platforms: #('iOS') category: 'supply chain' description: '1,870 orphaned pods claimable by anyone; RCE on Trunk server; zero-click account takeover. Exposed 3M+ iOS/macOS apps for ~10 years. CVE-2024-38366/38367/38368.' source: 'https://blog.evasec.io/eva-discovered-supply-chain-vulnerabities-in-cocoapods' installs: '3M+ apps' status: 'patched');
		add: (self incident: 'XZ Utils backdoor' vendor: 'open source' year: 2024 platforms: #('Android') category: 'supply chain' description: 'Maintainer spent 2 years gaining trust, then inserted SSH backdoor. CVE-2024-3094. Caught days before reaching stable distros.' source: 'https://www.openwall.com/lists/oss-security/2024/03/29/4' installs: 'near-universal' status: 'patched');
		add: (self incident: 'Polyfill.io CDN' vendor: 'Funnull (acquirer)' year: 2024 platforms: #('iOS' 'Android') category: 'supply chain' description: 'Domain acquired by new owner who injected malicious redirects targeting mobile users via the JavaScript polyfill CDN. 100K+ sites affected.' source: 'https://sansec.io/research/polyfill-supply-chain-attack' installs: '100K+ sites' status: 'patched');
		add: (self incident: 'BatMobi' vendor: 'BatMobi' year: 2019 platforms: #('Android') category: 'adware' description: 'Ad SDK with dormant code activation — turned clean apps into adware overnight. Pre-installed on some Xiaomi devices.' source: nil installs: 'unknown' status: 'removed');
		add: (self incident: 'EngageLab SDK' vendor: 'EngageLab' year: 2025 platforms: #('Android') category: 'intent redirection' description: 'Intent redirection vulnerability in push notification SDK. Exposed crypto wallet private keys, credentials, transaction data. 50M+ users, 30M+ wallet installs. Fixed in v5.2.1. Microsoft MSRC discovery.' source: 'https://www.microsoft.com/en-us/security/blog/2026/04/09/intent-redirection-vulnerability-third-party-sdk-android/' installs: '50M+' status: 'patched');
		yourself
]

{ #category : 'examples' }
Gt4SecurityIncidentExamples >> catalog [
	"The full incident catalog as an inspectable group. All offline — no network, no noTest."
	<gtExample>
	<return: #Gt4SecurityIncidentGroup>
	| group |
	group := Gt4SecurityIncidentGroup withAll: self allIncidents.
	self assert: group size equals: 21.
	self assert: (group android) notEmpty.
	self assert: (group ios) notEmpty.
	self assert: (group category: 'supply chain') notEmpty.
	self assert: (group category: 'spyware') notEmpty.
	self assert: (group matching: 'engagelab') notEmpty.
	^ group
]

{ #category : 'examples' }
Gt4SecurityIncidentExamples >> filterChain [
	"Demonstrate filter chaining: Android supply chain incidents."
	<gtExample>
	<return: #Gt4SecurityIncidentGroup>
	| group chain |
	group := self catalog.
	chain := group android category: 'supply chain'.
	self assert: chain class equals: Gt4SecurityIncidentGroup.
	self assert: chain notEmpty.
	self assert: (chain allSatisfy: [ :i | i affectsAndroid ]).
	self assert: (chain allSatisfy: [ :i | i category = 'supply chain' ]).
	^ chain
]

{ #category : 'private' }
Gt4SecurityIncidentExamples >> incident: aName vendor: aVendor year: aYear platforms: aPlatforms category: aCategory description: aDesc source: aUrl installs: anInstallsString status: aStatus [
	^ Gt4SecurityIncident new
		name: aName;
		vendor: aVendor;
		year: aYear;
		platforms: aPlatforms;
		category: aCategory;
		description: aDesc;
		sourceUrl: aUrl;
		affectedInstalls: anInstallsString;
		status: aStatus;
		yourself
]

{ #category : 'examples' }
Gt4SecurityIncidentExamples >> singleIncident [
	"A single incident for view testing."
	<gtExample>
	<return: #Gt4SecurityIncident>
	| incident |
	incident := self allIncidents detect: [ :i | i name = 'EngageLab SDK' ].
	self assert: incident year equals: 2025.
	self assert: incident affectsAndroid.
	self assert: incident affectsIos not.
	self assert: incident status equals: 'patched'.
	^ incident
]
