Class {
	#name : 'Gt4SecurityStrategySpanGroup',
	#superclass : 'Object',
	#traits : 'TGtGroupWithItems',
	#classTraits : 'TGtGroupWithItems classTrait',
	#category : 'Gt4Security',
	#package : 'Gt4Security'
}

{ #category : 'instance creation' }
Gt4SecurityStrategySpanGroup class >> fromHistoryEntries: entries [
	"Walk an ordered sequence of history entries (kind: #strategyStart, #strategyEnd, #http)
	and return a group of one Gt4SecurityStrategySpan per top-level strategy span. Nested
	spans are absorbed into the outer span's calls/bytes totals — this is what lets us
	report, e.g., 'HydratedWindow ran for 3.2 s, made 800 HTTP calls, transferred 8 MB'
	without double-counting the inner CachedCsvWindow span it delegates to."
	| group depth currentOuter |
	group := self new.
	depth := 0.
	currentOuter := nil.
	entries do: [ :entry |
		| kind |
		kind := entry at: 'kind' ifAbsent: [ #http ].
		kind = #strategyStart ifTrue: [
			depth = 0 ifTrue: [ currentOuter := Gt4SecurityStrategySpan fromStartEntry: entry ].
			depth := depth + 1 ].
		kind = #strategyEnd ifTrue: [
			depth := depth - 1.
			(depth = 0 and: [ currentOuter notNil ]) ifTrue: [
				currentOuter closeWithEndEntry: entry.
				group addItem: currentOuter.
				currentOuter := nil ] ].
		(kind = #http and: [ currentOuter notNil ]) ifTrue: [
			currentOuter recordHttpEntry: entry ] ].
	^ group
]

{ #category : 'printing' }
Gt4SecurityStrategySpanGroup >> gtDisplayOn: aStream [
	aStream
		print: self items size;
		nextPutAll: ' strategy span';
		nextPutAll: (self items size = 1 ifTrue: [ '' ] ifFalse: [ 's' ])
]

{ #category : 'gt-views' }
Gt4SecurityStrategySpanGroup >> gtNarrativeFor: aView [
	"Prose summary of the run — sentences over the same data the Strategies columned list
	exposes as rows. Sits alongside Strategies + Totals so the user can pick the form they
	prefer; complements rather than replaces."
	<gtView>
	^ aView textEditor
		title: 'Narrative';
		priority: 8;
		text: [ self narrativeSummary ];
		actionUpdateButton
]

{ #category : 'gt-views' }
Gt4SecurityStrategySpanGroup >> gtSpansFor: aView [
	"Per-strategy trace — one row per top-level span. Same columns as the parent
	Gt4SecurityQueryResult Strategies tab; this view *is* the parent tab's content (the
	parent forwards into us)."
	<gtView>
	^ aView columnedList
		title: 'Strategies';
		priority: 5;
		items: [ self items ];
		column: 'Strategy' text: [ :span | span description ] weight: 2;
		column: 'Ecosystems' text: [ :span | span ecosystemsDisplay ] weight: 1.2;
		column: 'Est. cost' text: [ :span | span cost asString ] weight: 0.8;
		column: 'HTTP' text: [ :span | span calls asString ] weight: 0.5;
		column: 'Bytes' text: [ :span | span bytesDisplay ] weight: 1;
		column: 'Duration' text: [ :span | span durationDisplay ] weight: 0.7
]

{ #category : 'gt-views' }
Gt4SecurityStrategySpanGroup >> gtTotalsFor: aView [
	"Roll-up across all spans — answers 'how much did the whole run cost?' at a glance."
	<gtView>
	^ aView columnedList
		title: 'Totals';
		priority: 10;
		items: [ self totalsRows ];
		column: 'Field' text: [ :row | row first ] weight: 0.4;
		column: 'Value' text: [ :row | row third ] weight: 1;
		send: [ :row | row second ]
]

{ #category : 'narrative' }
Gt4SecurityStrategySpanGroup >> narrativeJoinEcosystems: aCollection [
	"Comma-join with 'and' before the last item — Oxford-comma style for n >= 3.
	'<none>' for empty, the single name for n=1."
	aCollection isEmpty ifTrue: [ ^ '<no ecosystems>' ].
	aCollection size = 1 ifTrue: [ ^ aCollection first asString ].
	aCollection size = 2 ifTrue: [
		^ aCollection first asString , ' and ' , aCollection second asString ].
	^ String streamContents: [ :s |
		aCollection allButLast doWithIndex: [ :each :i |
			i > 1 ifTrue: [ s nextPutAll: ', ' ].
			s nextPutAll: each asString ].
		s nextPutAll: ', and '; nextPutAll: aCollection last asString ]
]

{ #category : 'narrative' }
Gt4SecurityStrategySpanGroup >> narrativeSummary [
	"Human-readable prose summary of what the strategies in this group did. Folds spans
	by strategy class so multi-ecosystem strategies (e.g. 'full ecosystem zip download +
	parse' running once per ecosystem) collapse into a single sentence. Returns a String
	with double-newline-separated paragraphs."
	self items isEmpty ifTrue: [ ^ 'No strategies ran for this query.' ].
	^ String streamContents: [ :stream |
		self narrativeWriteOpeningOn: stream.
		self narrativeWriteStrategyParagraphsOn: stream ]
]

{ #category : 'narrative' }
Gt4SecurityStrategySpanGroup >> narrativeWriteMultiSpan: spans ecosystems: ecosystems description: description totalCalls: totalCalls totalBytes: totalBytes totalMs: totalMs on: stream [
	"Sentence form for a strategy that ran multiple times — typically once per ecosystem.
	Includes a 'longest was X at Y' callout when there are 3+ spans."
	| longest |
	longest := spans inject: spans first into: [ :max :each |
		each durationMs > max durationMs ifTrue: [ each ] ifFalse: [ max ] ].
	stream
		nextPutAll: 'The ''';
		nextPutAll: description;
		nextPutAll: ''' strategy served '.
	ecosystems size > 1
		ifTrue: [
			stream print: ecosystems size; nextPutAll: ' ecosystems ('.
			stream nextPutAll: (', ' join: (ecosystems collect: [ :e | e asString ])).
			stream nextPutAll: ')' ]
		ifFalse: [ stream nextPutAll: (self narrativeJoinEcosystems: ecosystems) ].
	stream
		nextPutAll: ' over ';
		print: spans size;
		nextPutAll: (spans size = 1 ifTrue: [ ' transfer' ] ifFalse: [ ' transfers' ]);
		nextPutAll: ' totaling ';
		nextPutAll: (Gt4SecurityFormat humanBytes: totalBytes);
		nextPutAll: ' in ';
		nextPutAll: (Gt4SecurityFormat humanMs: totalMs);
		nextPutAll: ' combined'.
	spans size >= 3 ifTrue: [
		stream
			nextPutAll: '; the longest was ';
			nextPutAll: (self narrativeJoinEcosystems: longest ecosystems);
			nextPutAll: ' at ';
			nextPutAll: longest durationDisplay ].
	stream nextPutAll: '.'
]

{ #category : 'narrative' }
Gt4SecurityStrategySpanGroup >> narrativeWriteOpeningOn: stream [
	"Top-line totals — how much work the run did, in aggregate."
	stream
		nextPutAll: 'This run made ';
		print: self totalCalls;
		nextPutAll: (self totalCalls = 1 ifTrue: [ ' HTTP call' ] ifFalse: [ ' HTTP calls' ]);
		nextPutAll: ' and transferred ';
		nextPutAll: (Gt4SecurityFormat humanBytes: self totalBytes);
		nextPutAll: ' across ';
		print: self items size;
		nextPutAll: (self items size = 1 ifTrue: [ ' strategy invocation' ] ifFalse: [ ' strategy invocations' ]);
		nextPutAll: ' ('; nextPutAll: (Gt4SecurityFormat humanMs: self totalDurationMs);
		nextPutAll: ' wall clock).'
]

{ #category : 'narrative' }
Gt4SecurityStrategySpanGroup >> narrativeWriteSingleSpan: aSpan ecosystems: ecosystems description: description on: stream [
	"Sentence form for a strategy that ran exactly once."
	stream
		nextPutAll: 'The ''';
		nextPutAll: description;
		nextPutAll: ''' strategy served ';
		nextPutAll: (self narrativeJoinEcosystems: ecosystems);
		nextPutAll: ' ('.
	stream print: aSpan calls.
	stream nextPutAll: (aSpan calls = 1 ifTrue: [ ' call, ' ] ifFalse: [ ' calls, ' ]).
	stream nextPutAll: aSpan bytesDisplay.
	(aSpan bytes = 0 and: [ aSpan calls > 0 ])
		ifTrue: [ stream nextPutAll: ' — likely a cache hit' ].
	stream
		nextPutAll: ') in ';
		nextPutAll: aSpan durationDisplay;
		nextPutAll: '.'
]

{ #category : 'narrative' }
Gt4SecurityStrategySpanGroup >> narrativeWriteStrategyParagraphFor: spans on: stream [
	"Render one strategy's paragraph. Two cases: a single span (short form) versus multiple
	spans (aggregated, with longest-span callout). 'spans' is non-empty."
	| sample ecosystems totalCalls totalBytes totalMs description |
	sample := spans first.
	description := sample description ifEmpty: [ sample strategyName asString ].
	ecosystems := (spans flatCollect: [ :each | each ecosystems ]) asOrderedCollection.
	totalCalls := spans inject: 0 into: [ :sum :each | sum + each calls ].
	totalBytes := spans inject: 0 into: [ :sum :each | sum + each bytes ].
	totalMs := spans inject: 0 into: [ :sum :each | sum + each durationMs ].
	spans size = 1
		ifTrue: [
			self narrativeWriteSingleSpan: sample
				ecosystems: ecosystems
				description: description
				on: stream ]
		ifFalse: [
			self narrativeWriteMultiSpan: spans
				ecosystems: ecosystems
				description: description
				totalCalls: totalCalls
				totalBytes: totalBytes
				totalMs: totalMs
				on: stream ]
]

{ #category : 'narrative' }
Gt4SecurityStrategySpanGroup >> narrativeWriteStrategyParagraphsOn: stream [
	"One paragraph per distinct strategy class. Spans are grouped by strategyClass so a
	strategy that ran once per ecosystem produces a single combined sentence."
	| byStrategy |
	byStrategy := OrderedDictionary new.
	self items do: [ :each |
		(byStrategy at: each strategyClass ifAbsentPut: [ OrderedCollection new ])
			add: each ].
	byStrategy valuesDo: [ :spans |
		stream nextPutAll: String crlf , String crlf.
		self narrativeWriteStrategyParagraphFor: spans on: stream ]
]

{ #category : 'accessing' }
Gt4SecurityStrategySpanGroup >> totalBytes [
	^ (self items inject: 0 into: [ :sum :each | sum + each bytes ])
]

{ #category : 'accessing' }
Gt4SecurityStrategySpanGroup >> totalCalls [
	^ (self items inject: 0 into: [ :sum :each | sum + each calls ])
]

{ #category : 'accessing' }
Gt4SecurityStrategySpanGroup >> totalCost [
	^ (self items inject: 0 into: [ :sum :each | sum + each cost ])
]

{ #category : 'accessing' }
Gt4SecurityStrategySpanGroup >> totalDurationMs [
	^ (self items inject: 0 into: [ :sum :each | sum + each durationMs ])
]

{ #category : 'printing' }
Gt4SecurityStrategySpanGroup >> totalsRows [
	"Field/value/display rows for the Totals view — values stay raw so click-through still
	spawns a useful inspector (e.g. on Integer 244588631)."
	^ {
		{ '# spans'. self items size. self items size asString }.
		{ 'Total HTTP calls'. self totalCalls. self totalCalls asString }.
		{ 'Total bytes'. self totalBytes. Gt4SecurityFormat humanBytes: self totalBytes }.
		{ 'Total est. cost'. self totalCost. self totalCost asString }.
		{ 'Total duration'. self totalDurationMs. Gt4SecurityFormat humanMs: self totalDurationMs } }
]
