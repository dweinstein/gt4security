"
Thin, safe wrapper around /usr/bin/unzip for ZIP64-capable archive access.

Pharo's {{gtClass:ZipArchive}} cannot seek into ZIP64 archives (it reads the classic End-of-Central-Directory record with 32-bit fields, which become 0xFFFFFFFF sentinels in ZIP64). The OSV feeds for npm and the larger Linux distros are ZIP64 because they exceed 65,535 entries. This class shells out to system unzip — Info-ZIP v6+ handles ZIP64 natively.

Uses {{gtClass:GtSubprocessWithInMemoryOutput}}, the standard GT subprocess wrapper (same infrastructure as {{gtClass:GtAwsClient}}, etc.).

Primary APIs:
- listEntries: aZipFile — `unzip -l -qq`, returns parsed rows
- contentsOfEntry:in: (entryName, aZipFile) — `unzip -p`, returns stdout bytes
- extractAllTo:from: (tmpDir, aZipFile) — `unzip -o -d` for bulk extraction

Safety notes:
- `unzip -p` streams entry contents to stdout — we own the destination; the archive entry name cannot influence filesystem state. This structurally neutralizes Zip Slip for the single-entry path.
- Entry names are additionally validated against a tight allowlist regex as defense-in-depth (so a malformed archive triggers a clean error rather than surprising subprocess output).
- Bulk extract (extractAllTo:) relies on caller-chosen target directory + modern unzip's refusal to write outside target (v6+ rejects `..` by default). Callers should still use a fresh tmpdir per call.

Error model:
- isAvailable checks unzipPath once at class-side default; returns nil if unzip is missing (e.g. bare Windows).
- Each subprocess invocation checks isSuccess; failure signals GtSubprocessError with the stderr attached.

Async:
- Sync methods compose cleanly with {{gtClass:AsyncJoinAllFuture}} — wrap a single-call method in a block and send asAsyncForkedFuture when you want concurrent reads.

"
Class {
	#name : 'Gt4SecurityUnzipTool',
	#superclass : 'Object',
	#instVars : [
		'unzipPath',
		'version'
	],
	#category : 'Gt4Security-Clients',
	#package : 'Gt4Security',
	#tag : 'Clients'
}

{ #category : 'accessing' }
Gt4SecurityUnzipTool class >> argvByteBudget [
	"Maximum bytes of entry-name argv we pass to a single unzip invocation.
	macOS ARG_MAX is ~1 MB total (argv + environ); Linux typically allows ~2 MB.
	200 KB leaves generous headroom for the fixed prefix args and the current
	environment while still keeping batch count tiny for realistic id lists
	(npm 365-day window is ~4 MB of entry names → ~20 batches)."

	^ 200000
]

{ #category : 'accessing' }
Gt4SecurityUnzipTool class >> default [
	"Return a shared instance bound to the default unzip path, or nil if unzip isn't available. Callers should guard with `tool ifNotNil: [ ... ]`."
	| instance |
	instance := self new.
	^ instance isAvailable ifTrue: [ instance ] ifFalse: [ nil ]
]

{ #category : 'defaults' }
Gt4SecurityUnzipTool class >> defaultConcurrency [
	"Default cap for batched reads. Matches the HTTP-fetch default in Gt4SecurityOsvFeedClient so the two parallel paths behave consistently."
	^ 16
]

{ #category : 'accessing' }
Gt4SecurityUnzipTool class >> defaultUnzipPath [
	"Canonical location on macOS / most Linuxes. Callers can inject a different path if needed."
	^ '/usr/bin/unzip'
]

{ #category : 'safety' }
Gt4SecurityUnzipTool class >> entryNameAllowlistRegex [
	"Match archive-entry names we're willing to ask unzip to extract. The purpose is defense-in-depth (structural safety comes from `unzip -p`'s refusal to write to disk). Accepts printable characters minus control/path-traversal segments."
	^ '^[A-Za-z0-9][A-Za-z0-9._/+-]*$' asRegex
]

{ #category : 'defaults' }
Gt4SecurityUnzipTool class >> executionGroupName [
	"Named group for our subprocess work — lets the async pool partition and cap it independently of other async work in the image."
	^ 'gt4security-unzip'
]

{ #category : 'private' }
Gt4SecurityUnzipTool >> chunkEntryNames: anEntryNameCollection [
	"Split anEntryNameCollection into sub-collections whose total byte size
	(names + 1 byte per-name separator overhead) does not exceed the class-side
	argvByteBudget. Each returned chunk has at least one entry. macOS execve()
	fails with E2BIG when argv + environ exceeds ARG_MAX (~1 MB); at npm scale
	(~194K ids, ~4 MB argv) this manifests as GtExternalProcessFailedToStart."

	| budget chunks current currentBytes |
	budget := self class argvByteBudget.
	chunks := OrderedCollection new.
	current := OrderedCollection new.
	currentBytes := 0.
	anEntryNameCollection do: [ :name |
		| size |
		size := name size + 1.
		(current isNotEmpty and: [ currentBytes + size > budget ]) ifTrue: [
			chunks add: current.
			current := OrderedCollection new.
			currentBytes := 0 ].
		current add: name.
		currentBytes := currentBytes + size ].
	current isNotEmpty ifTrue: [ chunks add: current ].
	^ chunks
]

{ #category : 'extraction' }
Gt4SecurityUnzipTool >> contentsOfEntries: anEntryNameCollection in: aZipFile [
	"Default-concurrency convenience for contentsOfEntries:in:concurrency:."
	^ self
		contentsOfEntries: anEntryNameCollection
		in: aZipFile
		concurrency: self class defaultConcurrency
]

{ #category : 'extraction' }
Gt4SecurityUnzipTool >> contentsOfEntries: anEntryNameCollection in: aZipFile concurrency: anInteger [
	"Batched parallel reads via async futures scheduled in a named group with a bounded pool. First-error-wins semantics: if any individual entry read fails, signals that error from this method. Successful reads up to that point are orphaned.

	Returns an OrderedCollection of entryName -> bytes associations in input order."
	| cfg promises results |
	anEntryNameCollection do: [ :name | self validateEntryName: name ].
	cfg := AsyncFutureExecutionConfiguration new
		userBackgroundPriority;
		customGroup: self class executionGroupName;
		maxAmountOfWorkers: anInteger;
		yourself.
	promises := anEntryNameCollection collect: [ :name |
		[ name -> (self contentsOfEntry: name in: aZipFile) ]
			asAsyncFuture await: cfg ].
	results := promises collect: [ :p | p wait ].
	"First-error-wins: re-raise the first rejected promise's error, orphaning any in-flight work."
	results do: [ :r | (r isKindOf: Error) ifTrue: [ r signal ] ].
	^ results asOrderedCollection
]

{ #category : 'extraction' }
Gt4SecurityUnzipTool >> contentsOfEntry: anEntryName in: aZipFile [
	"Run `unzip -p <zip> <entry>` and return the entry's bytes as a String. Raises if the entry name fails allowlist validation or unzip reports failure (missing entry, corrupt zip)."
	| proc |
	self validateEntryName: anEntryName.
	proc := self runArguments: { '-p'. aZipFile fullName. anEntryName }.
	proc isSuccess ifFalse: [
		GtSubprocessError new
			messageText: 'unzip -p failed for ' , anEntryName , ': ' , proc stderr trimBoth;
			process: proc;
			signal ].
	^ proc stdout
]

{ #category : 'extraction' }
Gt4SecurityUnzipTool >> contentsOfEntryAsync: anEntryName in: aZipFile [
	"Async variant of contentsOfEntry:in: — returns an AsyncFuture that, when awaited, yields the entry's bytes. Used by contentsOfEntries:in:concurrency: to build a bag of pending reads, and directly by callers that want to compose with other async work."
	self validateEntryName: anEntryName.
	^ [ self contentsOfEntry: anEntryName in: aZipFile ] asAsyncFuture
]

{ #category : 'extraction' }
Gt4SecurityUnzipTool >> extractAllTo: aTargetDirectory from: aZipFile [
	"Run `unzip -o -d <dir> <zip>` to extract every entry into aTargetDirectory. Caller is responsible for choosing (and cleaning up) aTargetDirectory. Modern unzip (v6+) refuses to write outside the target directory by default."
	| target proc |
	target := aTargetDirectory asFileReference.
	target ensureCreateDirectory.
	proc := self runArguments: { '-o'. '-q'. '-d'. target fullName. aZipFile fullName }.
	proc isSuccess ifFalse: [
		GtSubprocessError new
			messageText: 'unzip -d failed: ' , proc stderr trimBoth;
			process: proc;
			signal ].
	^ target
]

{ #category : 'running' }
Gt4SecurityUnzipTool >> extractEntries: anEntryNameCollection from: aZipFile to: aTargetDirectory [
	"Run `unzip -o -j -d <dir> <zip> <name1> <name2> … <nameN>` to extract just the listed
	entries into aTargetDirectory. -j flattens any paths in the archive so output is a flat
	directory. Entries that don't exist in the archive are silently skipped (unzip exits 11
	with stderr 'caution: filename not matched', which we treat as success if exit code is
	0 or 11). Caller is responsible for aTargetDirectory lifecycle.

	Large id lists are chunked to stay under the platform argv size limit (macOS ARG_MAX
	~1 MB). Without chunking, ecosystems like npm — whose yearly modified-id window can
	yield ~200K ids / ~4 MB of argv — cause execve() to fail with E2BIG, surfacing as
	GtExternalProcessFailedToStart. See chunkEntryNames: for the byte budget."

	| target chunks |
	anEntryNameCollection do: [ :name | self validateEntryName: name ].
	target := aTargetDirectory asFileReference.
	target ensureCreateDirectory.
	chunks := self chunkEntryNames: anEntryNameCollection.
	chunks do: [ :chunk |
		| args proc |
		args := OrderedCollection new.
		args add: '-o'; add: '-j'; add: '-q'; add: '-d'; add: target fullName.
		args add: aZipFile fullName.
		chunk do: [ :name | args add: name ].
		proc := self runArguments: args asArray.
		"unzip exit 11 = 'no matching files' — benign when the caller's id list partially overlaps
		with the archive. Anything else is an error."
		(proc exitCode = 0 or: [ proc exitCode = 11 ]) ifFalse: [
			GtSubprocessError new
				messageText: 'unzip batch extract failed (chunk of ' , chunk size asString
					, '): ' , proc stderr trimBoth;
				process: proc;
				signal ] ].
	^ target
]

{ #category : 'gt - views' }
Gt4SecurityUnzipTool >> gtConfigurationFor: aView [
	<gtView>
	^ aView columnedList
		title: 'Configuration';
		priority: 1;
		items: [ {
			'unzip path' -> unzipPath.
			'path exists' -> unzipPath asFileReference exists printString.
			'available' -> self isAvailable printString.
			'version' -> (self version ifNil: [ '(unavailable)' ]) } ];
		column: 'Property' text: [ :assoc | assoc key ] weight: 1;
		column: 'Value' text: [ :assoc | assoc value ] weight: 3
]

{ #category : 'initialize-release' }
Gt4SecurityUnzipTool >> initialize [
	super initialize.
	unzipPath := self class defaultUnzipPath
]

{ #category : 'testing' }
Gt4SecurityUnzipTool >> isAvailable [
	^ self version notNil
]

{ #category : 'listing' }
Gt4SecurityUnzipTool >> listEntries: aZipFile [
	"Run `unzip -l -qq <zip>` and parse the output into an OrderedCollection of Dictionary rows with keys 'size', 'date', 'time', 'name'. Does not extract anything."
	| proc |
	proc := self runArguments: { '-l'. '-qq'. aZipFile fullName }.
	proc isSuccess ifFalse: [
		GtSubprocessError new
			messageText: 'unzip -l failed: ' , proc stderr;
			process: proc;
			signal ].
	^ self parseListingOutput: proc stdout
]

{ #category : 'private' }
Gt4SecurityUnzipTool >> parseListingOutput: aString [
	"Parse `unzip -l -qq` output. Each line: '   SIZE  MM-DD-YYYY HH:MM   name'.
	Name may contain spaces, so we parse from the left: 3 whitespace-separated fields then the remainder."
	| rows |
	rows := OrderedCollection new.
	aString lines do: [ :line |
		| trimmed tokens size date time name |
		trimmed := line trimBoth.
		trimmed isEmpty ifFalse: [
			tokens := trimmed substrings.
			tokens size >= 4 ifTrue: [
				size := [ (tokens at: 1) asNumber ] on: Error do: [ :e | nil ].
				date := tokens at: 2.
				time := tokens at: 3.
				"Name is everything after the third field — rejoin tokens 4..end with single spaces."
				name := ' ' join: (tokens copyFrom: 4 to: tokens size).
				size ifNotNil: [
					rows add: (Dictionary new
						at: 'size' put: size;
						at: 'date' put: date;
						at: 'time' put: time;
						at: 'name' put: name;
						yourself) ] ] ] ].
	^ rows
]

{ #category : 'private' }
Gt4SecurityUnzipTool >> runArguments: anArray [
	"Internal: run unzip with the given argv, return the completed process.
	Raises GtSubprocessError (when unzip is unavailable) or the subprocess's
	own error block. Callers check `proc isSuccess` afterward."
	| proc |
	self isAvailable ifFalse: [
		Error signal: 'unzip tool not available at ' , unzipPath ].
	proc := GtSubprocessWithInMemoryOutput new
		command: unzipPath;
		arguments: anArray;
		runAndWait.
	^ proc
]

{ #category : 'accessing' }
Gt4SecurityUnzipTool >> unzipPath [
	^ unzipPath
]

{ #category : 'accessing' }
Gt4SecurityUnzipTool >> unzipPath: aString [
	unzipPath := aString.
	version := nil
]

{ #category : 'safety' }
Gt4SecurityUnzipTool >> validateEntryName: anEntryName [
	"Guard against malformed / hostile entry names. Structural safety for -p comes from unzip writing to stdout (not the filesystem) regardless of the entry name, but we still reject anything that would look suspicious in logs or violate our caller-side contract."
	anEntryName isString ifFalse: [ Error signal: 'entry name must be a String' ].
	anEntryName isEmpty ifTrue: [ Error signal: 'entry name must be non-empty' ].
	(self class entryNameAllowlistRegex matches: anEntryName) ifFalse: [
		Error signal: 'entry name rejected by allowlist regex: ' , anEntryName ].
	(anEntryName includesSubstring: '..') ifTrue: [
		Error signal: 'entry name contains path traversal: ' , anEntryName ]
]

{ #category : 'accessing' }
Gt4SecurityUnzipTool >> version [
	"Lazy: cached first line of `unzip -v`, or nil if unzip not available."
	version ifNotNil: [ ^ version ].
	unzipPath asFileReference exists ifFalse: [ ^ nil ].
	^ version := [ | proc |
		proc := GtSubprocessWithInMemoryOutput new
			command: unzipPath;
			arguments: #('-v');
			runAndWait.
		proc isSuccess
			ifTrue: [ proc stdout lines ifEmpty: [ nil ] ifNotEmpty: [ :ls | ls first ] ]
			ifFalse: [ nil ] ]
		on: Error do: [ :e | nil ]
]
