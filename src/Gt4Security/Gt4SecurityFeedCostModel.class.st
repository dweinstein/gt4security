"
I hold the order-of-magnitude cost constants that Gt4SecurityFeedStrategy subclasses consult when ranking applicable strategies for a feed query.

The numbers are deliberately approximate — their purpose is to rank strategies relative to each other, not to predict wall-clock time. Keeping them centralized means there is one place to retune when the underlying OSV CDN (storage.googleapis.com/osv-vulnerabilities) shifts in size, and one place to read when debugging a surprising strategy selection.

## Units

All byte values are in bytes (raw integers — multiply or divide at the call site if you need a different unit for display).

## Current values (April 2026)

- revalidateHandshakeBytes ~ 1 KB       (If-Modified-Since 304 handshake)
- modifiedIdsFullBytes     ~ 42 MB      (cold download of modified_id.csv)
- modifiedIdsBytesPerDay   ~ 500 KB     (one day of tail rows)
- modifiedIdsRowsPerDay    ~ 800 rows   (aggregate across ecosystems)
- singleIdFetchBytes       ~ 10 KB      (one vulnerability JSON doc)
- perIdFetchBytes          ~ 10 KB      (per-id bulk hydration)
- smallEcosystemZipBytes   ~ 10 MB      (typical ecosystem zip)
- largeEcosystemZipBytes   ~ 100 MB     (npm, maven, etc.)
- defaultWindowDays        = 30         (fallback when a query has no since cutoff)

These are re-measured opportunistically during feed work — see the OSV modified_id.csv feed reference in Claude memory for the most recent numbers.

## Use

All methods are class-side. Do not instantiate.

    Gt4SecurityFeedCostModel modifiedIdsFullBytes
"
Class {
	#name : 'Gt4SecurityFeedCostModel',
	#superclass : 'Object',
	#category : 'Gt4Security-FeedStrategy',
	#package : 'Gt4Security',
	#tag : 'FeedStrategy'
}

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> defaultWindowDays [
	"Fallback window size used when a query has no since cutoff."
	^ 30
]

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> ecosystemRowShareFactor [
	"Rough divisor applied to modifiedIdsRowsPerDay when a query targets a specific set of
	ecosystems instead of the whole feed. Empirically npm covers ~30% of the aggregate rows,
	but most ecosystems are far smaller — averaging across the ~20 OSV ecosystems gives a
	per-ecosystem share closer to 1/20. The hydrated-window cost model uses this to avoid
	vastly over-estimating per-id fetch volume for single-ecosystem queries."
	^ 20
]

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> largeEcosystemZipBytes [
	"Cold-download size for a large ecosystem (npm, maven, etc. — ~100 MB)."
	^ 100 * 1024 * 1024
]

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> modifiedIdsBytesPerDay [
	"Empirical: about 500 KB of modified_id.csv rows correspond to one day of changes.
	Used by the stream-window strategy to estimate partial-read cost."
	^ 500 * 1024
]

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> modifiedIdsFullBytes [
	"Approximate size of the full modified_id.csv download (~41 MB in April 2026, rounded up)."
	^ 42 * 1024 * 1024
]

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> modifiedIdsRowsPerDay [
	"Empirical: roughly 800 id-modification entries per day on the aggregate feed.
	Conservative upper bound — shrinks when filtered by ecosystem."
	^ 800
]

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> perIdFetchBytes [
	"Average transfer for fetching an individual vulnerability record when hydrating rows
	from modified_id.csv. Matches singleIdFetchBytes but kept as a separate name to document
	the context in which it's applied (bulk hydration, not single-id scope)."
	^ 10 * 1024
]

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> revalidateHandshakeBytes [
	"A cache-revalidation request that returns 304 transfers ~1 KB (just headers).
	Used as the cost floor for any strategy that can short-circuit via If-Modified-Since."
	^ 1024
]

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> singleIdFetchBytes [
	"Order-of-magnitude size of a single vulnerability JSON document (~10 KB typical)."
	^ 10 * 1024
]

{ #category : 'constants' }
Gt4SecurityFeedCostModel class >> smallEcosystemZipBytes [
	"Cold-download size for a typical small ecosystem (~10 MB)."
	^ 10 * 1024 * 1024
]
