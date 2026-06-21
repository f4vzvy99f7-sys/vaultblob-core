# Encrypted Blob Vault — Spec v1

A minimal, write-only encrypted storage format. Files are split into chunks across blobs in a vault folder. All on-disk bytes are indistinguishable from random without the vault master key.

---

## Glossary

| Term | Meaning |
|---|---|
| **Vault** | A folder containing one or more blobs. |
| **Blob** | A single file on disk: front matter + body. The unit the OS sees. |
| **Chunk** | One AEAD-encrypted data block. Holds a portion of a file. |
| **File** | A logical, ordered collection of chunks identified by a UUID. No on-disk representation — emergent from grouping chunks by `file_id`. |
| **Index** | A single contiguous region of stream-cipher ciphertext near the end of a blob, listing chunks contained in that blob. Authenticated by a MAC stored in the volatile slot. |
| **Stable slot** | A record in front matter holding the spec version and per-blob constants (`vault_id`, `blob_id`, wrapped `K_data` and `K_index`, `index_nonce`). Encrypted under `vault_master_key`. Written once at blob creation. |
| **Volatile slot** | A record in front matter holding the current index location, length, generation, and authenticating MAC. Encrypted under `K_index`. Two slots per blob; the one with the highest valid generation is canonical. |

---

## File Layout

```
┌─────────────────────────────────────────────────────────────────┐
│                   FRONT MATTER  (4096 bytes, fixed)             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ stable slot   2048 B    AEAD(vault_master_key)           │   │
│  │ volatile A    1024 B    AEAD(K_index)                    │   │
│  │ volatile B    1024 B    AEAD(K_index)                    │   │
│  └──────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                       BODY  (variable length)                   │
│                                                                 │
│  [ chunk 1 ] [ chunk 2 ] ... [ chunk N ]                        │
│  [ random gap ]                                                 │
│  [ index ciphertext (single contiguous stream) ]                │
│  [ random trailing gap ]                                        │
│                                                                 │
│  All bytes in body are AEAD ciphertext, AEAD tags, AEAD nonces, │
│  stream-cipher ciphertext, or CSPRNG-generated random padding.  │
│  Indistinguishable from random without the key.                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

The volatile slot's `index_offset` and `index_length` locate the index region in the body. The index is one contiguous stream-cipher ciphertext, authenticated by a single MAC stored in the volatile slot. Without the key, the body is undifferentiated random-looking bytes.

---

## Front Matter (4096 bytes, fixed)

| Offset | Size | Field | Notes |
|---|---|---|---|---|
| 0 | 2048 | `stable_slot` | AEAD frame under `vault_master_key`. Written once at blob creation. |
| 2048 | 1024 | `volatile_slot_A` | AEAD frame under `K_index`. Rewritten on every commit. |
| 3072 | 1024 | `volatile_slot_B` | AEAD frame under `K_index`. Rewritten on every commit. |

The split between stable and volatile parts lets long-running writers discard the `vault_master_key` after the first open: the per-write fields are encrypted under `K_index`, which is itself recovered from the stable slot once at blob open.

### Stable slot (2048 bytes)

```
┌───────────┬──────────────────────────────────────┬───────┬─────────────────┐
│ nonce 24B │ ciphertext (stable payload)          │ tag   │ random padding  │
│           │ + random pad to fill                 │ 16B   │ inside ciphertxt│
└───────────┴──────────────────────────────────────┴───────┴─────────────────┘
```

**Cipher:** XChaCha20-Poly1305
**Key:** `vault_master_key` (provided by app layer, 32 B)
**Nonce:** 24 B random, set at blob creation
**AAD:** `vault_id`

**Stable payload (plaintext, before encryption):**

| Size | Field | Notes |
|---|---|---|
| 4 | `version` | Spec version (currently `1`). Tells readers how to interpret the payload. |
| 16 | `vault_id` | UUID. Same across all blobs in a vault. |
| 16 | `blob_id` | UUID. Unique per blob. |
| 48 | `wrapped_K_data` | AEAD(vault_master_key) over 32 B random key. |
| 48 | `wrapped_K_index` | AEAD(vault_master_key) over 32 B random key. |
| 24 | `index_nonce` | Random 24 B. Used for the stream cipher over the index region. Fixed for the life of the blob (see write protocol invariant below). |

Total payload: ~156 B. Remainder of the 2048 B slot is random padding inside the ciphertext, so payload size does not leak.

The stable slot is written exactly once at blob creation. It is never rewritten under normal operation. Master-key rotation is the only operation that touches it (rewrap `K_data` and `K_index` under the new master key, write a new stable slot). The `index_nonce` is preserved verbatim across master-key rotation.

### Volatile slots (1024 bytes each)

```
┌───────────┬──────────────────────────────────────┬───────┬─────────────────┐
│ nonce 24B │ ciphertext (volatile payload)        │ tag   │ random padding  │
│           │ + random pad to fill                 │ 16B   │ inside ciphertxt│
└───────────┴──────────────────────────────────────┴───────┴─────────────────┘
```

**Cipher:** XChaCha20-Poly1305
**Key:** `K_index` (recovered from stable slot at blob open)
**Nonce:** 24 B random per write
**AAD:** `vault_id || blob_id || slot_index` where `slot_index ∈ {0, 1}` indicates volatile A or B

**Volatile payload (plaintext, before encryption):**

| Size | Field | Notes |
|---|---|---|
| 8 | `generation` | Monotonic counter. Highest valid generation wins. |
| 8 | `index_offset` | Byte offset of the start of the index ciphertext within the blob. |
| 8 | `index_length` | Length of the index ciphertext in bytes. |
| 32 | `index_mac` | Keyed BLAKE2b-256 over `vault_id ‖ blob_id ‖ generation ‖ index_length ‖ index_ciphertext`. Key derived from `K_index` (see crypto summary). |

Fixed payload: 56 B. The remainder of the 984 B available ciphertext space (1024 − 24 nonce − 16 tag) is random padding inside the ciphertext.

The volatile slot fully describes the index: its location, length, and authenticating MAC. There is no segment list and no per-segment metadata.

### Reader rule

1. Decrypt the stable slot with `vault_master_key`. Recover `vault_id`, `blob_id`, `K_data`, `K_index`, `index_nonce`. The master key MAY now be discarded from memory.
2. Decrypt both volatile slots with `K_index`. Pick the one with the highest `generation` that AEAD-validates.
3. If neither volatile slot validates, fall back to scan recovery (out of scope for v1).
4. Read `index_length` bytes at `index_offset`. Compute keyed BLAKE2b-256 over `vault_id ‖ blob_id ‖ generation ‖ index_length ‖ ciphertext`. Compare against `index_mac` in constant time. If mismatch, treat as corruption / racing writer (see Concurrency).
5. On MAC success, decrypt the index ciphertext with XChaCha20 under `(K_index, index_nonce)` starting at keystream offset 0.

### Writer rule

The stable slot is never rewritten outside of master-key rotation. Per-write commits rewrite only the inactive volatile slot. The active volatile slot remains canonical until the new slot is fully written and fsynced.

---

## Chunk (data region)

```
┌───────────┬──────────────────────────┬────────┐
│ nonce 24B │ ciphertext (plaintext_N) │ tag 16B│
└───────────┴──────────────────────────┴────────┘
```

Overhead: 40 bytes per chunk. No plaintext length prefix. Length is stored in the index.

**Cipher:** XChaCha20-Poly1305
**Key:** `K_file = HKDF-SHA256(ikm=K_data, salt=vault_id, info="file/" || file_id, L=32)`
**Nonce:** 24 B random per chunk, from CSPRNG
**AAD:**

```
vault_id              16 B
blob_id               16 B
file_id               16 B
sequence_number        8 B   (chunk's position in its file, 0-indexed)
chunk_offset_in_blob   8 B   (byte offset of the nonce within the blob)
───────────────────────────
total                 64 B
```

The AAD binds the chunk to its file, position in the file, and physical location. Substitution, reordering, or transplantation between blobs or vaults all cause AEAD validation to fail.

**Size limits.** A chunk's plaintext length MUST NOT exceed 2³⁸ − 64 bytes (≈256 GiB), the per-frame ciphertext limit of XChaCha20-Poly1305. Within that bound, chunk size is a writer-policy decision and is not constrained by this spec. Different writers in the same vault may use different chunk sizes; each chunk's length is recorded explicitly in its index entry.

---

## Index region

The index is a single contiguous region of XChaCha20 stream-cipher ciphertext located in the body of the blob. It contains a sequence of length-prefixed entries (described below). Integrity is provided by a single keyed-BLAKE2b MAC stored in the volatile slot, not by per-entry tags.

**Cipher:** XChaCha20 (raw, no Poly1305)
**Key:** `K_index` (per-blob, from stable slot)
**Nonce:** `index_nonce` (per-blob, from stable slot — fixed for the life of the blob under the write-once invariant)
**Keystream offset:** Plaintext byte at index position `i` is XOR'd against the keystream byte at offset `i`. Appending plaintext means generating keystream at offsets `[old_length, new_length)` and XOR'ing with new entry bytes.

**MAC:** Keyed BLAKE2b-256, computed over:

```
vault_id           16 B
blob_id            16 B
generation          8 B   (volatile slot generation that authorizes this index)
index_length        8 B
index_ciphertext    (index_length bytes)
```

MAC key: `K_mac = HKDF-SHA256(ikm=K_index, salt=blob_id, info="index-mac", L=32)`.

The MAC is recomputed on every commit and stored in the volatile slot. It covers the index length explicitly, preventing truncation attacks where a prefix would otherwise validate.

### Write-once invariant

**The plaintext byte at any given index offset is written exactly once for the life of the blob.** All commits that extend the index do so by appending new plaintext at offsets `[old_length, new_length)`; previously-written index bytes are never re-encrypted with new plaintext.

This invariant is what makes it safe to reuse the same `(K_index, index_nonce)` pair across every commit. The stream-cipher prohibition is on encrypting *different* plaintext at the same keystream offset; encrypting *new* plaintext at *new* keystream offsets is exactly what stream-cipher extension is for.

Case 2 relocations move index ciphertext to a new file offset but do not change the plaintext at any index offset — the same plaintext bytes occupy the same positions within the index region; only the index region's location in the file changes. This preserves the invariant.

V1 has no deletion, modification, or compaction of index entries. Any future operation that would require rewriting a previously-written index offset with different plaintext MUST be accompanied by rotation of `index_nonce`, which is a stable-slot change.

### Entry types (inside plaintext stream)

Each entry is preceded by a 1-byte type tag for forward extensibility. Each entry has a fixed length determined by its type; the type tag is sufficient to compute the length and advance the decoder.

**`0x01` — chunk entry (73 bytes payload)**

| Size | Field |
|---|---|
| 16 | `file_id` |
| 8 | `sequence_number` |
| 8 | `offset_in_blob` |
| 8 | `plaintext_length` |
| 32 | `content_hash` (BLAKE2b-256 of plaintext) |

**`0x02` — file_complete entry (56 bytes payload)**

| Size | Field |
|---|---|
| 16 | `file_id` |
| 8 | `total_chunks` |
| 32 | `full_content_hash` (hash of concatenated plaintexts) |

Writer emits this after the final chunk of a file is committed. Readers use it to verify completeness.

Unknown type tags MUST cause the reader to stop decoding (v1 has no length prefix on the type tag itself; future versions adding new entry types MUST length-prefix them so older readers can skip).

---

## Crypto Summary

| Key | Derivation | Used For |
|---|---|---|
| `vault_master_key` | Provided by app layer (32 B) | Encrypting the stable slot only |
| `K_data` | Random 32 B per blob, wrapped in stable slot | HKDF input for per-file keys |
| `K_index` | Random 32 B per blob, wrapped in stable slot | Volatile slots and index stream cipher in this blob |
| `K_file` | `HKDF(K_data, salt=vault_id, info="file/"‖file_id)` | All chunks of one file |
| `K_mac` | `HKDF(K_index, salt=blob_id, info="index-mac")` | Keyed BLAKE2b MAC over the index region |
| `index_nonce` | Random 24 B per blob, stored in stable slot | XChaCha20 nonce for the index stream |

**AEAD primitive:** XChaCha20-Poly1305 (RFC 8439 + XChaCha extension) for stable slot, volatile slots, and chunks.
**Stream cipher:** XChaCha20 (raw) for the index region.
**Hash:** BLAKE2b-256 for content hashes and (keyed) for the index MAC.
**Randomness:** All nonces and padding from a CSPRNG.
**Byte order:** All multi-byte integer fields (offsets, lengths, counters, sequence numbers) are encoded **little-endian**. This applies to fields in stable and volatile slot payloads, index entries, and AAD / MAC construction.

---

## Write Protocol

Let:
- `index_start` = `index_offset` (start of index ciphertext in the body)
- `index_end` = `index_offset + index_length` (byte just past the index)
- `G` = current leading gap (between data tail and `index_start`)
- `T` = current trailing gap (between `index_end` and EOF)
- `C` = new chunk size = 24 + plaintext_length + 16
- `E` = new index entry size (in plaintext bytes; the same number of stream-cipher ciphertext bytes are appended)

### Case 1 — append-only (cheapest)

If `C ≤ G` and `E ≤ T`:

```
1. Write chunk into leading gap (advances data tail toward index_start).
2. fsync.
3. Generate keystream for offsets [index_length, index_length + E)
   under (K_index, index_nonce). XOR with new entry plaintext.
   Write the resulting ciphertext at (index_offset + index_length),
   extending the index region into the trailing gap.
4. fsync.
5. Compute new MAC over:
     vault_id ‖ blob_id ‖ (generation + 1) ‖ (index_length + E)
       ‖ full index ciphertext (length index_length + E)
6. Write new volatile slot (to inactive slot):
     generation += 1
     index_offset unchanged
     index_length = old index_length + E
     index_mac = newly computed MAC
7. fsync.
```

The active volatile slot remains valid throughout. It describes a valid prefix of the new index; that prefix MACs correctly against the *old* (volatile_slot, generation) pair until the new slot is fsynced.

There is no per-write segment-count ceiling. The index grows by exactly `E` bytes per appended entry, with no per-segment AEAD overhead.

### Case 2 — relocate index, then append

Triggered when any of the following are true:
- `C > G` (chunk doesn't fit in the leading gap)
- `E > T` (new entry doesn't fit in the trailing gap)

Existing index ciphertext is moved verbatim to a new location. Because the write-once invariant holds — same plaintext at same index offsets, just relocated within the file — the same `(K_index, index_nonce)` continues to apply and the MAC remains valid for the relocated bytes prior to extension.

Let `needed = C + index_length + E` (leading gap required to fit the new chunk, the relocated index, and the new entry's appended ciphertext).
Let `shortfall = max(0, needed - G)` (extra space to create past current EOF).

```
1. Append `shortfall` CSPRNG random bytes to current EOF. File grows.
2. Copy the index ciphertext (length index_length) verbatim from its
   current location to a new offset past old_EOF, leaving enough leading
   gap for the new chunk. Concretely: new_index_offset is chosen so that
   (new_index_offset - data_tail) ≥ C (plus any writer-policy padding).
3. fsync.
4. Generate keystream for offsets [index_length, index_length + E)
   and XOR with the new entry. Write the resulting ciphertext at
   (new_index_offset + index_length).
5. fsync.
6. Compute new MAC over:
     vault_id ‖ blob_id ‖ (generation + 1) ‖ (index_length + E)
       ‖ full index ciphertext (length index_length + E)
7. Write new volatile slot (to inactive slot):
     generation += 1
     index_offset = new_index_offset
     index_length = old index_length + E
     index_mac = newly computed MAC
8. fsync.   ← commit point. Layout is now:
              [front matter][data][large leading gap][relocated index]
   The old index region's bytes and any old trailing gap are now part
   of the new leading gap; their contents are stale ciphertext,
   indistinguishable from random.
9. Write the new chunk into the leading gap (between data tail and
   new_index_offset). Update the volatile slot again via Case 1 if the
   entry above did not already cover this chunk.
```

In practice, steps 2 and 9 can be reordered or fused: the writer chooses `new_index_offset` and then writes the chunk into the resulting leading gap before or after the index move, provided the canonical volatile slot is not advanced to reference a chunk that is not yet on disk. The commit-point invariant is unchanged from v1: **at no point does the canonical index reference a chunk that is not physically on disk.**

### Gap policy (writer-side, not spec)

After every Case 2 relocation, the writer should choose `shortfall` larger than the strict minimum so that subsequent writes can use Case 1. A reasonable default is to size the new leading gap to hold several typical chunks and the new trailing gap to hold many typical index entries. This is writer config, not part of the format.

Note that v1 (revised) has no analog of the old "segment-count ceiling" that previously forced index relocations independent of gap geometry. Index growth is purely linear in entry count, and the only forcing function for Case 2 is gap exhaustion.

---

## Recovery

```
1. Read bytes [0, 4096) → front matter.
2. AEAD-decrypt the stable slot at offset 0 with vault_master_key.
   Recover version, vault_id, blob_id, K_data, K_index, index_nonce.
   If version is not understood, refuse to open (forward-compat guard).
   The vault_master_key MAY now be discarded.
3. Derive K_mac = HKDF(K_index, salt=blob_id, info="index-mac").
5. AEAD-decrypt volatile slot A and volatile slot B with K_index.
6. Pick the volatile slot with the highest `generation` that validates.
   - If neither validates: scan recovery (out of scope for v1).
7. Read `index_length` bytes at `index_offset`.
8. Compute keyed-BLAKE2b MAC under K_mac over:
     vault_id ‖ blob_id ‖ generation ‖ index_length ‖ ciphertext
   Compare to `index_mac` in constant time.
   - If mismatch: see Concurrency (racing writer) or treat as corruption.
9. Decrypt the index ciphertext with XChaCha20 under (K_index, index_nonce)
   starting at keystream offset 0.
10. Decode entries sequentially. Group chunk entries by file_id; sort by
    sequence_number to reconstruct files. Verify against `file_complete`
    entries where present.
```

### Forensic recovery

The index region is raw XChaCha20 ciphertext and can be decrypted directly with `(K_index, index_nonce)` regardless of MAC validity. A recovery tool with the appropriate key material can extract index entries from a damaged blob; output past the corruption point is unverified and MUST be treated as untrusted.

Similarly, chunk ciphertext (XChaCha20-Poly1305) can be decrypted by XChaCha20 alone, ignoring the Poly1305 tag. A recovery tool with the appropriate key and nonce can extract plaintext from any chunk regardless of tag validity. Output is unverified — corrupted ciphertext positions yield corrupted plaintext positions — and MUST be treated as untrusted.

These paths are for forensic/recovery tooling only and MUST NOT be exposed through normal read APIs.

---

## Concurrency

The format supports multiple concurrent writers and readers across a vault, with the constraint that only one writer may modify a given blob at a time.

### Writers

A writer MUST acquire an **exclusive advisory lock** on the blob file before performing any write operation, and MUST hold it for the full duration of that operation (including all fsyncs in Case 1 or Case 2).

Pre-write sequence, in strict order:

```
1. Acquire LOCK_EX on the blob file.
2. Re-read the volatile slot region (both volatile slots).
3. Decrypt the volatile slots with the already-cached K_index;
   pick the highest-generation valid slot.
4. Read the full index region; verify the MAC against K_mac.
5. Plan and execute the write (Case 1 or Case 2).
6. Final fsync.
7. Release LOCK_EX.
```

Writer state read before acquiring the lock MUST NOT be trusted for writing decisions. A writer's previous in-memory view of the blob is a hint only; the canonical view comes from steps 2–4 under the lock.

A writer needs to decrypt the stable slot only once per blob-open (to recover `K_data`, `K_index`, `index_nonce`). After that, all per-write reads operate against the volatile slots and the index region under `K_index` and its derived subkey `K_mac`. The `vault_master_key` MAY be discarded from memory after the first stable-slot decrypt and re-supplied only when opening additional blobs.

### Readers

Readers MUST NOT acquire any lock for normal read operations. The format's properties make this safe:

- **Committed chunk bytes are immutable.** In v1, once a chunk is written and committed, its bytes are never overwritten. A reader holding any historical view of a chunk's offset will read correct bytes from that offset indefinitely.
- **Index plaintext is append-only.** A reader holding any historical view of the index will find that all index offsets it previously read remain valid; the index either stays in place and grows, or is relocated verbatim and grows at the new location. The reader's view may be stale (missing recent appends) but not inconsistent.
- **Races during index reads are detectable.** If a reader reads the index region while a writer performs Case 2 (relocating the index ciphertext), the bytes the reader receives may be a mix of the old region's stale ciphertext and unrelated bytes. The MAC computed over the bytes the reader read will not match the MAC in the volatile slot the reader chose. This is detectable.

On MAC failure during an index read, the reader MUST re-read the volatile slots and retry. After a configurable retry budget, the reader SHOULD surface an error to the application.

Readers MAY acquire a shared advisory lock (`LOCK_SH` or platform equivalent) if they require a point-in-time consistent snapshot across multiple chunk reads (e.g., for backup or forensic tooling). This is an application-layer decision and not required by the format.

### Platform notes

On POSIX systems, the exclusive lock is `flock(LOCK_EX)`. On Windows, the equivalent is `LockFileEx` with `LOCKFILE_EXCLUSIVE_LOCK`. The spec assumes the platform's advisory file-locking primitive provides cross-process mutual exclusion within a single host.

**NFS is not supported.** NFSv3 advisory locking via `rpc.lockd` is unreliable across many real-world deployments; NFSv4 byte-range locks are more reliable but not universally available. Vaults stored on NFS-mounted filesystems may experience corruption under concurrent access and are explicitly outside the scope of this spec.

### What this does NOT provide

- Notification of changes. Readers with cached state become eventually consistent; they refresh on MAC failure or on application-layer triggers (file watchers, polling, etc., all out of spec).
- Cross-blob atomicity. Concurrent writes to different blobs in the same vault are independent at the format level. Application-layer policy decides which blob each writer targets.

---

## Indistinguishability Properties

Without `vault_master_key`, an observer of a blob file learns:

- Total file length.
- That offsets 0..4096 contain three random-looking regions (one 2048 B and two 1024 B).
- That offsets 4096..EOF contain random-looking bytes.

They cannot determine:

- Where data ends and the index begins.
- How many chunks, files, or index entries the blob contains.
- Chunk boundaries.
- Whether two blobs share any files.

Format-anonymity (hiding that this is the blob vault format) is explicitly NOT a goal.

---

## Tradeoffs vs. multi-segment indices

Compared to a design that stores the index as a chain of independent AEAD frames:

- **Pro:** No per-frame overhead. Index grows by exactly the entry's plaintext size per append, with one 32 B MAC stored in the volatile slot regardless of entry count.
- **Pro:** No segment-count ceiling. The volatile slot is fixed-size and does not fill up as entries accumulate. Writes never need to "compact" the index for bookkeeping reasons; relocations are driven only by gap exhaustion.
- **Pro:** Readers perform one stream decrypt and one MAC verify, regardless of entry count, instead of N independent AEAD decryptions.
- **Con:** Per-entry corruption localization is lost. A single bit-flip anywhere in the index invalidates the whole MAC and renders the entire index untrusted (though forensic recovery can still decrypt past the corruption).
- **Con:** The write-once invariant on index plaintext is load-bearing for nonce reuse safety. Any future feature that would rewrite an existing index offset with different plaintext (deletion, in-place compaction, entry mutation) MUST rotate `index_nonce`, which is a stable-slot change and therefore touches the master key.

---

## Out of Scope for v1

- Deletion and tombstones.
- Modification of existing files.
- Compaction of blobs (rewriting to remove dead data).
- Cross-blob coordination, vault-level transactions, rename.
- Scan-recovery fallback when both volatile slots fail.
- KDF from passphrase (handled at app layer; spec consumes a 32-byte vault master key).