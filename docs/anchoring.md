# External time anchoring — OpenTimestamps now, qualified eIDAS TSA later

The Agent Witness Protocol (AWP) anchors a **checkpoint root** to an
**independent, external** time source — proof, outside the audited entity's
control, that the root existed at a point in time. Anchoring is **per checkpoint,
never per record** (spec §2): cost and proof volume scale with the checkpoint
cadence, not with traffic. The anchor input is always an AW-4 checkpoint
(`root + size + origin`), and `submitCheckpoint` only ever reads the 32-byte
`root`.

> **Tamper-evidence, not tamper-proofing.** An external anchor makes a backdated
> or fabricated timestamp *evident* — it does not make time un-forgeable by
> physics. The verifier reports **which** anchor backs the time and **how much
> evidentiary weight** that anchor honestly carries, and nothing more.

There are two anchor paths, and they carry **different** evidentiary weight. The
verifier never blurs them.

| Path | Buildable | Trust model | Honest weight the verifier reports |
|------|-----------|-------------|-------------------------------------|
| **OpenTimestamps (OTS)** | **NOW** — free, no contract, no € | Bitcoin calendars, no trusted party | `trust-minimized` (Bitcoin). Confirmed vs pending stated explicitly. |
| **RFC 3161 (qualified eIDAS TSA)** | **LATER** — operator contracts a QTSP (vendor + €) | A QTSP on an EU trusted list (eIDAS Art. 41) | `qualified` **only** when the operator pins the anchor as qualified; otherwise a plain `timestamp`. |

---

## 1. OpenTimestamps — the buildable-NOW anchor (`src/anchor/`)

OTS is the **only** external anchor available with zero external contracts and
zero € (ADR D-b1). It aggregates a digest into a Bitcoin commitment via public
calendar servers, with **no trusted party**. Its latency is **hours / block-time
granularity** — fine for a checkpoint cadence, and stated honestly as "existence
no later than the checkpoint anchored at T."

### Two halves: offline VERIFY and online SUBMIT/UPGRADE

- **Verify (offline, zero network)** — `readOtsProof` / `verifyOtsAnchor`
  (`opentimestamps.ts`). Given a finished `.ots` proof and the digest it should
  commit, it walks the proof's commitment operations and reports whether the
  attestation reached is a **confirmed Bitcoin block** or a **pending calendar**
  commitment. This path makes **no network calls** — an auditor verifies a
  receipt with no calendar, no Bitcoin node, and no relationship with the
  producer.

- **Submit + upgrade (online, network injected)** — `submitCheckpoint` /
  `upgradeProof` (`ots-submit.ts`). The producer-side path:
  1. `submitCheckpoint(checkpoint, http)` POSTs the checkpoint root to OTS
     calendar(s) and returns a **PENDING** proof (`pending: true`) — the
     calendars have aggregated the root but it is **not yet in a Bitcoin block**.
  2. `upgradeProof(pendingProof, http)`, run **later** (hours), queries the
     calendar for the Bitcoin attestation and, **only if a calendar actually
     serves one**, returns a `confirmed` proof. If no block is available yet it
     returns the proof **unchanged** as `still-pending`.

  All network I/O goes through an **injected `OtsHttp` transport** — the module
  opens no sockets itself, so tests run fully offline against a mock calendar.

### Honest asynchrony — confirmation is never fabricated

Bitcoin confirmation is genuinely asynchronous (block time). `submitCheckpoint`
returns `pending: true`; `upgradeProof` reports `confirmed` **only** when a
calendar returns a real Bitcoin block-header attestation that the offline reader
then re-derives. A pending proof is reported as
*"calendar-attested, awaiting Bitcoin confirmation"* — never as confirmed time.

---

## 2. RFC 3161 — a TSA-agnostic VERIFY slot, qualified vendor added by CONFIG

The auditor-grade anchor — an **eIDAS qualified** RFC 3161 timestamp carrying the
**Art. 41 presumption** of time accuracy — requires a contracted, audited QTSP on
an EU trusted list. **No free qualified TSA exists; pricing is per-provider and
cadence-driven** (ADR D-b2). That is an **operator decision (vendor + €)**, and
it is deliberately **NOT a code blocker**.

`verifyRfc3161Token` / `verifyRfc3161Anchor` (`rfc3161.ts`) implement **generic**
RFC 3161 token verification over a checkpoint root:

1. parse the CMS `SignedData` / `TSTInfo`;
2. check `messageImprint == hash(checkpoint root)` — a token that does not cover
   the data **fails**;
3. check the signed attributes bind the signature to the `TSTInfo`
   (`content-type` + `message-digest`);
4. verify the TSA signature over the DER-re-encoded `signedAttrs` against a
   **supplied trust anchor** (RSA or ECDSA);
5. expose `genTime` to the caller.

The **same code path** verifies a free non-qualified TSA token (freetsa.org,
DigiCert) today and a qualified token tomorrow. The qualified vendor drops in by
**config, not code**: supply an `Rfc3161TrustAnchor` whose `publicKey` is the
vendor's TSA key and set `qualified: true`. Nothing in `rfc3161.ts` changes.

```ts
// Today — a free TSA, reported as a plain timestamp (no legal presumption):
verifyRfc3161Anchor(proof, { trustAnchor: { publicKey: freeTsaPem } });

// Later — the operator contracts a QTSP and pins it qualified. Same call site:
verifyRfc3161Anchor(proof, {
  trustAnchor: { publicKey: qtspPem, qualified: true, name: 'Evidency QTSP' },
});
```

### `qualified` is operator-asserted, never inferred

The verifier reports `qualified` weight **only** when the supplied trust anchor is
flagged `qualified: true` — the operator's assertion that the key belongs to a
QTSP on an EU trusted list. The **identical** valid token, verified against a
non-qualified anchor, is reported as a plain `timestamp` and **never** as
carrying the Art. 41 presumption. This module makes **zero** network calls and
reads **no** trust list: it cannot, and does not, infer qualified status from the
token itself.

---

## 3. The anchor proof union is open

`AnchorProof` is a discriminated union (`ots | rfc3161 | <reserved: chain>`). A
third, **optional**, operator-gated on-chain witness (e.g. a Base anchor) is
reserved in the union but **not built here** (ADR operator decision 5). Leaving
the union open lets it land later without reshaping the verifier.

---

## 4. Re-implementability (no hidden canonicalization)

Both paths are dependency-free and auditable:

- the OTS reader/assembler is a plain walk of the documented `.ots` byte format;
- the RFC 3161 verifier is a plain DER TLV walk; the only "canonical" step is
  re-serializing the `signedAttrs` SET with its `[0] IMPLICIT` tag rewritten to
  the universal SET tag (`0x31`) — exactly as RFC 5652 §5.4 specifies, and
  documented inline at the call site.

An auditor can re-derive every byte the verifier checks, from the public
OpenTimestamps format spec, RFC 3161, and RFC 5652.

---

## Anchor posture, in one line

Anyone can **verify** an anchored receipt for free, forever, offline. **OTS is
live now** as a trust-minimized anchor; a **qualified eIDAS timestamp is a
drop-in** the moment the operator contracts a TSA vendor — surfaced, deferred,
and never silently overclaimed in the meantime.
