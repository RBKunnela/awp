/**
 * @module schema/witness-record
 *
 * The canonical, OPEN WitnessRecord v0.1 data definition: TypeScript types plus
 * a Zod runtime validator. This file mirrors AWP spec §4 verbatim (the
 * predicate `profile | deployment | intent | authorization | artifacts |
 * verifications | chain | erasure_events`) and is the single source of truth
 * every later story and every producer imports.
 *
 * Scope of AW-1: the typed record and its *structural* constraints only — no
 * signing, no Merkle, no anchoring (those are AW-2/AW-4/AW-5). The DSSE/in-toto
 * envelope that wraps this predicate is described here only as documented
 * constants ({@link PREDICATE_TYPE}, {@link STATEMENT_TYPE}, {@link PAYLOAD_TYPE})
 * so the wrapping story has a stable reference; this file does not build it.
 *
 * Honesty boundary (enforced by the types, not merely documented):
 *  - `verifications[].claim_class` is a closed enum — `integrity-since-witness`
 *    ≠ `verified-against` ≠ `asserted-by`. A record cannot grammatically claim
 *    authenticity-at-origin or identity-proofing.
 *  - `authorization.credential.assurance_echo` is an opaque ECHOED string. AWP
 *    never asserts an assurance level; it only repeats what an issuer stated.
 *  - PII-bearing artifacts may not use a plain `sha256` digest — see
 *    {@link ArtifactDigest} and the profile/record validators.
 *
 * Canonical-JSON expectation (documented rule the schema relies on, NOT
 * implemented here): any hashing or signing of this record uses recursive
 * key-sorted JSON. The reusable `sortObjectKeys` implementation is introduced
 * in AW-2 where signing actually happens; AW-1 only declares the expectation.
 *
 * Dependencies: `zod` (runtime validation).
 * Used by: `./profiles` (profile constraint checks), `./index` (barrel),
 *          later producer/verifier stories, and `paybot`'s emitter (which
 *          imports this package — it is never imported FROM here).
 */

import { z } from 'zod';

/**
 * in-toto Statement `_type` for the envelope payload that carries a
 * WitnessRecord. The record predicate rides inside an in-toto Statement v1
 * (AWP spec §4). Defined here as a stable reference for the AW-2 envelope
 * story; AW-1 does not construct the Statement.
 */
export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1' as const;

/**
 * DSSE `payloadType` for the wrapped Statement (AWP spec §4). Reference
 * constant only — the DSSE envelope itself is AW-2.
 */
export const PAYLOAD_TYPE = 'application/vnd.in-toto+json' as const;

/**
 * AWP predicate namespace (interim production host — not `.dev`).
 *
 * Live document (Cloudflare Worker + DNS on operator-owned zone):
 *   `https://awp.paybotfin.com/witness-record/v1`
 * Schema:
 *   `https://awp.paybotfin.com/witness-record/v1/schema.json`
 *
 * Apex alias also served: `https://paybotfin.com/witness-record/v1`
 * Why not `.dev`: many enterprise networks block or distrust `.dev` TLDs.
 * DNS for `awp.paybotfin.com` was created via Maia (Hetzner) + vault
 * Cloudflare-all (2026-07-21).
 *
 * Schema `$id` is the same URI with `/schema.json` suffix.
 */
export const PREDICATE_TYPE = 'https://awp.paybotfin.com/witness-record/v1' as const;

/** Lowercase 64-char hex SHA-256, the only digest representation AWP accepts. */
const SHA256_HEX = /^[a-f0-9]{64}$/;

/** RFC 3339 / ISO-8601 timestamp (the subset the kernel already emits). */
const sha256Hex = z
  .string()
  .regex(SHA256_HEX, 'must be lowercase 64-char hex SHA-256');

const rfc3339 = z
  .string()
  .datetime({ offset: true })
  .describe('RFC 3339 timestamp');

// ---------------------------------------------------------------------------
// Honesty boundary — the closed enums that make overclaim unrepresentable.
// ---------------------------------------------------------------------------

/**
 * The four record profiles. A profile is a CONSTRAINT SET over one schema, not
 * a separate schema (AWP spec §4): it selects which optional blocks become
 * required. See `./profiles` for the constraints.
 */
export const PROFILES = ['pay', 'doc', 'principal', 'composite'] as const;
export type Profile = (typeof PROFILES)[number];

/**
 * The claim-class enum — the typed honesty boundary (AWP spec §4, line
 * `claim_class`). Every verification entry MUST carry exactly one:
 *
 *  - `integrity-since-witness` — the witness proves only that the referenced
 *    material is unaltered since it was witnessed. The weakest, always-true-of-
 *    AWP claim. Says nothing about origin or truth.
 *  - `verified-against` — the witness checked the material against a named
 *    issuer's keys/trust anchor and it verified. Attributes authenticity to the
 *    ISSUER, never to AWP.
 *  - `asserted-by` — the witness is merely recording a claim some issuer made,
 *    without itself verifying it. The honest "we were told" class.
 *
 * There is deliberately NO value for "authenticity-at-origin" or
 * "identity-proofing": those claims are not representable.
 */
export const CLAIM_CLASSES = [
  'integrity-since-witness',
  'verified-against',
  'asserted-by',
] as const;
export type ClaimClass = (typeof CLAIM_CLASSES)[number];

/** Credential types AWP can CONSUME (AWP spec §4 `authorization.credential.type`). */
export const CREDENTIAL_TYPES = [
  'oidc',
  'saml',
  'webauthn',
  'openid4vp',
  'sd-jwt-vc',
  'mdoc',
  'ap2-mandate',
] as const;
export type CredentialType = (typeof CREDENTIAL_TYPES)[number];

/**
 * Credential types that count as a "mandate-class" credential for the `pay`
 * profile (AWP spec §4 profiles: "a mandate-class credential"). AP2 mandates are
 * the canonical payment-authorization artifact; SD-JWT VC presentations carry
 * mandates in the EUDI path.
 */
export const MANDATE_CLASS_CREDENTIAL_TYPES = ['ap2-mandate', 'sd-jwt-vc'] as const;
export type MandateClassCredentialType = (typeof MANDATE_CLASS_CREDENTIAL_TYPES)[number];

/** Digest algorithms. `hmac-sha256` is REQUIRED for PII-bearing content (GDPR §7). */
export const DIGEST_ALGS = ['sha256', 'hmac-sha256'] as const;
export type DigestAlg = (typeof DIGEST_ALGS)[number];

// ---------------------------------------------------------------------------
// Block schemas (Zod) — each mirrors one block of AWP spec §4.
// ---------------------------------------------------------------------------

/** `deployment.software` — AI Act Art. 12 system identity + version. */
const SoftwareSchema = z
  .object({
    name: z.string().min(1),
    version: z.string().min(1),
  })
  .strict();

/**
 * `deployment` block — which deployment's log and key witnessed this record.
 * `node_key_fpr` is the customer-held Ed25519 fingerprint; AWP-the-company holds
 * nothing.
 */
const DeploymentSchema = z
  .object({
    log_id: z.string().min(1).describe('origin string of this deployment log'),
    node_key_fpr: z.string().min(1).describe('Ed25519 fingerprint — customer key'),
    software: SoftwareSchema,
  })
  .strict();

/** `intent.agent` — who acted. Opaque references only; never raw PII. */
const AgentSchema = z
  .object({
    agent_id: z.string().min(1),
    agent_key_fpr: z.string().min(1),
    runtime_ref: z.string().min(1),
  })
  .strict();

/** `intent.policy` — the governance decision recorded with the intent. */
const PolicySchema = z
  .object({
    policy_id: z.string().min(1),
    policy_hash: sha256Hex,
    decision: z.enum(['allow', 'deny', 'escalate']),
  })
  .strict();

/**
 * `intent` block — FROM THE KERNEL, semantics unchanged (AWP spec §4). Field
 * names align with `paybot`'s `ActionIntent` kernel: `action` (the verb),
 * `target_ref`, `params_hash`, start/end timestamps, and the policy decision.
 */
const IntentSchema = z
  .object({
    agent: AgentSchema,
    action: z.string().min(1).describe('verb, e.g. payment.refund | doc.generate'),
    target_ref: z.string().min(1).describe('opaque customer ref'),
    params_hash: sha256Hex,
    started_at: rfc3339,
    ended_at: rfc3339,
    policy: PolicySchema,
  })
  .strict();

/**
 * `authorization.credential.challenge_binding` — the WebAuthn path (PSD2
 * dynamic-linking shape). One of the two intent-binding mechanisms the
 * `principal` profile requires.
 */
const ChallengeBindingSchema = z
  .object({
    challenge: z.string().min(1).describe('H(canonical_intent) || server_nonce'),
    canonicalization: z.string().min(1).describe('versioned scheme id'),
    evidence_hash: sha256Hex,
    display_mechanism: z.enum(['none', 'spc', 'customer-ui-asserted']),
  })
  .strict();

/**
 * `authorization.credential.presentation_binding` — the OpenID4VP path. The
 * verifier-generated `nonce` is the linchpin (freshness + audience). One of the
 * two intent-binding mechanisms the `principal` profile requires.
 */
const PresentationBindingSchema = z
  .object({
    nonce: z.string().min(1).describe('verifier-generated — freshness + audience'),
    aud: z.string().min(1).describe('verifier id'),
    sd_hash: sha256Hex,
    transaction_data_hashes: z.array(sha256Hex),
  })
  .strict();

/** `authorization.credential.status_check` — revocation/status lookup result. */
const StatusCheckSchema = z
  .object({
    method: z.enum(['bitstring', 'token-status-list']),
    result: z.string().min(1),
    checked_at: rfc3339,
  })
  .strict();

/**
 * `authorization.credential` — the verification receipt for one externally
 * issued credential (no standard exists for this shape; AWP defines it).
 *
 * `assurance_echo` is an OPTIONAL, OPAQUE string ECHOED from the issuer. It is
 * the honesty boundary at the field level: AWP repeats an issuer's stated
 * assurance, it never asserts identity proofing.
 */
const CredentialSchema = z
  .object({
    type: z.enum(CREDENTIAL_TYPES),
    issuer: z.string().min(1).describe('iss / DID / IdP entity id'),
    assertion_hash: sha256Hex.describe('sha256 of raw assertion; assertion stays in customer systems'),
    challenge_binding: ChallengeBindingSchema.optional(),
    presentation_binding: PresentationBindingSchema.optional(),
    status_check: StatusCheckSchema.optional(),
    trust_anchor: z.string().min(1).describe('trust list / jwks_uri / x5c ref + retrieval time'),
    verified: z.boolean(),
    assurance_echo: z
      .string()
      .optional()
      .describe('e.g. "eIDAS-high" — ECHOED from issuer, never asserted by AWP'),
    verifier_policy_version: z.string().min(1),
  })
  .strict();

/**
 * `authorization` block — who authorized the intent and what was verified about
 * their credential. `principal_ref` is pseudonymous, customer-resolvable only.
 */
const AuthorizationSchema = z
  .object({
    principal_ref: z.string().min(1).describe('pseudonymous, customer-resolvable only'),
    credential: CredentialSchema,
  })
  .strict();

/**
 * `artifacts[].digest` — content addressed by hash, never by value.
 *
 * THE PII RULE (AWP spec §4 / AC4): when an artifact is PII-bearing, a plain
 * `sha256` digest is forbidden (a hash of low-entropy PII is reversible —
 * CJEU C-413/23 P, EDPB 02/2025). It MUST use `hmac-sha256` with a customer-held
 * `key_ref`; destroying that key is GDPR erasure. The structural rule is
 * enforced by a refinement so the wrong combination cannot validate.
 */
const ArtifactDigestSchema = z
  .object({
    alg: z.enum(DIGEST_ALGS),
    value: sha256Hex,
    key_ref: z.string().min(1).optional().describe('customer-held key id, required when hmac'),
  })
  .strict()
  .refine((d) => d.alg !== 'hmac-sha256' || typeof d.key_ref === 'string', {
    message: 'hmac-sha256 digest requires a key_ref',
    path: ['key_ref'],
  });

/** One attributed provenance claim on an artifact — pass-through, never warranted. */
const OriginClaimSchema = z
  .object({
    claim: z.string().min(1),
    asserted_by: z.string().min(1).describe('issuer'),
    verified: z.boolean(),
  })
  .strict();

/** `artifacts[].provenance` — C2PA pass-through; AWP attributes, never warrants. */
const ProvenanceSchema = z
  .object({
    c2pa_manifest_hash: sha256Hex.nullable(),
    c2pa_validation: z.enum(['pass', 'fail', 'absent']),
    origin_claims: z.array(OriginClaimSchema),
  })
  .strict();

/**
 * `artifacts[]` entry — one input or output, addressed by hash.
 *
 * `pii_bearing` is an AWP schema flag (not in the raw spec YAML, which states
 * the rule in prose) that makes AC4 enforceable at validation time: when true,
 * the digest MUST be `hmac-sha256`. It defaults to `false`.
 */
const ArtifactSchema = z
  .object({
    role: z.enum(['input', 'output']),
    digest: ArtifactDigestSchema,
    media_type: z.string().min(1),
    size: z.number().int().nonnegative(),
    pii_bearing: z
      .boolean()
      .default(false)
      .describe('when true, digest.alg MUST be hmac-sha256 (GDPR §7)'),
    provenance: ProvenanceSchema.optional(),
  })
  .strict()
  .refine((a) => !a.pii_bearing || a.digest.alg === 'hmac-sha256', {
    message: 'PII-bearing artifact must use hmac-sha256 digest (plain sha256 forbidden)',
    path: ['digest', 'alg'],
  });

/**
 * `verifications[]` entry — the witness's OWN testimony about one thing it
 * checked. Each entry is TYPED by `claim_class` (the honesty boundary).
 */
const VerificationSchema = z
  .object({
    check: z.string().min(1).describe('e.g. ap2.checkout_mandate.sd_jwt_signature'),
    subject_hash: sha256Hex,
    issuer: z.string().min(1).describe('whose material'),
    method: z.string().min(1).describe('how keys were obtained'),
    result: z.enum(['pass', 'fail', 'unverifiable']),
    claim_class: z.enum(CLAIM_CLASSES),
  })
  .strict();

/** `chain` block — the kernel per-record hash chain, retained inside the record. */
const ChainSchema = z
  .object({
    prev_record_hash: sha256Hex,
  })
  .strict();

/** `erasure_events[]` entry — key destruction is itself witnessed (GDPR). */
const ErasureEventSchema = z
  .object({
    artifact_ref: z.string().min(1),
    key_ref: z.string().min(1),
    destroyed_at: rfc3339,
    requested_by_ref: z.string().min(1),
  })
  .strict();

/**
 * The full WitnessRecord v0.1 predicate (AWP spec §4). Optional blocks are
 * optional at the SCHEMA level; the per-profile minimums are enforced
 * separately by `validateProfile` in `./profiles` (profiles are constraints,
 * not schemas). `deployment`, `intent`, and `chain` are always required.
 */
export const WitnessRecordSchema = z
  .object({
    profile: z.enum(PROFILES),
    deployment: DeploymentSchema,
    intent: IntentSchema,
    authorization: AuthorizationSchema.optional(),
    artifacts: z.array(ArtifactSchema).optional(),
    verifications: z.array(VerificationSchema).optional(),
    chain: ChainSchema,
    erasure_events: z.array(ErasureEventSchema).optional(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Inferred types — the public TypeScript surface.
// ---------------------------------------------------------------------------

/** `deployment.software` — system identity + version. */
export type Software = z.infer<typeof SoftwareSchema>;
/** `deployment` block. */
export type Deployment = z.infer<typeof DeploymentSchema>;
/** `intent.agent` block. */
export type Agent = z.infer<typeof AgentSchema>;
/** `intent.policy` block. */
export type Policy = z.infer<typeof PolicySchema>;
/** `intent` block (from the kernel ActionIntent, semantics unchanged). */
export type Intent = z.infer<typeof IntentSchema>;
/** `authorization.credential.challenge_binding` (WebAuthn path). */
export type ChallengeBinding = z.infer<typeof ChallengeBindingSchema>;
/** `authorization.credential.presentation_binding` (OpenID4VP path). */
export type PresentationBinding = z.infer<typeof PresentationBindingSchema>;
/** `authorization.credential.status_check`. */
export type StatusCheck = z.infer<typeof StatusCheckSchema>;
/** `authorization.credential` — one credential verification receipt. */
export type Credential = z.infer<typeof CredentialSchema>;
/** `authorization` block. */
export type Authorization = z.infer<typeof AuthorizationSchema>;
/** `artifacts[].digest`. */
export type ArtifactDigest = z.infer<typeof ArtifactDigestSchema>;
/** `artifacts[].provenance.origin_claims[]`. */
export type OriginClaim = z.infer<typeof OriginClaimSchema>;
/** `artifacts[].provenance`. */
export type Provenance = z.infer<typeof ProvenanceSchema>;
/** `artifacts[]` entry. */
export type Artifact = z.infer<typeof ArtifactSchema>;
/** `verifications[]` entry — the witness's typed testimony. */
export type Verification = z.infer<typeof VerificationSchema>;
/** `chain` block. */
export type Chain = z.infer<typeof ChainSchema>;
/** `erasure_events[]` entry. */
export type ErasureEvent = z.infer<typeof ErasureEventSchema>;
/** The full WitnessRecord v0.1 predicate. */
export type WitnessRecord = z.infer<typeof WitnessRecordSchema>;

/**
 * A discriminated result for {@link validateWitnessRecord}: either the parsed,
 * typed record or a flat list of human-readable validation errors. Returning a
 * result (never throwing) keeps producers and verifiers fail-closed by
 * inspection rather than by exception handling.
 */
export type WitnessRecordResult =
  | { ok: true; record: WitnessRecord }
  | { ok: false; errors: string[] };

/**
 * Validate an unknown value as a WitnessRecord v0.1 against the schema's
 * STRUCTURAL rules (shape, field types, digest/PII rule, claim-class enum).
 *
 * This does NOT check per-profile minimums — call {@link validateProfile} from
 * `./profiles` for that. The two-step split mirrors the spec: one schema, with
 * profiles layered as constraints on top.
 *
 * @param input - The candidate value (e.g. parsed JSON) to validate.
 * @returns `{ ok: true, record }` when valid, else `{ ok: false, errors }`
 *          with one `path: message` string per violation. Never throws on
 *          invalid input.
 *
 * @example
 * const r = validateWitnessRecord(JSON.parse(raw));
 * if (!r.ok) throw new Error(r.errors.join('; '));
 * // r.record is a fully-typed WitnessRecord
 */
export function validateWitnessRecord(input: unknown): WitnessRecordResult {
  const parsed = WitnessRecordSchema.safeParse(input);
  if (parsed.success) {
    return { ok: true, record: parsed.data };
  }
  const errors = parsed.error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join('.') : '(root)';
    return `${path}: ${issue.message}`;
  });
  return { ok: false, errors };
}

/**
 * Type guard: true when `input` is a structurally-valid WitnessRecord.
 *
 * @param input - The candidate value.
 * @returns Whether `input` satisfies the WitnessRecord schema.
 *
 * @example
 * if (isWitnessRecord(x)) { x.profile; /* narrowed *\/ }
 */
export function isWitnessRecord(input: unknown): input is WitnessRecord {
  return WitnessRecordSchema.safeParse(input).success;
}
