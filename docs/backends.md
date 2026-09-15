# Signing backends

`solana-keychain-sign` signs Solana transactions via a pluggable backend
selected by the `backend` config key. Three backends ship; **only Vault is
fully working in v0**. AWS KMS and GCP KMS are stubbed (return `NotImplemented`)
with hand-roll plans documented below so operators can budget the v1 work.

| Backend       | v0 status                          | Key location                                          | Auth model                                                                                   | Recommended for                                                               |
| ------------- | ---------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| **`vault`**   | ✅ Fully working                   | HashiCorp Vault transit (dev or HA cluster)           | `X-Vault-Token` header                                                                       | **Getting started**, small-to-mid deployments, any shop already running Vault |
| **`aws_kms`** | 🚧 Stub (returns `NotImplemented`) | AWS Key Management Service (regional, FIPS-validated) | SigV4 (hand-rolled ~300 LOC pure Rust, planned v1)                                           | **Production at scale**, HIPAA/FedRAMP workloads, shops already on AWS        |
| **`gcp_kms`** | 🚧 Stub (returns `NotImplemented`) | Google Cloud Key Management Service (regional)        | OAuth2 access token (from `gcloud auth print-access-token` in v1; service-account JWT in v2) | **Shops already on GCP**, integrations that already use Cloud KMS             |

**v0 recommendation:** start with Vault (the Quickstart ships a one-command
dev-mode compose). Plan the KMS migration when you outgrow it.

---

## Vault (transit engine)

The session key is an ed25519 key created inside Vault's `transit/` engine.
The private key **never leaves Vault** — the plugin POSTs message bytes to
`POST /v1/transit/sign/{key}` and receives only the signature.

### Config keys

```toml
[plugins.entries.solana-keychain-sign.config]
backend        = "vault"
signer_pubkey  = "<base58 from vault-init.sh>"   # must match build-tx
rpc_url        = "https://api.devnet.solana.com"

[plugins.entries.solana-keychain-sign.config.vault]
vault_addr     = "http://localhost:8200"
vault_token    = "root"                           # dev only; prod: short-lived token
vault_key_name = "solana-session"
```

### Getting started (5 minutes)

```bash
docker compose -f docker/vault-dev-compose.yml up -d
eval "$(bash docker/vault-init.sh)"   # exports VAULT_ADDR / TOKEN / KEY_NAME / PUBKEY
```

Then set the four config keys from the printed env vars. See
[`docker/session-wallet-setup.md`](./session-wallet-setup.md) for funding the
on-chain session wallet.

### Cost model

- **Dev mode** (`docker compose`): free, in-memory, fixed root token. Data is
  lost on container restart.
- **Production**: Vault OSS cluster (3+ nodes, raft storage, auto-unseal) or
  HCP Vault. Rough cost: 3 VMs × your region's `t3.small`-equivalent, plus
  ops time for upgrades/backup testing. HCP Vault dev tier starts around
  $0.10/hour.

### Security properties

- Private key is non-exportable (`exportable=false`) with no plaintext backup
  (`allow_plaintext_backup=false`) — enforced by `docker/vault-init.sh`.
- Every sign call is auditable in Vault's audit log (enable with
  `vault audit enable file file_path=/var/log/vault/audit.log`).
- Rotate the key without rekeying the chain: create a new transit key, drain
  the old session wallet to the new pubkey, update config. See
  [`session-wallet-setup.md`](./session-wallet-setup.md) §6.

### v0 limitations

- Token auth only. AppRole / Kubernetes auth / AWS IAM auth land in v1 (the
  plugin just needs the token string; auth-method plumbing is host-side).
- No auto-renew of the token. Operators must provision a long-enough TTL or
  rotate before expiry.

---

## AWS KMS (asymmetric ed25519 signing) — STUB in v0

**Status:** returns `NotImplemented` from `AwsKmsClient::sign_message`. All
config keys parse and validate; no HTTP egress. Ships so operators can wire
config now and flip the backend when v1 lands.

### Config keys

```toml
[plugins.entries.solana-keychain-sign.config]
backend        = "aws_kms"
signer_pubkey  = "<base58 ed25519 pubkey derived from the KMS public key>"
rpc_url        = "https://api.mainnet-beta.solana.com"

[plugins.entries.solana-keychain-sign.config.aws_kms]
arn               = "arn:aws:kms:us-east-1:123456789012:key/abc123-def456-..."
region            = "us-east-1"
access_key_id     = "AKIA..."                     # prefer IAM role in production
secret_access_key = "..."                         # never commit; use env or secrets manager
```

### Provisioning (for when v1 ships)

```bash
# Create an asymmetric ed25519 signing key in KMS.
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_ED25519 \
  --description "ZeroClaw Solana session signing key"

# Fetch the public key and convert to Solana base58.
aws kms get-public-key --key-id <key-id> \
  --output text --query PublicKey | base64 --decode | <to-base58>
```

### Cost model (for budgeting, not billed in v0)

- $1.00 per key per month.
- $0.03 per 10,000 sign requests (varies slightly by region).
- No data transfer charge within the same region.

### v1 plan: SigV4 in pure Rust (~300 LOC)

The signer posts to `https://kms.<region>.amazonaws.com/` with the
`Sign` operation. Signing the request requires AWS Signature Version 4
(SigV4), which is ~300 LOC of pure Rust (canonical request → string-to-sign
→ HMAC-SHA256 signing key chain). No new crate deps — `sha2` + `hmac` +
`hex` cover it. Plan:

1. `aws_kms.rs::sign_request()` — builds the canonical request, computes the
   SigV4 signature, attaches the `Authorization` header.
2. POST `Action=Sign&Version=2014-11-01` with the message bytes
   (base64-encoded) and `SigningAlgorithm = ED25519`.
3. Parse the `Signature` from the response, verify length (64 bytes), return.

The hand-roll is needed because the WASM target bans `rusoto_core` /
`aws-sdk-rust` (they pull in `tokio` + `hyper`). No new deps; no std-only
code.

### Security properties (once v1 ships)

- Private key never leaves AWS KMS (FIPS 140-2 validated HSM backing in
  `aws-cloudhsm` mode).
- IAM policy scopes sign-only (no `Decrypt`, no `GetPublicKey` for
  unauthorized roles).
- CloudTrail logs every `Sign` call with the caller identity.

---

## GCP KMS (Cloud Key Management Service) — STUB in v0

**Status:** returns `NotImplemented` from `GcpKmsClient::sign_message`. All
config keys parse and validate; no HTTP egress.

### Config keys

```toml
[plugins.entries.solana-keychain-sign.config]
backend        = "gcp_kms"
signer_pubkey  = "<base58 ed25519 pubkey derived from the Cloud KMS public key>"
rpc_url        = "https://api.mainnet-beta.solana.com"

[plugins.entries.solana-keychain-sign.config.gcp_kms]
key_version_name = "projects/x/locations/global/keyRings/y/cryptoKeys/z/cryptoKeyVersions/1"
access_token     = "ya29..."                      # from: gcloud auth print-access-token
```

### Provisioning (for when v1 ships)

```bash
# Create a key ring + ed25519 key.
gcloud kms keyrings create zeroclaw --location global
gcloud kms keys create solana-session \
  --keyring zeroclaw --location global --purpose asymmetric-signing \
  --default-algorithm ec-sign-ed25519

# Get the public key, convert DER → raw 32 bytes → base58.
gcloud kms keys versions get-public-key 1 \
  --key solana-session --keyring zeroclaw --location global \
  --format="value(pem)" | <pem-to-base58>
```

### Cost model (for budgeting, not billed in v0)

- $1.00 per active key version per month.
- $0.03 per 10,000 sign operations.
- Free tier: first $10,000 of Cloud KMS spend waived per month for
  billing-enabled projects.

### v1 plan: OAuth2 bearer token

The signer posts to
`https://cloudkms.googleapis.com/v1/{key_version_name}:asymmetricSign` with
`Authorization: Bearer <access_token>`. The token comes from
`gcloud auth print-access-token` (operator-pasted in v1) or a service-account
JWT (v2). The only Rust code is:

1. `gcp_kms.rs::sign_request()` — set the bearer header.
2. POST the digest (base64), parse the `signature` from the JSON response.
3. Done — no SigV4-style signing chain needed because Google auth is
   stateless bearer.

This is ~50 LOC simpler than AWS SigV4; it's stubbed in v0 only because the
plugin needs the HTTP plumbing (`waki`) wired into the backend trait first,
and that's the same plumbing the Vault backend uses.

### Security properties (once v1 ships)

- Private key never leaves Cloud KMS (FIPS 140-2 Level 3 HSM backing).
- IAM `roles/cloudkms.signerVerifier` scopes the caller to sign-only.
- Audit logs land in Cloud Logging automatically.

---

## Switching backends

Change `backend` and the matching subtable. The `signer_pubkey` will differ
between backends (different key, different on-chain account), so you must:

1. Create the new backend's key.
2. Fund the new session wallet (see
   [`docker/session-wallet-setup.md`](./session-wallet-setup.md)).
3. Update BOTH plugins' `signer_pubkey` to match the new key's pubkey:

```bash
zeroclaw config set plugins.entries.solana-build-tx.config.signer_pubkey <NEW_PUBKEY>
zeroclaw config set plugins.entries.solana-keychain-sign.config.signer_pubkey <NEW_PUBKEY>
zeroclaw config set plugins.entries.solana-keychain-sign.config.backend <vault|aws_kms|gcp_kms>
```

4. Drain the old session wallet to the new one (or keep it empty for audit).

The `signer_pubkey` match is the defense-in-depth check — if the two plugins
disagree, every message is rejected at the signer's envelope guard with
`fee_payer mismatch`.

## Recommendation summary

| If you are…                                     | Use                                               | Why                                                                        |
| ----------------------------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------- |
| Evaluating the bounty, following the Quickstart | **Vault**                                         | One `docker compose up`, zero cloud accounts, zero cost.                   |
| Running in production at scale on AWS           | **AWS KMS** (v1)                                  | FIPS-validated, IAM-scoped, CloudTrail-audited, no extra infra to operate. |
| Running in production on GCP                    | **GCP KMS** (v1)                                  | Same properties as AWS KMS, integrated with your existing IAM and logging. |
| A small team with no cloud account              | **Vault** (HA cluster)                            | OSS, self-hosted, no per-call cost; your ops cost is the cluster.          |
| Needing FIPS 140-2 Level 3                      | **AWS KMS** with CloudHSM backing, or **GCP KMS** | Both offer HSM-backed key stores; Vault dev mode does not.                 |
