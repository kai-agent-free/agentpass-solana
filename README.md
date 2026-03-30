# AgentPass Solana — Credential Anchor Program

On-chain infrastructure for AI agent identity on Solana.

## What this does

1. **Credential Anchoring** — Store MVA Credential hashes on-chain as immutable proof
2. **Wallet-Passport Binding** — Cryptographically link Solana wallets to AgentPass identities
3. **On-chain Verification** — Other programs can verify agent credentials

## Architecture

```
┌──────────────┐     ┌───────────────────┐     ┌──────────────┐
│  AgentPass   │────▶│  Solana Program    │◀────│  Verifier    │
│  API Server  │     │  (Anchor)          │     │  (any dApp)  │
└──────────────┘     └───────────────────┘     └──────────────┘
                            │
                     ┌──────┴──────┐
                     │  Accounts:  │
                     │  - Passport │
                     │  - Credential│
                     │  - Registry │
                     └─────────────┘
```

## Accounts

### PassportAccount
- `passport_id`: AgentPass passport identifier
- `authority`: Solana wallet that controls this passport
- `credential_count`: Number of anchored credentials
- `created_at`: Unix timestamp
- `bump`: PDA bump

### CredentialAnchor
- `passport`: Reference to PassportAccount
- `credential_hash`: SHA-256 hash of the MVA Credential JSON
- `issuer`: Passport ID of the credential issuer
- `subject`: Passport ID of the credential subject
- `credential_type`: Type string (e.g., "capability", "endorsement")
- `anchored_at`: Unix timestamp
- `bump`: PDA bump

## Instructions

- `register_passport` — Link a Solana wallet to an AgentPass passport
- `anchor_credential` — Store a credential hash on-chain
- `verify_credential` — Check if a credential hash exists and is valid
- `revoke_credential` — Mark a credential as revoked

## Development

```bash
anchor build
anchor test
anchor deploy --provider.cluster devnet
```

## License

MIT
