# gatekeeper-agent

Proof Gatekeeper agent for the zkVerify Agent Games — competing as **@peros**.

The agent is a public HTTPS endpoint. The platform POSTs signed task
envelopes; the agent verifies the HMAC, runs deterministic trap checks, and
returns a decision plus its own Groth16 proof (generated locally with
snarkjs from the official gatekeeper circuit).

## How it works

1. `POST /agent` — HMAC-SHA256 over the raw body, checked against the
   `x-agent-games-signature` header **before** parsing JSON.
2. Preflight (`agent-games.preflight.v1`) → `{ ok: true, protocolVersion: "v1" }`, signed.
3. Task (`agent-games.proof-gatekeeper.v1`) → deterministic checks:
   `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `PROOF_REUSED` (local seen-set),
   `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`, else
   `VALID_CONDITION` → APPROVE. Fail closed: any uncertainty → REJECT.
4. Groth16 proof of the decision with the official circuit
   (`gatekeeper.wasm` + `gatekeeper_final.zkey`, vkHash
   `0x6b79c6…77b0`). `PROOF_REUSED` is unprovable by design → `proof: null`.
   The platform re-verifies the proof against its own registered key.
5. Every response is signed with `x-agent-games-signature` over the raw body.

## Run

```sh
npm install
# download the circuit artifacts into ./circuits/
curl -s https://agentgames.zkverify.io/circuits/gatekeeper.wasm -o circuits/gatekeeper.wasm
curl -s https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey -o circuits/gatekeeper_final.zkey
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (dashboard: Rotate Secret)
PORT=3000 node server.js
```

Expose it as public HTTPS (e.g. a Cloudflare Tunnel) and register the
endpoint URL in the Agent Games dashboard, then run preflight.

## Files

- `server.js` — the whole agent (endpoint, HMAC, decision logic, proving)
- `package.json` — deps (`snarkjs`, `js-sha3`)
- `circuits/` — not in git; downloaded from the official site (see above)
