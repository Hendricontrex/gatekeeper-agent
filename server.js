// Proof Gatekeeper agent — @peros (agentgames.zkverify.io)
// Node.js, no framework. POST /agent, HMAC auth, preflight, deterministic
// trap checks, Groth16 proof via snarkjs (witness mapping verified by
// local snarkjs runs against the official artifacts, 2026-11-15).
// Env: AGENT_GAMES_HMAC_SECRET (dashboard Rotate Secret), KURIER_API_KEY,
// PORT (default 3000). Secrets ONLY from env, never logged.
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { keccak256 } = require("js-sha3");

const PORT = parseInt(process.env.PORT || "3000", 10);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const CIRCUIT_DIR = process.env.CIRCUIT_DIR || path.join(__dirname, "circuits");
const WASM = path.join(CIRCUIT_DIR, "gatekeeper.wasm");
const ZKEY = path.join(CIRCUIT_DIR, "gatekeeper_final.zkey");

// bn128 scalar field prime (snarkjs reduces oversized inputs mod p anyway)
const FIELD_P = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

// proof_tx values already seen (persisted so restarts don't forget)
const SEEN_FILE = path.join(__dirname, "seen.json");
let seen = new Set();
try { seen = new Set(JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"))); } catch (_) {}
function markSeen(tx) {
  seen.add(tx);
  try { fs.writeFileSync(SEEN_FILE, JSON.stringify([...seen])); } catch (_) {}
}

function hmacHex(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}
function signResponse(res, bodyObj) {
  const raw = JSON.stringify(bodyObj);
  if (HMAC_SECRET) res.setHeader("x-agent-games-signature", hmacHex(HMAC_SECRET, Buffer.from(raw)));
  res.setHeader("content-type", "application/json");
  res.end(raw);
}
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

const REASONS = {
  VALID: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  THRESHOLD: "THRESHOLD_MISMATCH",
  REUSED: "PROOF_REUSED",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  AMOUNT: "AMOUNT_OVERFLOW",
};

// Deterministic trap checks, in trap-encyclopedia order.
// Fail closed: any uncertainty -> REJECT.
function decide(input) {
  const n = (v) => BigInt(String(v));
  try {
    if (String(input.proof_vk).toLowerCase() !== String(input.registered_vk).toLowerCase())
      return { decision: "REJECT", reason_code: REASONS.VK };
    if (n(input.public_balance) < n(input.minimum))
      return { decision: "REJECT", reason_code: REASONS.THRESHOLD };
    if (seen.has(String(input.proof_tx)))
      return { decision: "REJECT", reason_code: REASONS.REUSED };
    if (n(input.current_block) >= n(input.expiry_block))
      return { decision: "REJECT", reason_code: REASONS.EXPIRED };
    if (String(input.recipient).toLowerCase() !== String(input.condition_recipient).toLowerCase())
      return { decision: "REJECT", reason_code: REASONS.RECIPIENT };
    if (n(input.amount) > n(input.max_transfer))
      return { decision: "REJECT", reason_code: REASONS.AMOUNT };
    return { decision: "APPROVE", reason_code: REASONS.VALID };
  } catch (_) {
    return { decision: "REJECT", reason_code: "INVALID_INPUT" };
  }
}

// task_id is a string like "gk_8d31_..."; the circuit takes a field element.
// No source documents the derivation — first guess: keccak256(string) mod p.
// Practice Mode is the oracle: if practice rejects the proof, try another
// encoding (sha256 mod p, ...). Verified locally that fullProve + groth16
// verify succeed with this shape; only the platform's comparison is unknown.
function taskIdToField(taskId) {
  const h = keccak256(String(taskId || ""));
  return (BigInt("0x" + h) % FIELD_P).toString();
}

// Groth16 proof of the decision. Circuit enforces
// decision == AND(vk match, balance >= minimum, not expired,
// recipient match, amount <= max). PROOF_REUSED is unprovable by design
// (all on-chain checks pass but the correct decision is REJECT) -> null.
async function generateProof(input, decision, reasonCode) {
  if (reasonCode === REASONS.REUSED) return null;
  const witness = {
    registeredVkHash: String(input.registered_vk),
    proofVkHash: String(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: String(input.recipient),
    conditionRecipient: String(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: taskIdToField(input.task_id || ""),
    salt: "0",
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(witness, WASM, ZKEY);
  return { proof, public_signals: publicSignals };
}

const server = http.createServer((req, res) => {
  const started = Date.now();
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    try {
      if (req.method !== "POST" || req.url !== "/agent") {
        res.writeHead(404, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "not found" }));
      }
      // 1. Verify HMAC over the RAW body BEFORE parsing.
      const sig = req.headers["x-agent-games-signature"] || "";
      if (!HMAC_SECRET || !safeEqual(hmacHex(HMAC_SECRET, raw), sig)) {
        res.writeHead(401, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "bad signature" }));
      }
      const env = JSON.parse(raw.toString("utf8"));

      // 2. Preflight handshake.
      if (env.type === "agent-games.preflight.v1") {
        console.log(`[${new Date().toISOString()}] preflight nonce=${env.nonce}`);
        return signResponse(res, { ok: true, protocolVersion: "v1" });
      }
      if (env.type !== "agent-games.proof-gatekeeper.v1") {
        res.writeHead(400, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "unknown type" }));
      }

      // 3. Decide (fail closed; 50s internal budget inside the 60s deadline).
      const input = env.input || {};
      const taskId = env.task_id || "";
      const { decision, reason_code } = decide(input);
      markSeen(String(input.proof_tx || ""));
      let proof = null, public_signals = null;
      if (Date.now() - started < 50000) {
        try {
          const r = await generateProof({ ...input, task_id: taskId }, decision, reason_code);
          if (r) { proof = r.proof; public_signals = r.public_signals; }
        } catch (e) {
          console.log(`[${taskId}] proof failed: ${e.message}`);
        }
      }
      const out = { decision, reason_code, proof_tx: input.proof_tx };
      if (reason_code === REASONS.REUSED) out.proof = null;
      else if (proof) { out.proof = proof; out.public_signals = public_signals; }
      console.log(`[${new Date().toISOString()}] ${taskId} ${decision} ${reason_code} ${Date.now() - started}ms proof=${!!proof}`);
      return signResponse(res, out);
    } catch (e) {
      console.log("handler error:", e.message);
      res.writeHead(400, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "bad request" }));
    }
  });
});

server.listen(PORT, () => console.log(`gatekeeper agent listening on :${PORT}`));
