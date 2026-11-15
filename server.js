// Proof Gatekeeper + Steal the VFY agent — @peros (agentgames.zkverify.io)
// Node.js, no framework. POST /agent, HMAC auth, preflight, deterministic
// decisions, Groth16 proofs via snarkjs.
// - Gatekeeper: trap checks + gatekeeper circuit (fullProve; inputs verified
//   2026-11-15, practice 2/2 correct, proof verified by platform).
// - Steal the VFY: EXTRACT min(10, opponentBalance) every turn (dominant
//   simple strategy: free, beats HOLD, ties EXTRACT, punishes FORTIFY);
//   HOLD only when the opponent is at 0. Proof via the vfy-policy circuit.
//   vfy-policy inputs (found by probing the compiled WASM, 2026-11-16):
//   17 total; 9 named: commitment, matchId, turnNumber, selfBalance,
//   opponentBalance, action, amount, circuitVersion, salt. The other 8
//   private inputs are unnamed in every public source and default to 0 in
//   the witness; snarkjs fullProve refuses a partial input, so the witness
//   is built directly through the circom_runtime calculator (bypassing its
//   all-inputs-set check) and proven with groth16.prove. Public signals:
//   [output(0), commitment, matchId, turnNumber, selfBalance,
//   opponentBalance, action, amount, circuitVersion]. The output stays 0
//   with the unknown inputs at 0 — the practice verdict is the oracle for
//   whether the platform accepts that.
// Env: AGENT_GAMES_HMAC_SECRET (dashboard Rotate Secret), PORT (default
// 3000). Secrets ONLY from env, never logged.
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { keccak256 } = require("js-sha3");
const { WitnessCalculatorBuilder } = require("circom_runtime");
const ff = require("ffjavascript");

const PORT = parseInt(process.env.PORT || "3000", 10);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const CIRCUIT_DIR = process.env.CIRCUIT_DIR || path.join(__dirname, "circuits");
const WASM = path.join(CIRCUIT_DIR, "gatekeeper.wasm");
const ZKEY = path.join(CIRCUIT_DIR, "gatekeeper_final.zkey");
const VFY_WASM = path.join(CIRCUIT_DIR, "vfy-policy.wasm");
const VFY_ZKEY = path.join(CIRCUIT_DIR, "vfy-policy_final.zkey");

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

// ---------- Steal the VFY ----------

// Circom 2 WASM resolves input signals by FNV-1a-64 of the name.
function fnv1a64(str) {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = (1n << 64n) - 1n;
  for (let i = 0; i < str.length; i++) { h ^= BigInt(str.charCodeAt(i)); h = (h * prime) & mask; }
  return h.toString(16).padStart(16, "0");
}

let vfyWc = null;
async function getVfyWc() {
  if (!vfyWc) {
    const wasmBuf = fs.readFileSync(VFY_WASM);
    vfyWc = await WitnessCalculatorBuilder(wasmBuf, { sanityCheck: false });
  }
  return vfyWc;
}

// Build the vfy-policy witness directly through the calculator, setting
// only the 9 known inputs (the other 8 default to 0). The JS wrapper's
// all-inputs-set check is skipped by calling the raw wasm exports, and the
// result is serialized to the .wtns binary format (copied from
// circom_runtime's calculateWTNSBin) so snarkjs.groth16.prove can read it.
async function vfyWtnsBin(fields) {
  const wc = await getVfyWc();
  const ex = wc.instance.exports;
  const n32 = ex.getFieldNumLen32();
  ex.getRawPrime();
  const arr = new Uint32Array(n32);
  for (let i = 0; i < n32; i++) arr[n32 - 1 - i] = ex.readSharedRWMemory(i);
  const prime = ff.Scalar.fromArray(arr, 0x100000000);
  function toArray32(v) {
    const a = new Array(n32).fill(0);
    let x = ((BigInt(v) % prime) + prime) % prime;
    for (let i = n32 - 1; i >= 0; i--) { a[i] = Number(x & 0xffffffffn); x >>= 32n; }
    return a;
  }
  function setInput(name, val) {
    const h = fnv1a64(name);
    const arrFr = toArray32(val);
    for (let j = 0; j < n32; j++) ex.writeSharedRWMemory(j, arrFr[n32 - 1 - j]);
    ex.setInputSignal(parseInt(h.slice(0, 8), 16), parseInt(h.slice(8, 16), 16), 0);
  }
  ex.init(1); // sanityCheck ON: the wasm asserts circuit constraints
  for (const [k, v] of Object.entries(fields)) setInput(k, v);
  const witnessSize = ex.getWitnessSize();
  const n8 = n32 * 4;
  const buff32 = new Uint32Array(witnessSize * n32 + n32 + 11);
  const buff = new Uint8Array(buff32.buffer);
  buff[0] = "w".charCodeAt(0);
  buff[1] = "t".charCodeAt(0);
  buff[2] = "n".charCodeAt(0);
  buff[3] = "s".charCodeAt(0);
  buff32[1] = 2; // version
  buff32[2] = 2; // number of sections
  buff32[3] = 1; // id section 1
  const idSection1length = 8 + n8;
  const idSection1lengthHex = idSection1length.toString(16);
  buff32[4] = parseInt(idSection1lengthHex.slice(0, 8), 16);
  buff32[5] = parseInt(idSection1lengthHex.slice(8, 16), 16);
  buff32[6] = n8;
  ex.getRawPrime();
  let pos = 7;
  for (let j = 0; j < n32; j++) buff32[pos + j] = ex.readSharedRWMemory(j);
  pos += n32;
  // witness size (nWitness, read by snarkjs from section 1)
  buff32[pos] = witnessSize;
  pos++;
  buff32[pos] = 2; // id section 2
  pos++;
  const idSection2length = n8 * witnessSize;
  const idSection2lengthHex = idSection2length.toString(16);
  buff32[pos] = parseInt(idSection2lengthHex.slice(0, 8), 16);
  buff32[pos + 1] = parseInt(idSection2lengthHex.slice(8, 16), 16);
  pos += 2;
  for (let i = 0; i < witnessSize; i++) {
    ex.getWitness(i);
    for (let j = 0; j < n32; j++) buff32[pos + j] = ex.readSharedRWMemory(j);
    pos += n32;
  }
  return buff;
}

const VFY_ACTION = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

function matchIdToField(matchId) {
  const hex = String(matchId || "").replace(/-/g, "");
  return (BigInt("0x" + (hex || "0")) % FIELD_P).toString();
}

// Optional audit pointer from the build guide: keccak256 of ABI-packed
// fields, each padded to 32 bytes big-endian.
function vfyPublicInputsHash(o) {
  const b32 = (v) => {
    const b = Buffer.alloc(32);
    let x = BigInt(v);
    for (let i = 31; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; }
    return b;
  };
  const packed = Buffer.concat([
    b32(o.commitment),
    b32(matchIdToField(o.matchId)),
    b32(o.turn),
    b32(o.selfBalance),
    b32(o.opponentBalance),
    b32(VFY_ACTION[o.actionType]),
    b32(o.amount),
    b32(1n), // circuitVersion "v1" -> 1
  ]);
  return "0x" + keccak256(packed);
}

async function generateVfyProof(o) {
  const fields = {
    commitment: (BigInt(o.commitment) % FIELD_P).toString(),
    matchId: matchIdToField(o.matchId),
    turnNumber: String(o.turn),
    selfBalance: String(o.selfBalance),
    opponentBalance: String(o.opponentBalance),
    action: VFY_ACTION[o.actionType].toString(),
    amount: String(o.amount),
    circuitVersion: "1",
    salt: "0",
  };
  const witness = await vfyWtnsBin(fields);
  const wtnsPath = path.join("/tmp", `vfy-${o.matchId}-t${o.turn}.wtns`);
  fs.writeFileSync(wtnsPath, Buffer.from(witness));
  try {
    const { proof, publicSignals } = await snarkjs.groth16.prove(VFY_ZKEY, wtnsPath);
    return { proof, public_signals: publicSignals };
  } finally {
    try { fs.unlinkSync(wtnsPath); } catch (_) {}
  }
}

// Steal strategy: EXTRACT min(10, opponentBalance) every turn; HOLD only
// when the opponent is at 0. EXTRACT is free and dominates HOLD/FORTIFY
// in every pairing (vs EXTRACT it nets 0, vs HOLD +10, vs FORTIFY +4).
function stealDecide(state) {
  const opp = BigInt(String(state.opponentBalance || "0"));
  if (opp <= 0n) return { type: "HOLD" };
  const amount = opp < 10n ? opp : 10n;
  return { type: "EXTRACT", amount: amount.toString() };
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

      // 3a. Steal the VFY turn (practice or competition).
      if (env.eventId === "steal-the-vfy") {
        const matchId = env.matchId || "";
        const turn = env.turn ?? 0;
        const state = env.state || {};
        const commitment = (env.strategyCommitment && env.strategyCommitment.hash) || "0";
        const action = stealDecide(state);
        const amount = action.type === "EXTRACT" ? action.amount : "0";
        let proof = null, public_signals = null;
        try {
          const r = await generateVfyProof({
            commitment, matchId, turn,
            selfBalance: state.selfBalance || "0",
            opponentBalance: state.opponentBalance || "0",
            actionType: action.type, amount,
          });
          proof = r.proof; public_signals = r.public_signals;
        } catch (e) {
          console.log(`[steal ${matchId} t${turn}] proof failed: ${e.message}`);
        }
        const outAction = action.type === "EXTRACT"
          ? { type: "EXTRACT", amount: action.amount }
          : { type: action.type };
        const out = {
          matchId, turn,
          action: outAction,
          policyProof: {
            circuitVersion: "v1",
            proof: proof || undefined,
            public_signals: public_signals || undefined,
            publicInputsHash: vfyPublicInputsHash({
              commitment, matchId, turn,
              selfBalance: state.selfBalance || "0",
              opponentBalance: state.opponentBalance || "0",
              actionType: action.type, amount,
            }),
          },
          agentTimestamp: new Date().toISOString(),
          idempotencyKey: `steal-vfy-${matchId}-turn-${turn}`,
        };
        console.log(`[${new Date().toISOString()}] steal ${matchId} t${turn} ${action.type} ${amount} ${Date.now() - started}ms proof=${!!proof} mode=${env.mode || "?"}`);
        return signResponse(res, out);
      }

      if (env.type !== "agent-games.proof-gatekeeper.v1") {
        res.writeHead(400, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "unknown type" }));
      }

      // 3b. Gatekeeper task (fail closed; 50s internal budget inside the 60s deadline).
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

server.listen(PORT, () => console.log(`gatekeeper+steal agent listening on :${PORT}`));
