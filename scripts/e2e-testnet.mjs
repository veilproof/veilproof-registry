// Run the whole credential flow against the deployed testnet registry, proving
// with the WebAssembly prover the dashboard ships, and report each step.
//
//   node scripts/e2e-testnet.mjs <veilproof_prover.wasm> <pk.bin> <vk.bin>
//
// It also runs the two attacks the system claims to stop, and fails unless the
// contract refuses each one with the expected error.

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Address, nativeToScVal, scValToNative } from "@stellar/stellar-sdk";

import { bytes, fundedKeypair, invoke, read, struct } from "./lib.mjs";

const [wasmPath, pkPath, vkPath] = process.argv.slice(2);
if (!vkPath) throw new Error("usage: e2e-testnet.mjs <prover.wasm> <pk.bin> <vk.bin>");

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { contractId, circuit } = JSON.parse(
  readFileSync(join(root, "deployments/testnet.json"), "utf8"),
);

// --- the prover, driven the way the browser drives it ----------------------

const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), {});
const vp = instance.exports;

function put(data) {
  const ptr = vp.vp_alloc(data.length);
  new Uint8Array(vp.memory.buffer, ptr, data.length).set(data);
  return ptr;
}

function call(request) {
  const input = Buffer.from(JSON.stringify(request));
  const ptr = put(input);
  vp.vp_call(ptr, input.length);
  vp.vp_free(ptr, input.length);
  const output = new Uint8Array(vp.memory.buffer, vp.vp_result_ptr(), vp.vp_result_len());
  const answer = JSON.parse(Buffer.from(output).toString());
  if (answer.error) throw new Error(answer.error);
  return answer;
}

function loadKeys() {
  const pk = readFileSync(pkPath);
  const vk = readFileSync(vkPath);
  const started = performance.now();
  if (vp.vp_load_keys(put(pk), pk.length, put(vk), vk.length) !== 1) {
    throw new Error("the prover rejected the keys");
  }
  console.log(`keys loaded in ${Math.round(performance.now() - started)} ms`);
}

const seed = () => randomBytes(32).toString("hex");

// --- the flow --------------------------------------------------------------

const symbol = (value) => nativeToScVal(value, { type: "symbol" });
const address = (keypair) => new Address(keypair.publicKey()).toScVal();
const proofArg = ({ a, b, c }) => struct({ a: bytes(a), b: bytes(b), c: bytes(c) });

async function expectContractError(label, code, attempt) {
  try {
    await attempt();
  } catch (error) {
    if (String(error.message ?? error).includes(`Error(Contract, #${code})`)) {
      console.log(`  ${label}: refused with #${code}, as it should be`);
      return;
    }
    throw error;
  }
  throw new Error(`${label}: the contract accepted it`);
}

loadKeys();

const credential = `e2e${randomBytes(6).toString("hex")}`;
console.log(`contract   ${contractId}`);
console.log(`credential ${credential}`);

const [issuer, holder, thief] = await Promise.all([
  fundedKeypair(),
  fundedKeypair(),
  fundedKeypair(),
]);

const member = call({ op: "new_secret", seed: seed() });
const others = [1, 2, 3].map(() => call({ op: "new_secret", seed: seed() }).commitment);
const leaves = [others[0], member.commitment, others[1], others[2]];
const { root: merkleRoot } = call({ op: "root", leaves });

const claimed = await invoke(
  issuer,
  contractId,
  "claim_credential",
  address(issuer),
  symbol(credential),
  symbol(circuit),
);
console.log(`claim_credential  ${claimed.hash}`);

const published = await invoke(
  issuer,
  contractId,
  "publish_root",
  address(issuer),
  symbol(credential),
  bytes(merkleRoot),
);
console.log(`publish_root      ${published.hash}`);

const started = performance.now();
const proof = call({
  op: "prove",
  leaves,
  secret: member.secret,
  holder: holder.publicKey(),
  seed: seed(),
});
console.log(`proved in ${Math.round(performance.now() - started)} ms, in WebAssembly`);

if (proof.root !== merkleRoot) throw new Error("the proof is not against the published root");

await expectContractError("stolen proof, other address", 7, () =>
  invoke(
    thief,
    contractId,
    "verify_credential",
    address(thief),
    symbol(credential),
    proofArg(proof.proof),
    bytes(proof.nullifier),
  ),
);

const verified = await invoke(
  holder,
  contractId,
  "verify_credential",
  address(holder),
  symbol(credential),
  proofArg(proof.proof),
  bytes(proof.nullifier),
);
console.log(`verify_credential ${verified.hash}`);

const status = await read(contractId, "is_verified", address(holder), symbol(credential));
if (scValToNative(status) !== true) throw new Error("is_verified did not read true");
console.log(`is_verified(holder) = true, for ${holder.publicKey()}`);

const thiefStatus = await read(contractId, "is_verified", address(thief), symbol(credential));
if (scValToNative(thiefStatus) !== false) throw new Error("the thief reads as verified");
console.log("is_verified(thief)  = false");

await expectContractError("replayed proof", 8, () =>
  invoke(
    holder,
    contractId,
    "verify_credential",
    address(holder),
    symbol(credential),
    proofArg(proof.proof),
    bytes(proof.nullifier),
  ),
);

console.log("end to end: ok");
