// Deploy veilproof-registry to testnet, ready for the public demo: the
// `membership` circuit registered and self-service credentials open.
//
//   cargo build --locked --release --target wasm32v1-none
//   node scripts/deploy-testnet.mjs
//
// Testnet is reset from time to time, which removes every contract on it, so this
// has to stay something anyone can rerun: it needs no account beyond the one it
// funds from friendbot. Set ADMIN_SECRET to deploy under an existing key.
// A generated admin key is written to .deploy/, which git ignores.
//
// The result goes to deployments/testnet.json, which veilproof-web points at.

import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Address, Keypair, Operation, nativeToScVal, scValToNative, xdr } from "@stellar/stellar-sdk";

import { bytes, fundedKeypair, invoke, PASSPHRASE, struct, submit } from "./lib.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const wasmPath = join(root, "target/wasm32v1-none/release/veilproof_registry.wasm");
const GRACE_SECONDS = 3600;
const CIRCUIT = "membership";

const wasm = readFileSync(wasmPath);
const vk = JSON.parse(readFileSync(join(root, "deployments/membership-vk.json"), "utf8"));

const admin = process.env.ADMIN_SECRET
  ? Keypair.fromSecret(process.env.ADMIN_SECRET)
  : await fundedKeypair();
console.log(`admin    ${admin.publicKey()}`);
if (!process.env.ADMIN_SECRET) {
  mkdirSync(join(root, ".deploy"), { recursive: true });
  writeFileSync(join(root, `.deploy/admin-${admin.publicKey()}.secret`), admin.secret());
}

const upload = await submit(admin, Operation.uploadContractWasm({ wasm }));
const wasmHash = createHash("sha256").update(wasm).digest("hex");
console.log(`wasm     ${wasmHash} (${upload.hash})`);

const created = await submit(
  admin,
  Operation.createCustomContract({
    address: new Address(admin.publicKey()),
    wasmHash: Buffer.from(wasmHash, "hex"),
    salt: randomBytes(32),
    constructorArgs: [
      new Address(admin.publicKey()).toScVal(),
      nativeToScVal(GRACE_SECONDS, { type: "u64" }),
    ],
  }),
);
const contractId = scValToNative(created.returnValue);
console.log(`contract ${contractId} (${created.hash})`);

const symbol = (value) => nativeToScVal(value, { type: "symbol" });
const adminArg = new Address(admin.publicKey()).toScVal();

const circuit = await invoke(
  admin,
  contractId,
  "register_circuit",
  adminArg,
  symbol(CIRCUIT),
  struct({
    alpha_g1: bytes(vk.alpha_g1),
    beta_g2: bytes(vk.beta_g2),
    gamma_g2: bytes(vk.gamma_g2),
    delta_g2: bytes(vk.delta_g2),
    ic: xdr.ScVal.scvVec(vk.ic.map(bytes)),
  }),
);
console.log(`circuit  ${CIRCUIT} (${circuit.hash})`);

const open = await invoke(admin, contractId, "set_open_registration", adminArg, xdr.ScVal.scvBool(true));
console.log(`open     yes (${open.hash})`);

const deployment = {
  network: "testnet",
  networkPassphrase: PASSPHRASE,
  contractId,
  wasmHash,
  admin: admin.publicKey(),
  circuit: CIRCUIT,
  graceSeconds: GRACE_SECONDS,
  openRegistration: true,
  deployedAt: new Date().toISOString(),
  transactions: {
    upload: upload.hash,
    create: created.hash,
    registerCircuit: circuit.hash,
    openRegistration: open.hash,
  },
};
writeFileSync(join(root, "deployments/testnet.json"), `${JSON.stringify(deployment, null, 2)}\n`);
console.log("wrote deployments/testnet.json");
