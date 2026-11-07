// Shared plumbing for the deploy and end-to-end scripts: an RPC client, a
// friendbot-funded key, and signed contract calls that wait for the result.

import {
  Account,
  Contract,
  Keypair,
  Networks,
  TransactionBuilder,
  rpc,
  xdr,
} from "@stellar/stellar-sdk";

export const RPC_URL = process.env.VEILPROOF_RPC_URL ?? "https://soroban-testnet.stellar.org";
export const PASSPHRASE = Networks.TESTNET;

export const server = new rpc.Server(RPC_URL);

/** A new keypair with a testnet balance. Testnet funds are free and worthless. */
export async function fundedKeypair() {
  const keypair = Keypair.random();
  await fund(keypair.publicKey());
  return keypair;
}

export async function fund(address) {
  const res = await fetch(`https://friendbot.stellar.org/?addr=${address}`);
  if (!res.ok) throw new Error(`friendbot refused ${address}: HTTP ${res.status}`);
}

/** Sign and submit one operation with `signer` as the source, and wait for it. */
export async function submit(signer, operation) {
  const account = await server.getAccount(signer.publicKey());
  const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: PASSPHRASE })
    .addOperation(operation)
    .setTimeout(120)
    .build();
  const prepared = await server.prepareTransaction(tx);
  prepared.sign(signer);

  const sent = await server.sendTransaction(prepared);
  if (sent.status === "ERROR") {
    throw new Error(`submission failed: ${sent.errorResult?.toXDR("base64")}`);
  }

  const deadline = Date.now() + 60_000;
  let result = await server.getTransaction(sent.hash);
  while (result.status === "NOT_FOUND" && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    result = await server.getTransaction(sent.hash);
  }
  if (result.status !== "SUCCESS") {
    throw new Error(`transaction ${sent.hash} ended as ${result.status}`);
  }
  return { hash: sent.hash, returnValue: result.returnValue };
}

/** Call a contract function from `signer` and wait for it. */
export function invoke(signer, contractId, method, ...args) {
  return submit(signer, new Contract(contractId).call(method, ...args));
}

/** Read a contract view through simulation; nothing is submitted. */
export async function read(contractId, method, ...args) {
  // A simulation never touches its source account, so it need not exist.
  const source = new Account(Keypair.random().publicKey(), "0");
  const tx = new TransactionBuilder(source, { fee: "100", networkPassphrase: PASSPHRASE })
    .addOperation(new Contract(contractId).call(method, ...args))
    .setTimeout(30)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(sim.error);
  return sim.result?.retval;
}

/** A Soroban struct, encoded as a map of its fields in lexicographic order. */
export function struct(fields) {
  return xdr.ScVal.scvMap(
    Object.keys(fields)
      .sort()
      .map(
        (name) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(name), val: fields[name] }),
      ),
  );
}

export const bytes = (hex) => xdr.ScVal.scvBytes(Buffer.from(hex, "hex"));
