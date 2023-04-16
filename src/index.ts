#!/usr/bin/env node

const { Command } = require("commander");
const {
  mnemonicValidate,
  mnemonicToMiniSecret,
  naclBoxPairFromSecret,
  encodeAddress,
  sr25519PairFromSeed,
  cryptoWaitReady,
} = require("@polkadot/util-crypto");
const { u8aToHex } = require("@polkadot/util");
const figlet = require("figlet");

const program = new Command();

program
  .version("0.0.1")
  .description("Generate public and private key from mnemonic")
  .option("-m, --mnemonic  <value>", "Account mnemonic")
  .option("-f, --format <value>", "Keys format")
  .option("-o, --output <value>", "Output value")
  .option("-p, --keyPrefix <value>", "Key prefix")
  .option("-h, --toHex", "Key prefix")
  .parse(process.argv);

const options = program.opts();

function toSs58OrHex(key: Uint8Array, toHex: boolean, prefix?: number) {
  if (toHex) {
    return u8aToHex(key);
  } else {
    return encodeAddress(key, prefix);
  }
}

function generateEd25519({
  mnemonic,
  output,
  keyPrefix,
  toHex = false,
}: {
  mnemonic: string;
  output: string;
  keyPrefix?: number;
  toHex?: boolean;
}) {
  const keypair = naclBoxPairFromSecret(mnemonicToMiniSecret(mnemonic));

  if (output === "public") {
    console.log("Ed25519 :: Public key >>>");
    console.log(toSs58OrHex(keypair.publicKey, toHex ?? false, keyPrefix));
  } else if (output === "private") {
    console.log("Ed25519 :: Private key >>>");
    console.log(toSs58OrHex(keypair.secretKey, toHex ?? false, keyPrefix));
  }
}

async function generateSr25519({
  mnemonic,
  output,
  keyPrefix,
  toHex = false,
}: {
  mnemonic: string;
  output: string;
  keyPrefix?: number;
  toHex?: boolean;
}) {
  await cryptoWaitReady();
  const keypair = sr25519PairFromSeed(mnemonicToMiniSecret(mnemonic));

  if (output === "public") {
    console.log("Sr25519 :: Public key >>>");
    console.log(toSs58OrHex(keypair.publicKey, toHex ?? false, keyPrefix));
  } else if (output === "private") {
    console.log("Functionality is not implemented.");
  }
}

if (options.mnemonic && options.format && options.output) {
  if (!mnemonicValidate(options.mnemonic)) {
    console.log("Mnemonic is not valid.");
    process.exit(1);
  }

  if (options.keyPrefix && Number.isNaN(Number.parseInt(options.keyPrefix))) {
    console.log("Key prefix is not valid.");
    process.exit(1);
  }
  try {
    console.log(figlet.textSync("Substrate Account Keys"));
    switch (options.format) {
      case "ed25519":
        generateEd25519({
          mnemonic: options.mnemonic.trim(),
          output: options.output.trim(),
          keyPrefix: Number.parseInt(options.keyPrefix),
          toHex: options.toHex ?? false,
        });
        break;
      case "sr25519":
        generateSr25519({
          mnemonic: options.mnemonic.trim(),
          output: options.output.trim(),
          keyPrefix: Number.parseInt(options.keyPrefix),
          toHex: options.toHex ?? false,
        });
    }
  } catch (e) {
    console.log(e);
    process.exit(1);
  }
} else {
  console.log("Arguments have not been provided.");
  process.exit(1);
}
