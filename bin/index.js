#!/usr/bin/env node
"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var _a, _b;
const { Command } = require("commander");
const { mnemonicValidate, mnemonicToMiniSecret, naclBoxPairFromSecret, encodeAddress, sr25519PairFromSeed, cryptoWaitReady, } = require("@polkadot/util-crypto");
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
function toSs58OrHex(key, toHex, prefix) {
    if (toHex) {
        return u8aToHex(key);
    }
    else {
        return encodeAddress(key, prefix);
    }
}
function generateEd25519({ mnemonic, output, keyPrefix, toHex = false, }) {
    const keypair = naclBoxPairFromSecret(mnemonicToMiniSecret(mnemonic));
    if (output === "public") {
        console.log("Ed25519 :: Public key >>>");
        console.log(toSs58OrHex(keypair.publicKey, toHex !== null && toHex !== void 0 ? toHex : false, keyPrefix));
    }
    else if (output === "private") {
        console.log("Ed25519 :: Private key >>>");
        console.log(toSs58OrHex(keypair.secretKey, toHex !== null && toHex !== void 0 ? toHex : false, keyPrefix));
    }
}
function generateSr25519({ mnemonic, output, keyPrefix, toHex = false, }) {
    return __awaiter(this, void 0, void 0, function* () {
        yield cryptoWaitReady();
        const keypair = sr25519PairFromSeed(mnemonicToMiniSecret(mnemonic));
        if (output === "public") {
            console.log("Sr25519 :: Public key >>>");
            console.log(toSs58OrHex(keypair.publicKey, toHex !== null && toHex !== void 0 ? toHex : false, keyPrefix));
        }
        else if (output === "private") {
            console.log("Functionality is not implemented.");
        }
    });
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
                    toHex: (_a = options.toHex) !== null && _a !== void 0 ? _a : false,
                });
                break;
            case "sr25519":
                generateSr25519({
                    mnemonic: options.mnemonic.trim(),
                    output: options.output.trim(),
                    keyPrefix: Number.parseInt(options.keyPrefix),
                    toHex: (_b = options.toHex) !== null && _b !== void 0 ? _b : false,
                });
        }
    }
    catch (e) {
        console.log(e);
        process.exit(1);
    }
}
else {
    console.log("Arguments have not been provided.");
    process.exit(1);
}
//# sourceMappingURL=index.js.map