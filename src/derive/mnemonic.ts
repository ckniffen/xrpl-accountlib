"use strict";

import { mnemonicToSeedSync } from "@scure/bip39";
import { HDKey } from "@scure/bip32";
import { bytesToHex } from '@xrplf/isomorphic/utils'

import { deriveAddress } from "ripple-keypairs";

import Account from "../schema/Account";

import * as Utils from "../utils";

type options = {
  passphrase?: string;
  accountPath?: string;
  changePath?: string;
  addressIndex?: number;
};

type ValidHDKey = HDKey & {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

function validateKey(node: HDKey): asserts node is ValidHDKey {
  if (!(node.privateKey instanceof Uint8Array)) {
    throw new Error('Unable to derive privateKey from mnemonic input')
  }

  if (!(node.publicKey instanceof Uint8Array)) {
    throw new Error('Unable to derive publicKey from mnemonic input')
  }
}

const mnemonic = (words: string, options: options = {}) => {
  const passphrase = options.passphrase ? options.passphrase : undefined;

  const accountPath =
    options.accountPath && !isNaN(parseInt(options.accountPath))
      ? options.accountPath
      : 0;
  const changePath =
    options.changePath && !isNaN(parseInt(options.changePath))
      ? options.changePath
      : 0;
  const addressIndex =
    options.addressIndex && !isNaN(options.addressIndex)
      ? options.addressIndex
      : 0;

  const Path = `m/44'/144'/${accountPath}'/${changePath}/${addressIndex}`;

  const Seed = mnemonicToSeedSync(words, passphrase);
  const m = HDKey.fromMasterSeed(Seed);
  const Node = m.derive(Path);
  validateKey(Node)

  const publicKey = bytesToHex(Node.publicKey);
  // @ts-ignore
  const privateKey = bytesToHex(Node.privateKey);
  const Keypair = {
    publicKey: publicKey,
    privateKey: "00" + privateKey
  };
  const Address = deriveAddress(Keypair.publicKey);

  return new Account({
    address: Address,
    mnemonic: words,
    passphrase: passphrase,
    keypair: Keypair,
    path: Path
  });
};

export default mnemonic;
