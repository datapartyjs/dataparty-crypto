import { box, sign, randomBytes, hash, verify } from "tweetnacl";

import * as base64 from "@stablelib/base64";

import { Buffer } from 'buffer'

import hkdf from '@panva/hkdf'

//! @todo use polyfill
var crypto = require('crypto')

if(!crypto.getRandomValues){
  global.crypto = crypto.webcrypto
}

const bip39 = require('bip39')

const logger = require("debug")("dataparty-crypto.Routines");

const newNonce = () => randomBytes(box.nonceLength);

const nonceSignSize = box.nonceLength + sign.publicKeyLength;

const nonceSignBoxSize = nonceSignSize + box.publicKeyLength;

const hkdfSalt = "ain't no party like a dataparty party. cu's dataparty party don't stop!"

/**
 * Generate private and public keys
 */
export const createKey = (): IKey => {
  const boxKeyPair = box.keyPair();
  const signKeyPair = sign.keyPair();

  return {
    private: {
      box: base64.encode(boxKeyPair.secretKey),
      sign: base64.encode(signKeyPair.secretKey)
    },
    public: {
      box: base64.encode(boxKeyPair.publicKey),
      sign: base64.encode(signKeyPair.publicKey)
    },
    type: "nacl"
  };
};


export const getBip39 = (): any => {
  return bip39;
}

export const generateMnemonic = (): string => {
  return bip39.generateMnemonic()
}

export const validateMnemonic = (
  phrase: string
): boolean => {

  return bip39.validateMnemonic(phrase);
};

/**
 * Generate key from mnemonic phrase
 */
export const createKeyFromSeed = async (
  phrase: string,
  ignoreValidation: boolean
): IKey => {

  const validMnemonic = validateMnemonic(phrase)
  if(!ignoreValidation && !validMnemonic){
    throw new Error('invalid mnemonic phrase')
  }
  
  const fullSeed = await bip39.mnemonicToSeed(phrase);  //! 64bytes
  const fullSecret = await hkdf('sha512', fullSeed, hkdfSalt, 'fullSeed', 96)

  const boxSecret = fullSecret.slice(0, 32)
  const signSecret = fullSecret.slice(32)

  const boxKeyPair = box.keyPair.fromSecretKey(boxSecret);
  const signKeyPair = sign.keyPair.fromSecretKey(signSecret);

  return {
    private: {
      box: base64.encode(boxKeyPair.secretKey),
      sign: base64.encode(signKeyPair.secretKey)
    },
    public: {
      box: base64.encode(boxKeyPair.publicKey),
      sign: base64.encode(signKeyPair.publicKey)
    },
    type: "nacl"
  };

};

/**
 * Encrypt data using our private key and their public key
 * @param identity Our identity
 * @param toPublic their public key
 * @param data anything...
 */
export const encryptData = async function(
  ourIdentity: IIdentity,
  theirPublicKeyBundle: IKeyBundle,
  data: any
): Promise<IEncryptedData> {

  const payload = Buffer.from(JSON.stringify({
      from: ourIdentity.toJSON(true),
      data
    })
  );

  logger(
    `encrypting ${payload.length} bytes from 
    [${ourIdentity.key.public.box}, ${ourIdentity.key.public.sign}] 
    with [${theirPublicKeyBundle.box}, ${theirPublicKeyBundle.sign}]`
  );

  const nonce = newNonce();
  const ourPrivateKeyBundle = ourIdentity.key.private;

  // SIGN DATA ----
  const ourPrivateSignKey = base64.decode(ourPrivateKeyBundle.sign);
  const signedData = sign(payload, ourPrivateSignKey);

  // ENCRYPT ----
  const theirPublicBoxKey = base64.decode(theirPublicKeyBundle.box);
  const ourPrivateBoxKey = base64.decode(ourPrivateKeyBundle.box);

  const message = box(signedData, nonce, theirPublicBoxKey, ourPrivateBoxKey);

  //#region EMBED PUBLIC KEYS
  const fullMessage = new Uint8Array(nonceSignBoxSize + message.length);

  const ourPublicSignKey = base64.decode(ourIdentity.key.public.sign);
  const ourPublicBoxKey = base64.decode(ourIdentity.key.public.box);

  fullMessage.set(nonce);
  fullMessage.set(ourPublicSignKey, box.nonceLength);
  fullMessage.set(ourPublicBoxKey, nonceSignSize);
  fullMessage.set(message, nonceSignBoxSize);

  // Message last to infer size

  //#endregion

  // CREATE HASH - SHA-512
  const messageHash = hash(fullMessage);

  logger("Message hash: " + base64.encode(messageHash));

  // SIGN HASH
  const messageHashSigned = sign(messageHash, ourPrivateSignKey);

  return {
    enc: base64.encode(fullMessage),
    sig: base64.encode(messageHashSigned)
  };
};

/**
 * Decrypted an encrypted data (base of Message) with our identity
 * @param ourIdentity
 * @param param1
 */
export const decryptData = async function(
  ourIdentity: IIdentity,
  { enc, sig }: IMessage
): Promise<IDecryptedData> {
  let decryptStep = "";

  const ourPrivateKeyBundle = ourIdentity.key.private;
  const ourPrivateBoxKey = base64.decode(ourPrivateKeyBundle.box);

  const fullMessage = base64.decode(enc);
  const messageHashSigned = base64.decode(sig as string);

  decryptStep = "EXTRACT EMBEDED DATA";
  //#region 
  if(fullMessage.length <= nonceSignBoxSize) {
    logger(`ERROR ${decryptStep}: data is tampered`);
    throw new Error("data is tampered");
  }

  const nonce = fullMessage.slice(0, box.nonceLength);

  const theirPublicSignKey = fullMessage.slice(box.nonceLength, nonceSignSize);

  const theirPublicBoxKey = fullMessage.slice(nonceSignSize, nonceSignBoxSize);

  const message = fullMessage.slice(nonceSignBoxSize, fullMessage.length);

  //#endregion

  decryptStep = "HASH SIGN OPEN";
  //#region
  const msgHash = sign.open(messageHashSigned, theirPublicSignKey);
  if (msgHash === null) {
    const errorMessage = `ERROR ${decryptStep}: Cannot open ${sig}. 
    Their public sign key - ${theirPublicSignKey} `;

    logger(errorMessage);
    throw new Error('signed message hash verification failed');
  }
  //#endregion

  decryptStep = "FULLMSG HASH VERIFY";
  //#region
  const selfHash = hash(fullMessage);

  if (!verify(selfHash, msgHash)) {
    const errorMessage = `ERROR ${decryptStep}: 
      our\t\t - ${base64.encode(selfHash)}
      their\t\t - ${base64.encode(msgHash)}
    `;

    logger(errorMessage);
    throw new Error('message hash verification failed');
  }
  //#endregion

  decryptStep = "SIGNEDMSG BOX OPEN";
  //#region
  const signedData = box.open(
    message,
    nonce,
    theirPublicBoxKey,
    ourPrivateBoxKey
  );

  if (signedData === null) {
    const errorMessage = `ERROR ${decryptStep}: Cannot open the box.
    Their public box key - ${base64.encode(theirPublicBoxKey)}`;
    logger(errorMessage);
    throw new Error('signed data decryption failed');
  }

  //#endregion

  decryptStep = "EXTRACT PAYLOAD";
  //#region

  const payload = sign.open(signedData, theirPublicSignKey);
  if (payload === null) {
    const errorMessage = `ERROR ${decryptStep}: Cannot open ${payload}. 
    Their public sign key - ${theirPublicSignKey} `;
    logger(errorMessage);
    throw new Error('payload signature verification failed');
  }
  //#endregion

  const { data, from } = JSON.parse(Buffer.from(payload).toString());

  return { data, from };
};

const getPayload = (signer: IIdentity, data: any) => {
  const timestamp = Date.now();
  const sender = signer.toMini();
  const payload = Buffer.from(
    JSON.stringify({
      sender,
      data
    })
  );

  return { timestamp, sender, payload };
};

/**
 * Sign only the data's hash
 * @param signer
 * @param data
 */
export const signData = async function(
  signer: IIdentity,
  data: any
): Promise<ISignature> {
  const { timestamp, sender, payload } = getPayload(signer, data);

  logger(`signing ${payload.length} bytes as ${signer.key.public}`);

  const payloadHash = hash(payload);

  logger("data hash: " + base64.encode(payloadHash));

  const signerPrivateSignKey = base64.decode(signer.key.private.sign);
  const payloadSignature = sign.detached(payloadHash, signerPrivateSignKey);

  return {
    timestamp,
    sender,
    value: base64.encode(payloadSignature)
  };
};

/**
 *
 */
export const verifyData = async function(
  signer: IIdentity,
  signature: ISignature,
  data: any
): Promise<boolean> {
  const { payload } = getPayload(signer, data)

  const theirPayloadSignature = base64.decode(signature.value)
  
  const payloadHash = hash(payload)

  logger(`VERIFY - payloadHash: ${base64.encode(payloadHash)}`);
  logger(`VERIFY - theirSignature: ${signature.value}`);

  const theirPublicSignKey = base64.decode(signer.key.public.sign)

  return sign.detached.verify(payloadHash, theirPayloadSignature, theirPublicSignKey)
};


export function extractPublicKeys (enc : string) : IKeyBundle {
  const fullMessage = base64.decode(enc);

  const publicSignKey = fullMessage.slice(box.nonceLength, nonceSignSize);

  const publicBoxKey = fullMessage.slice(nonceSignSize, nonceSignBoxSize);

  return {
    box: base64.encode(publicBoxKey),
    sign: base64.encode(publicSignKey)
  }
}
