import { box, sign, randomBytes, hash, verify } from "tweetnacl";

import * as base64 from "@stablelib/base64";

import { Buffer } from 'buffer'

import hkdf from '@panva/hkdf'

import * as crypto from 'crypto'

import * as bip39 from 'bip39'

import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa'


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

export const createPQKey = (): IKey => {
  const encKeyPair = ml_kem768.keygen();
  const signKeyPair = ml_dsa65.keygen();

  return {
    private: {
      box: base64.encode(encKeyPair.secretKey),
      sign: base64.encode(signKeyPair.secretKey)
    },
    public: {
      box: base64.encode(encKeyPair.publicKey),
      sign: base64.encode(signKeyPair.publicKey)
    },
    type: 'pq_kem768,pq_dsa65'
  };
};


export const getBip39 = (): any => {
  return bip39;
}

export const getRandomBuffer = async(
  length: number
): Promise<Buffer> => {
  let randomBuffer = new Promise((resolve, reject)=>{
    crypto.randomBytes(length, (err,buf)=>{
      if(err){ return reject(err) }

      resolve(buf)
    })
  })

  return randomBuffer
}

/**
 * Generate mnemonic phrase
 */
export const generateMnemonic = async (): Promise<string> => {

  let randomBuffer = await getRandomBuffer(16)
  
  return bip39.entropyToMnemonic(randomBuffer)
}

export const validateMnemonic = (
  phrase: string
): boolean => {

  return bip39.validateMnemonic(phrase);
};

/**
 * Generate key from mnemonic phrase
 */
export const createKeyFromMnemonic = async (
  phrase: string,
  ignoreValidation: boolean = false
): IKey => {

  const validMnemonic = validateMnemonic(phrase)
  if(!ignoreValidation && !validMnemonic){
    throw new Error('invalid mnemonic phrase')
  }
  
  const fullSeed = await bip39.mnemonicToSeed(phrase);  //! 64bytes
  const fullSecret = await hkdf('sha512', fullSeed, hkdfSalt, 'fullSeed', 64)

  const boxSecret = fullSecret.slice(0, 32)
  const signSeed = fullSecret.slice(32)

  const boxKeyPair = box.keyPair.fromSecretKey(boxSecret);
  const signKeyPair = sign.keyPair.fromSeed(signSeed);

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
 * Generate salt
 */
export const generateSalt = async (): Buffer => {

  let randomBuffer = await getRandomBuffer(32)
  return randomBuffer
}

/**
 * Generate private and public keys from password and salt using pbkdf2
 */
export const createKeyFromPasswordPbkdf2 = async (
  password: string,
  salt: Buffer,
  rounds: Number = 500000
): IKey => {


  const fullSecret = await ( new Promise((resolve,reject)=>{
    crypto.pbkdf2(password, salt, rounds, 64, 'sha512', (err, derivedKey)=>{
      if(err){ return reject(err) }

      resolve(derivedKey)
    })
  }))


  const boxSecret = fullSecret.slice(0, 32)
  const signSeed = fullSecret.slice(32)

  const boxKeyPair = box.keyPair.fromSecretKey(boxSecret);
  const signKeyPair = sign.keyPair.fromSeed(signSeed);

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
 * Generate private key from password using argon2. You must pass in the instance
 * of argon2. We expect either `npm:argon2` or `npm:argon2-browser`.
 * @param argon Instance of argon2 either from `npm:argon2` or `npm:argon2-browser`
 * @param password 
 * @param salt 
 * @param timeCost      Defaults to 3
 * @param memoryCost    Defaults to 64MB
 * @param parallelism   Defaults to 4
 * @param type          Defaults to `argon2id`
 * @param hashLength    Defaults to 64
 */
export const createKeyFromPasswordArgon2 = async (
  argon: any,
  password: string,
  salt: Uint8Array,
  //associatedData: Buffer,
  timeCost: Number = 3,
  memoryCost: Number = 65536,
  parallelism: Number = 4,
  type: string = 'argon2id',
  hashLength: Number = 64
): IKey => {

  let fullSecret = null

  if( typeof argon.unloadRuntime == 'function' ){

    //! brower
    let argonType = {
      'argon2d': argon.ArgonType.Argon2d,
      'argon2i': argon.ArgonType.Argon2i,
      'argon2id': argon.ArgonType.Argon2id
    }[type]

    const hashResult = await argon.hash({
      pass: password,
      salt,
      //ad: associatedData,
      time: timeCost,
      mem: memoryCost,
      parallelism,
      hashLen: hashLength,
      type: argonType
    })

    fullSecret = hashResult.hash
  
  } else {

    //! node
    let argonType = {
      'argon2d': argon.argon2d,
      'argon2i': argon.argon2i,
      'argon2id': argon.argon2id
    }[type]

    const hashResult = await argon.hash(password, {
      salt,
      //associatedData,
      timeCost,
      memoryCost,
      parallelism,
      hashLength,
      type: argonType,
      raw: true
    })
  
    fullSecret = hashResult


  }


  const boxSecret = fullSecret.slice(0, 32)
  const signSeed = fullSecret.slice(32)

  const boxKeyPair = box.keyPair.fromSecretKey(boxSecret);
  const signKeyPair = sign.keyPair.fromSeed(signSeed);

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
    from: ourIdentity.toMini(),
    data
  }));

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

  decryptStep = "VERIFY SENDER";
  //#region

  if(from.public.box != base64.encode(theirPublicBoxKey)
    || from.public.sign != base64.encode(theirPublicSignKey)
  ) {

    const errorMessage = `ERROR ${decryptStep}: Cannot open ${base64.encode(payload)}. 
    Their public sign key - ${base64.encode(theirPublicSignKey)}.
    Their from key - ${from.public.sign}`;
    logger(errorMessage);
    throw new Error('payload [from] field does not match signature key');
  }

  //#endregion

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

  logger(`signing ${payload.length} bytes as ${signer.toMini()}`);

  const payloadHash = hash(payload);

  logger("data hash: " + base64.encode(payloadHash));

  const signerPrivateSignKey = base64.decode(signer.key.private.sign);
  const payloadSignature = sign.detached(payloadHash, signerPrivateSignKey);

  return {
    timestamp,
    sender,
    value: base64.encode(payloadSignature),
    type: signer.key.type
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

export const createPQSharedSecret = async function(
  to: IIdentity
): Promise<IPQSharedSecret> {

  const { cipherText, sharedSecret } = ml_kem768.encapsulate(base64.decode(to.key.public.box));
  
  return {
    cipherText: base64.encode(cipherText),
    sharedSecret: base64.encode(sharedSecret)
  }

};

export const recoverPQSharedSecret = async function(
  identity: IIdentity,    //! our identity
  cipherText: string
): Promise<IPQSharedSecret> {

  const { sharedSecret } = ml_kem768.decapsulate(cipherText, base64.decode(identity.key.private.box));
  
  return {
    cipherText, sharedSecret
  }

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
