import { box, sign, randomBytes, hash, verify } from "tweetnacl";

import * as base64 from "@stablelib/base64";

import { Buffer } from 'buffer'

import hkdf from '@panva/hkdf'

import * as crypto from 'crypto'

import * as bip39 from 'bip39'


import { x25519 } from '@noble/curves/ed25519';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { 
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s
} from '@noble/post-quantum/slh-dsa';
import { siv } from '@noble/ciphers/aes';

import {parseObject, BaseParser, serializeBSONWithoutOptimiser} from '@deepkit/bson';

import Debug from "debug";
const logger = Debug("dataparty-crypto.Routines");


const PQ_CLASSES = {
  kem: {  ml_kem512, ml_kem768, ml_kem1024 },
  dsa: {
    ml_dsa44, ml_dsa65, ml_dsa87,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_128s,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_192s,
    slh_dsa_sha2_256f,
    slh_dsa_sha2_256s
  }
}

const newNonce = () => randomBytes(box.nonceLength);

export const Utils = {
  randomBytes, base64, 
}

export let BSON = { parseObject, BaseParser, serializeBSONWithoutOptimiser }

const nonceSignSize = box.nonceLength + sign.publicKeyLength;

const nonceSignBoxSize = nonceSignSize + box.publicKeyLength;

const AES_OFFER_INFO = 'aesoffer'
const AES_OFFER_SALT = base64.decode('kr7/W7rHJD6gMpK5oLfER/ubYcqf7DqNrZThLAi9PSs=')

const HkdfFullseedSalt = base64.decode('GgRPwNd9OImrnIisRl79XhgltCZ7g6zGcRpaxqJuOco=')


export const toHexString = (
  byteArray : Buffer | Uint8Array
) => {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}

export const reach = (obj, path, defaultVal)=>{
  var tokens = path.split('.')
  var val = obj;

  try{
    for(var i=0; i<tokens.length; i++){
      val = val[tokens[i]]
    }

    if(val == undefined){ val = defaultVal }
  }
  catch(excp){
    val = (defaultVal != undefined) ? defaultVal : null
  }

  return val;
}


export const hashLongKey = async (
  key: IKey
): Promise<string> => {

  let typeList = key.type.split(',')

  return base64.encode(hash(
    Buffer.concat([
      Buffer.from(typeList.join(',')),
      base64.decode(key.public.box),
      base64.decode(key.public.sign),
      base64.decode(key.public.pqkem),
      base64.decode(key.public.pqsign_ml),
      base64.decode(key.public.pqsign_slh)
    ])
  ))
}

export const hashShortKey = async (
  key: IKey
): Promise<string> => {

  let typeList = key.type.split(',')

  return base64.encode(hash(
    Buffer.concat([
      Buffer.from(typeList.join(',')),
      base64.decode(key.public.box),
      base64.decode(key.public.sign)
    ])
  ))
}


export const hashKey = async (
  key: IKey
): Promise<string> => {

  let typeList = key.type.split(',')

  if(typeList.length == 2){
    return hashShortKey(key)
  }

  return hashLongKey(key)
}


/**
 * Generate private and public keys
 */
export const createKey = async (
  seed: Buffer,
  postQuantum: boolean = true,
  type: string = "nacl,nacl,ml_kem768,ml_dsa65,slh_dsa_sha2_128f"
): Promise<IKey> => {

  if(seed.length != 64){
    throw new Error('seed expected to be 64 bytes')
  }

  const [box_type, sign_type, pqkem_type, pqsign_ml_type, pqsign_slh_type ] = type.split(',')
  

  if(box_type != 'nacl'){ throw new Error('box_type must be nacl') }
  if(sign_type != 'nacl'){ throw new Error('sign_type must be nacl') }

  const boxSeed = await hkdf('sha512', seed, HkdfFullseedSalt, 'box', 32)
  const signSeed = await hkdf('sha512', seed, HkdfFullseedSalt, 'sign', 32)

  const boxKeyPair = box.keyPair.fromSecretKey( boxSeed );
  const signKeyPair = sign.keyPair.fromSeed( signSeed );

  if(postQuantum){

    const typeList = [box_type, sign_type, pqkem_type, pqsign_ml_type, pqsign_slh_type ]

    if(pqkem_type.indexOf('ml_kem') != 0){ throw new Error('pqkem_type must start with ml_kem')}
    if(pqsign_ml_type.indexOf('ml_dsa') != 0){ throw new Error('pqsign_ml_type must start with ml_dsa')}
    if(pqsign_slh_type.indexOf('slh_dsa') != 0){ throw new Error('pqsign_slh_type must start with slh_dsa')}

    let pqkemClass = PQ_CLASSES.kem[ pqkem_type ] || null
    let pqsignmlClass = PQ_CLASSES.dsa[ pqsign_ml_type ] || null
    let pqsignslhClass = PQ_CLASSES.dsa[ pqsign_slh_type ] || null

    if(pqkemClass == null){ throw new Error('invalid pqkem_type') }
    if(pqsignmlClass == null){ throw new Error('invalid pqsign_ml_type') }
    if(pqsignslhClass == null){ throw new Error('invalid pqsign_slh_type') }

    const pqKemSeed = await hkdf('sha512', seed, HkdfFullseedSalt, 'pqkem', 64)
    const pqSignMLSeed = await hkdf('sha512', seed, HkdfFullseedSalt, 'pqsignml', 32)
    const pqSignSLDSeed = await hkdf('sha512', seed, HkdfFullseedSalt, 'pqsignslh', pqsignslhClass.seedLen)
  
  
    const pqKemKeyPair = pqkemClass.keygen( pqKemSeed );
    const pqSignMLKeyPair = pqsignmlClass.keygen( pqSignMLSeed );
    const pqSignSLHKeyPair = pqsignslhClass.keygen( pqSignSLDSeed );
    
    const keyHash = hash(
      Buffer.concat([
        Buffer.from(typeList.join(',')),
        boxKeyPair.publicKey,
        signKeyPair.publicKey,
        pqKemKeyPair.publicKey,
        pqSignMLKeyPair.publicKey,
        pqSignSLHKeyPair.publicKey
      ])
    )

    return {
      private: {
        box: base64.encode(boxKeyPair.secretKey),
        sign: base64.encode(signKeyPair.secretKey),
        pqkem: base64.encode(pqKemKeyPair.secretKey),
        pqsign_ml: base64.encode(pqSignMLKeyPair.secretKey),
        pqsign_slh: base64.encode(pqSignSLHKeyPair.secretKey)
      },
      public: {
        box: base64.encode(boxKeyPair.publicKey),
        sign: base64.encode(signKeyPair.publicKey),
        pqkem: base64.encode(pqKemKeyPair.publicKey),
        pqsign_ml: base64.encode(pqSignMLKeyPair.publicKey),
        pqsign_slh: base64.encode(pqSignSLHKeyPair.publicKey)
      },
      type: typeList.join(','),
      hash: base64.encode(keyHash)
    };

  }

  const typeList = [box_type, sign_type]

  return {
    private: {
      box: base64.encode(boxKeyPair.secretKey),
      sign: base64.encode(signKeyPair.secretKey)
    },
    public: {
      box: base64.encode(boxKeyPair.publicKey),
      sign: base64.encode(signKeyPair.publicKey)
    },
    type: typeList.join(','),
    hash: base64.encode(hash(
      Buffer.concat([
        Buffer.from(typeList.join(',')),
        boxKeyPair.publicKey,
        signKeyPair.publicKey
      ])
    ))
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
  }) as Promise<Buffer>

  return randomBuffer
}

/**
 * Generate mnemonic phrase
 */
export const generateMnemonic = async (
  seed?: Buffer
): Promise<string> => {

  if(!seed){
    seed = await getRandomBuffer(32)
  }
  
  return bip39.entropyToMnemonic(seed)
}

export const validateMnemonic = (
  phrase: string
): boolean => {

  return bip39.validateMnemonic(phrase);
};

/**
 * Generate key from mnemonic phrase
 */
export const createSeedFromMnemonic = async (
  phrase: string,
  password: string,
  argon2: any,
  ignoreValidation: boolean = false
): Promise<Buffer> => {

  const validMnemonic = validateMnemonic(phrase)
  if(!ignoreValidation && !validMnemonic){
    throw new Error('invalid mnemonic phrase')
  }
  
  const entropy = await bip39.mnemonicToEntropy(phrase)
  const normalizedPhrase = bip39.entropyToMnemonic(entropy)

  if(!password || password.length < 1){
    password = '00000000'
  }

  const normalizedPassword = password.normalize('NFKD')

  const fullSeed = await createSeedFromPasswordArgon2(
    argon2,
    normalizedPhrase,
    hash(Buffer.from(normalizedPassword, 'utf8'))
  )

  return fullSeed

};

export const entropyToMnemonic = async(
  entropy: Buffer
): Promise<string> => {

  return bip39.entropyToMnemonic(entropy)
}


/**
 * Generate salt
 */
export const generateSalt = async (): Promise<Buffer> => {

  let randomBuffer = await getRandomBuffer(32)
  return randomBuffer
}

/**
 * Generate private and public keys from password and salt using pbkdf2
 */
export const createSeedFromPasswordPbkdf2 = async (
  password: string,
  salt: Buffer,
  rounds: number = 500000
): Promise<Buffer> => {


  const fullSecret = await ( new Promise((resolve,reject)=>{
    crypto.pbkdf2(password, salt, rounds, 64, 'sha512', (err, derivedKey)=>{
      if(err){ return reject(err) }

      resolve(derivedKey)
    })
  })) as Buffer;

  return fullSecret

};

/**
 * Generate private key seed from password using argon2. You must pass in the instance
 * of argon2. We expect either `npm:argon2` or `npm:argon2-browser`.
 * @param argon Instance of argon2 either from `npm:argon2` or `npm:argon2-browser`
 * @param password 
 * @param salt 
 * @param timeCost      Defaults to 3
 * @param memoryCost    Defaults to 64MB
 * @param parallelism   Defaults to 4
 * @param type          Defaults to `argon2id`
 */
export const createSeedFromPasswordArgon2 = async (
  argon: any,
  password: string,
  salt: Uint8Array,
  //associatedData: Buffer,
  timeCost: Number = 3,
  memoryCost: Number = 64*1024,
  parallelism: Number = 4,
  type: string = 'argon2id'
): Promise<Buffer> => {

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
      hashLen: 64,
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
      hashLength:64,
      type: argonType,
      raw: true
    })
  
    fullSecret = hashResult


  }

  return fullSecret

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


  const payload = serializeBSONWithoutOptimiser({
    from: ourIdentity.toMini(false),
    data
  });

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
    enc: fullMessage,
    sig: messageHashSigned
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

  const fullMessage = /*base64.decode(*/ enc //);
  const messageHashSigned = sig; // base64.decode(sig as string);

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

  const { data, from } = parseObject(new BaseParser(payload))
  //JSON.parse(Buffer.from(payload).toString());

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
  const sender = signer.toMini(false);

  const payload = serializeBSONWithoutOptimiser({
    timestamp,
    sender,
    data
  })

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

  logger(`signing ${payload.length} bytes as ${signer.toMini(false)}`);

  const payloadHash = hash(payload);

  logger("data hash: " + base64.encode(payloadHash));

  const signerPrivateSignKey = base64.decode(signer.key.private.sign);
  const payloadSignature = sign.detached(payloadHash, signerPrivateSignKey);

  return {
    timestamp,
    sender,
    value: payloadSignature,
    type: 'sign'
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

  const theirPayloadSignature = signature.value
  
  const payloadHash = hash(payload)

  logger(`VERIFY - payloadHash: ${base64.encode(payloadHash)}`);
  logger(`VERIFY - theirSignature: ${signature.value}`);

  const theirPublicSignKey = base64.decode(signer.key.public.sign)

  return sign.detached.verify(payloadHash, theirPayloadSignature, theirPublicSignKey)
};



export const signDataPQ = async (
  signer: IIdentity,
  data: Uint8Array,
  type: 'pqsign_ml' | 'pqsign_slh'
): Promise<ISignature> => {

  const [box_type, sign_type, pqkem_type, pqsign_ml_type, pqsign_slh_type ] = signer.key.type.split(',')

  
  let signClass = null

  if(type == 'pqsign_slh'){

    if(pqsign_slh_type.indexOf('slh_dsa') != 0){ throw new Error('pqsign_slh_type must start with slh_dsa')}
    signClass = PQ_CLASSES.dsa[ pqsign_slh_type ] || null
    
  } else if(type == 'pqsign_ml'){

    if(pqsign_ml_type.indexOf('ml_dsa') != 0){ throw new Error('pqsign_ml_type must start with ml_dsa')}
    signClass = PQ_CLASSES.dsa[ pqsign_ml_type ] || null

  } else {
    throw new Error('invalid signature type requested')
  }

  if(!signClass){ throw new Error('invalid signing class type') }

  const privateKey = base64.decode(signer.key.private[type])

  const timestamp = Date.now()
  const sender = signer.toMini()
  const payload = serializeBSONWithoutOptimiser({
    timestamp,
    sender,
    data
  })

  const payloadHash = hash(payload)

  const signature = signClass.sign( privateKey, payloadHash)

  return {
    timestamp,
    sender,
    value: signature,
    type
  }
  
}


export const verifyDataPQ = async (
  signer: IIdentity,
  signature: ISignature,
  data: Uint8Array,
): Promise<boolean> => {

  const [box_type, sign_type, pqkem_type, pqsign_ml_type, pqsign_slh_type ] = signer.key.type.split(',')

  const type = signature.type
  let signClass = null

  if(type == 'pqsign_slh'){

    if(pqsign_slh_type.indexOf('slh_dsa') != 0){ throw new Error('pqsign_slh_type must start with slh_dsa')}
    signClass = PQ_CLASSES.dsa[ pqsign_slh_type ] || null
    
  } else if(type == 'pqsign_ml'){

    if(pqsign_ml_type.indexOf('ml_dsa') != 0){ throw new Error('pqsign_ml_type must start with ml_dsa')}
    signClass = PQ_CLASSES.dsa[ pqsign_ml_type ] || null

  } else {
    throw new Error('invalid signature type requested')
  }

  if(!signClass){ throw new Error('invalid signing class type') }

  const payload = serializeBSONWithoutOptimiser({
    timestamp: signature.timestamp,
    sender: signer.toMini(),
    data
  })

  const payloadHash = hash(payload)

  return signClass.verify( base64.decode(signer.key.public[type]), payloadHash, signature.value )
}


export const createNaclSharedSecret = async function(
  to: IIdentity,
  from: IIdentity
): Promise<INaclSharedSecret> {

  const sharedSecret = x25519.getSharedSecret(
    toHexString( base64.decode( from.key.private.box ) ),
    toHexString( base64.decode( to.key.public.box ) )
  )

  return {
    sharedSecret: base64.encode(sharedSecret)
  }
};

export const createPQSharedSecret = async function(
  to: IIdentity
): Promise<IPQSharedSecret> {


  const [box_type, sign_type, pqkem_type, pqsign_ml_type, pqsign_slh_type ] = to.key.type.split(',')
  

  if(pqkem_type.indexOf('ml_kem') != 0){ throw new Error('pqkem_type must start with ml_kem')}

  let pqkemClass = PQ_CLASSES.kem[ pqkem_type ] || null

  if(pqkemClass == null){ throw new Error('invalid pqkem_type') }

  const { cipherText, sharedSecret } = pqkemClass.encapsulate(base64.decode(to.key.public.pqkem));
  
  return {
    cipherText: base64.encode(cipherText),
    sharedSecret: base64.encode(sharedSecret)
  }

};

export const recoverPQSharedSecret = async function(
  identity: IIdentity,    //! our identity
  cipherText: string
): Promise<IPQSharedSecret> {


  const [box_type, sign_type, pqkem_type, pqsign_ml_type, pqsign_slh_type ] = identity.key.type.split(',')
  

  if(pqkem_type.indexOf('ml_kem') != 0){ throw new Error('pqkem_type must start with ml_kem')}

  let pqkemClass = PQ_CLASSES.kem[ pqkem_type ] || null

  if(pqkemClass == null){ throw new Error('invalid pqkem_type') }

  const sharedSecret = pqkemClass.decapsulate(base64.decode(cipherText), base64.decode(identity.key.private.pqkem));
  
  return {
    cipherText, sharedSecret: base64.encode(sharedSecret)
  }

};

export class AESStream implements IAESStream {
  rxNonce: Uint8Array;
  txNonce: Uint8Array;
  streamKey: Uint8Array;

  constructor(streamKey: Uint8Array, streamNonce: Uint8Array) {

    this.streamKey = streamKey
    this.rxNonce = new Uint8Array(streamNonce)
    this.txNonce = new Uint8Array(streamNonce)
  }

  async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    const nextTxNonce = randomBytes(12)
    const payload = serializeBSONWithoutOptimiser({
      nonce: nextTxNonce,
      data: plaintext
    })

    let aesFn = siv(this.streamKey, this.txNonce)

    this.txNonce = nextTxNonce

    return aesFn.encrypt(payload)
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {


    let aesFn = siv(this.streamKey, this.rxNonce)

    const plaintext = aesFn.decrypt(ciphertext)

    const payload = parseObject(new BaseParser(plaintext))

    this.rxNonce = payload.nonce

    return payload.data
  }
}

export const createAESStream = async function(
  naclSharedSecret: INaclSharedSecret=null,
  pqSharedSecret: IPQSharedSecret=null,
  streamNonce: Uint8Array,
  info: Uint8Array | string=AES_OFFER_INFO,
  salt: Uint8Array | string=AES_OFFER_SALT,
): Promise<IAESStream> {

  let fullSecret = null

  if(naclSharedSecret && pqSharedSecret){
  
    fullSecret = Buffer.concat([ 
      base64.decode(naclSharedSecret.sharedSecret),
      base64.decode(pqSharedSecret.sharedSecret)
    ])

  } else if (naclSharedSecret && !pqSharedSecret){

    fullSecret = base64.decode(naclSharedSecret.sharedSecret)

  } else if (!naclSharedSecret && pqSharedSecret){

    fullSecret = base64.decode(pqSharedSecret.sharedSecret)
    
  }

  const streamKey = await hkdf('sha512', fullSecret, salt, info, 32)

  const stream = new AESStream(streamKey, streamNonce)
  return stream;
}


export function extractPublicKeys (enc : Uint8Array) : IKeyBundle {
  const fullMessage = enc;

  const publicSignKey = fullMessage.slice(box.nonceLength, nonceSignSize);

  const publicBoxKey = fullMessage.slice(nonceSignSize, nonceSignBoxSize);

  return {
    box: base64.encode(publicBoxKey),
    sign: base64.encode(publicSignKey)
  }
}

export const solveProofOfWork = async (
  input : Buffer | string,
  argon,
  { timeCost = 3, memoryCost = 2048, parallelism = 1, complexity = 19 } = {}
) => {
  const options = {
    timeCost,
    memoryCost,
    parallelism,
    type: argon.argon2d
  };

  if (complexity < 8) {
    throw new Error("complexity must be at least 8");
  }

  try {
    for (;;) {
      const proof = await argon.hash(input, options);
      if (await checkProofOfWorkComplexity(hash.split("$")[5], complexity)) {
        return proof;
      }
    }
  } catch (error) {
    throw error;
  }
};

export const verifyProofOfWork = async (
  input: Buffer | string,
  proof: string,
  argon,
  { timeCost = 3, memoryCost = 9, parallelism = 1, complexity = 19 } = {}
) => {
  const parsed = proof.split("$");
  const regexp = /m=([0-9]+),t=([0-9]+),p=([0-9]+)/;

  if (parsed[3] === undefined) {
    throw new Error("Invalid proof");
  }

  const matches = parsed[3].match(regexp);

  if (!matches) {
    throw new Error("Invalid proof");
  }

  if (parseInt(matches[1]) != memoryCost) {
    return false;
  }

  if (parseInt(matches[2]) != timeCost) {
    return false;
  }

  if (parseInt(matches[3]) != parallelism) {
    return false;
  }

  if (!checkProofOfWorkComplexity(parsed[5], complexity)) {
    return false;
  }

  const result = await argon.verify(proof, input);

  return result;
};

export const checkProofOfWorkComplexity = (
  proof: string,
  complexity
) => {
  if (complexity < 8) {
    throw new Error("complexity must be at least 8");
  }

  let off = 0;
  let i;

  for (i = 0; i <= complexity - 8; i += 8, off++) {
    if (proof[off] !== "0") return false;
  }

  const mask = 0xff << (8 + i - complexity);
  return (proof[off] & mask) === 0;
};
