import { Buffer } from 'buffer'
import { gcmsiv } from '@noble/ciphers/aes.js';

import Identity from "./identity";

import {
  Utils,
  BSON,
  reach,
  getRandomBuffer,
  createPQSharedSecret,
  recoverPQSharedSecret,
  createNaclSharedSecret,
} from "./routines";


const AES_OFFER_INFO = 'aesoffer'
const AES_OFFER_SALT = Utils.base64.decode('kr7/W7rHJD6gMpK5oLfER/ubYcqf7DqNrZThLAi9PSs=')

function copyBuffer(src)  {
  var dst = new ArrayBuffer(src.byteLength);
  new Uint8Array(dst).set(new Uint8Array(src));
  return dst;
}


export default class AESStream implements IAESStream {
  identity: IIdentity;
  rxNonce: Uint8Array;
  txNonce: Uint8Array;
  key: Uint8Array;
  offer: IAESStreamOffer;

  constructor(opts = {/*identity, key, offer, mode*/} as any) {

    this.identity = opts.identity
    this.key = opts.key
    this.rxNonce = new Uint8Array( copyBuffer(opts.offer.streamNonce) )
    this.txNonce = new Uint8Array( copyBuffer(opts.offer.streamNonce) )
    this.offer = opts.offer
  }

  async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    if(this.offer.mode.indexOf('chain') != -1){
      console.log('chaining')

      const nextTxNonce = Utils.randomBytes(12)
      const payload = BSON.serializeBSONWithoutOptimiser({
        nonce: this.txNonce,
        data: plaintext
      })

      let aesFn = gcmsiv(this.key, this.txNonce)

      this.txNonce = nextTxNonce

      return aesFn.encrypt(payload)

    } else {

      this.txNonce = Utils.randomBytes(12)
      let aesFn = gcmsiv(this.key, this.txNonce)
      const payload = BSON.serializeBSONWithoutOptimiser({
        nonce: this.txNonce,
        cipher: aesFn.encrypt(plaintext)
      })

      return payload

    }
    
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    if(this.offer.mode.indexOf('chain') != -1){
      console.log('chaining')
      
      let aesFn = gcmsiv(this.key, this.rxNonce)

      const plaintext = aesFn.decrypt(ciphertext)

      const payload = BSON.parseObject(new BSON.BaseParser(plaintext))

      this.rxNonce = payload.nonce

      return payload.data

    } else {

      const payload = BSON.parseObject(new BSON.BaseParser(ciphertext))
      this.rxNonce = payload.nonce
      let aesFn = gcmsiv(this.key, this.rxNonce)
      const plaintext = aesFn.decrypt(payload.cipher)

      return plaintext
    }
  }

  async getOffer() : Promise<IAESStreamOffer> {
    return this.offer
  }

  static async createStream(
    identity: Identity,
    to: Identity,
    requirePostQuantum: boolean = true,
    mode: 'chain+random' | 'random' = 'chain+random',
    info?: Uint8Array | string,
    salt?: Uint8Array | string,
    aesSize: number=256
  ) : Promise<IAESStream> {

    let pqSharedSecret = null

    if(requirePostQuantum){
      to.assertHasPostQuatumKEM()
      identity.assertHasPostQuatumKEM()
    }
    
    if(identity.hasPostQuatumKEM() && to.hasPostQuatumKEM()){
      
      pqSharedSecret = await createPQSharedSecret(to)
      
    }
    
    const naclSharedSecret = await createNaclSharedSecret(to, identity)
    const streamNonce = Utils.randomBytes(12)
    
    const streamKey = await AESStream.createStreamKey(
      naclSharedSecret,
      pqSharedSecret,
      info,
      salt,
      aesSize
    )
    
    const streamOffer = {
      sender: identity.toJSON(false),
      pqCipherText: pqSharedSecret.cipherText,
      streamNonce: streamNonce,
      mode: mode
    }

    return new AESStream({
      identity,
      key: streamKey,
      offer: streamOffer
    })
  }

  static async createStreamKey(
    naclSharedSecret: INaclSharedSecret=null,
    pqSharedSecret: IPQSharedSecret=null,
    info: Uint8Array | string=AES_OFFER_INFO,
    salt: Uint8Array | string=AES_OFFER_SALT,
    aesSize: number=256
  ) : Promise<Uint8Array> {
    
    let fullSecret = null

    if(naclSharedSecret && pqSharedSecret){
    
      fullSecret = Buffer.concat([ 
        Utils.base64.decode(naclSharedSecret.sharedSecret),
        Utils.base64.decode(pqSharedSecret.sharedSecret)
      ])

    } else if (naclSharedSecret && !pqSharedSecret){

      fullSecret = Utils.base64.decode(naclSharedSecret.sharedSecret)

    } else if (!naclSharedSecret && pqSharedSecret){

      fullSecret = Utils.base64.decode(pqSharedSecret.sharedSecret)
      
    }

    const streamKey = await Utils.hkdf('sha512', fullSecret, salt, info, aesSize/8)

    return streamKey

  }

  static async recoverStream(
    identity: Identity,
    offer: IAESStreamOffer,
    requirePostQuantum: boolean = true,
    info?: Uint8Array | string,
    salt?: Uint8Array | string,
    aesSize: number=256
  ) : Promise<IAESStream> {
    
    let pqSharedSecret = null

    const streamOffer = {
      pqCipherText: offer.pqCipherText,
      streamNonce: offer.streamNonce,
      sender: Identity.fromJSON(offer.sender),
      mode: offer.mode
    }


    if(requirePostQuantum){
      streamOffer.sender.assertHasPostQuatumKEM()
      identity.assertHasPostQuatumKEM()
    }
    
    if(identity.hasPostQuatumKEM() && streamOffer.sender.hasPostQuatumKEM()){
      
      pqSharedSecret = await recoverPQSharedSecret(identity, offer.pqCipherText)
      
    }

    const naclSharedSecret = await createNaclSharedSecret(streamOffer.sender, identity)

    const streamKey = await AESStream.createStreamKey(
      naclSharedSecret,
      pqSharedSecret,
      info,
      salt,
      aesSize
    )


    return new AESStream({
      identity,
      key: streamKey,
      offer: streamOffer,
    })

  }
}

