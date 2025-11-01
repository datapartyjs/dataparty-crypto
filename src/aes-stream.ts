import { Buffer } from 'buffer'
import Message from "./message";
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
  mode: 'chain+counter' | 'counter' | 'chain+random'

  constructor(opts = {/*identity, key, nounce, offer, mode*/} as any) {

    this.identity = opts.identity
    this.key = opts.key
    this.rxNonce = new Uint8Array( copyBuffer(opts.nounce) )
    this.txNonce = new Uint8Array( copyBuffer(opts.nounce) )
    this.offer = opts.offer
    this.mode = opts.mode
  }

  async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    const nextTxNonce = /* this.txNonce */ Utils.randomBytes(12)
    const payload = BSON.serializeBSONWithoutOptimiser({
      nonce: nextTxNonce,
      data: plaintext
    })

    let aesFn = gcmsiv(this.key, this.txNonce)

    this.txNonce = nextTxNonce

    return aesFn.encrypt(payload)
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    let aesFn = gcmsiv(this.key, this.rxNonce)

    const plaintext = aesFn.decrypt(ciphertext)

    const payload = BSON.parseObject(new BSON.BaseParser(plaintext))

    this.rxNonce = payload.nonce

    return payload.data
  }

  async getOffer() : Promise<IAESStreamOffer> {
    return this.offer
  }

  static async createStream(
    identity: Identity,
    to: IIdentity,
    requirePostQuantum: boolean = true,
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


    /**
     *  sender: IIdentity;
     *  pqCipherText: string;
     *  streamNonce: string;
     */

    const streamOffer = {
      key: streamKey,
      nounce: streamNonce,
      identity: identity.publicIdentity()
    }

    return new AESStream({
      identity,
      key: streamKey,
      nounce: streamNonce,
      offer: streamOffer,
      mode: 'chain+random'
    })
  }

  /*static recoverStream(
    from: IIdentity,
    offer: IAESStreamOffer,
    requirePostQuantum: boolean = true,
    info?: Uint8Array | string,
    salt?: Uint8Array | string
  ) : Promise<IAESStream> {
    //
  }*/
}

