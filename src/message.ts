import Debug from "debug";
const logger = Debug("dataparty-crypto.Message");


import {
  encryptData, decryptData,
  signData, verifyData,
  signDataPQ, verifyDataPQ,
  BSON, Utils
} from "./routines";

export default class Message implements IMessage {
  enc: Uint8Array;
  sig: ISignature | Uint8Array;
  msg: any;

  from: IIdentityProps;

  constructor(opts: IEncryptedData) {
    this.enc = opts.enc;
    this.sig = opts.sig; //! Uint8Array when this.enc set, or object when this.msg set
    this.msg = opts.msg;
  }

  get sender() {

    if(this.enc){
      return this.from;
    }
    else{
      return (this.sig as ISignature).sender
    }
  }

  toBSON(): Uint8Array {
    return BSON.serializeBSONWithoutOptimiser({
      enc: this.enc,
      sig: this.sig
    })
  }

  fromBSON(bson: Uint8Array){
    const {enc, sig} = BSON.parseObject( BSON.BaseParser(bson) )

    this.enc = enc
    this.sig = sig
  }

  fromJSON(json){
    if(json.enc){ this.enc = Utils.base64.decode(json.enc) }
    if(json.sig){ this.sig = Utils.base64.decode(json.sig) }
    if(json.msg){ this.msg = Utils.base64.decode(json.msg) }
  }

  toJSON(){
    return {
      enc: this.enc ? Utils.base64.encode(this.enc) : undefined,
      sig: this.sig ? Utils.base64.encode(this.sig) : undefined,
      msg: this.msg ? Utils.base64.encode(this.msg) : undefined
    }
  }

  async sign(
    identity: IIdentity,
    requirePostQuantum: boolean = false,
    pqType: 'pqsign_ml' | 'pqsign_slh' = 'pqsign_ml'
  ) {
    if (!this.msg) {
      throw new Error("plaintext not available");
    }
    if (this.enc) {
      throw new Error("encypted messages already have signatures");
    }

    let msgToSign = this.msg
    /*if(! (msgToSign instanceof Uint8Array)){
      msgToSign = BSON.serializeBSONWithoutOptimiser(msgToSign)
    }*/

    let sigs = []
    logger('signing classic')
    sigs.push( await signData(identity, msgToSign) )

    if(requirePostQuantum){
      logger('signing pq')
      sigs.push( await signDataPQ(identity, msgToSign, pqType) )
    }

    sigs = sigs.map( sig=>{
      return {
        t: sig.timestamp,   // timestamp
        y: sig.type,        // type
        v: sig.value        // signature value
      }
    })

    const sigPayload = {
      sigs,
      hash: identity.key.hash,
    }


    this.sig = BSON.serializeBSONWithoutOptimiser( sigPayload )

    return true;
  }

  async assertVerified(from: IIdentity, requirePostQuantum: boolean = false) {
    let verified = await this.verify(from)

    if(!verified){
      throw new Error('message is not verified')
    }
  }

  async verify(
    from: IIdentity,
    requirePostQuantum: boolean = false
  ) {
    if (!this.msg) {
      throw new Error("plaintext not available");
    }

    if (!this.sig) {
      throw new Error("signature not available");
    }

    let sigObj = BSON.parseObject( new BSON.BaseParser(this.sig) )


    const classicSig = {
      timestamp: sigObj.sigs[0].t,
      type: sigObj.sigs[0].y,
      value: sigObj.sigs[0].v,
      sender: from.toMini()
    }
    
    logger('verify - classic')
    let verified = await verifyData(from, classicSig as ISignature, this.msg);

    if(requirePostQuantum || sigObj.sigs.length > 1){

      if(sigObj.sigs.length < 2){
        throw new Error('expected post quantum signature but none was found')
      }

      for(let i=1; i<sigObj.sigs.length; i++){
        logger('verify - postquantum[',i ,']')

        const pqSig = {
          timestamp: sigObj.sigs[1].t,
          type: sigObj.sigs[1].y,
          value: sigObj.sigs[1].v,
          sender: from.toMini()
        }
  
        verified = verified && await verifyDataPQ(from, pqSig as ISignature, this.msg)
      }

    }

    return verified
  }

  async decrypt(identity: IIdentity) {
    if (!this.enc) {
      throw new Error("ciphertext not available");
    }
    if (!this.sig) {
      throw new Error("signature not available");
    }

    const { data, from } = await decryptData(identity, this);

    this.msg = data;

    this.from = from;

    return this.msg;
  }

  async encrypt(from: IIdentity, toKey: IKey) {
    const result = await encryptData(from, toKey.public, this.msg);

    this.enc = result.enc;
    this.sig = result.sig;
    this.msg = null;

    return result;
  }
}
