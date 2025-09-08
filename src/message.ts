import {parseObject, ParserV3, serializeBSON} from '@deepkit/bson';

import { encryptData, signData, verifyData, decryptData } from "./routines";

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
    return serializeBSON({
      enc: this.enc,
      sig: this.sig
    })
  }

  fromBSON(bson: Uint8Array){
    const {enc, sig} = parseObject( ParserV3(bson) )

    this.enc = enc
    this.sig = sig
  }

  toJSON(){
    return {
      enc: this.enc,
      sig: this.sig,
      msg: this.msg
    }
  }

  async sign(identity: IIdentity) {
    if (!this.msg) {
      throw new Error("plaintext not available");
    }
    if (this.enc) {
      throw new Error("encypted messages already have signatures");
    }

    this.sig = await signData(identity, this.msg);

    return true;
  }

  async assertVerified(from: IIdentity) {
    let verified = await this.verify(from)

    if(!verified){
      throw new Error('message is not verified')
    }
  }

  async verify(from: IIdentity) {
    if(this.enc){
      await this.decrypt(from)
    } else {
      return verifyData(from, this.sig as ISignature, this.msg);
    }
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
