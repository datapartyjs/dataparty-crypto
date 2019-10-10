import { encryptData, signData, verifyData, decryptData } from "./routines";

export default class Message implements IMessage {
  enc: string;
  sig: string | ISignature;
  msg: any;

  from: IIdentityProps;

  constructor(opts: IEncryptedData) {
    this.enc = opts.enc;
    this.sig = opts.sig; //! String when this.enc set, or object when this.msg set
    this.msg = opts.msg;
  }

  get sender() {
    return this.from.key;
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

  async verify(from: IIdentity) {
    // TODO: Investigate type loop hole. I.e this.sig can be string or object.
    // string is encrypted, and object is decrypted
    return verifyData(from, this.sig as ISignature, this.msg);
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
