
import { Buffer } from 'buffer'
import Message from "./message";
import { createKey, createKeyFromMnemonic, createKeyFromPassword } from "./routines";

export default class POIdentity implements IIdentity {
  id: string;
  key: IKey;

  constructor(opts = {} as any) {
    this.id = opts.id || "";
    this.key = !opts || !opts.key ? createKey() : opts.key;
  }

  async encrypt(msg, to :IIdentity) {
    const message = new Message({ msg });
    await message.encrypt(this, to.key);

    return message;
  }

  async decrypt(input: IEncryptedData) {
    const message = new Message(input);
    await message.decrypt(this);

    return message;
  }

  async sign(msg: any) {
    const message = new Message({ msg });
    await message.sign(this);

    return message;
  }

  async verify(message: IMessage) {
    return message.verify(this);
  }

  /**
   *
   * @param extract if true, remove private key
   */
  toJSON(extract?: boolean) {
    return {
      id: this.id,
      key: {
        type: this.key.type,
        public: this.key.public,
        private: !extract ? undefined : this.key.private
      }
    };
  }

  toMini() {
    return {
      id: this.id,
      public: this.key.public,
      type: this.key.type
    };
  }

  toString() {
    return JSON.stringify(this.toJSON());
  }

  static fromString(input: string) {
    const parsed = JSON.parse(input);
    return new Identity(parsed);
  }

  static fromMnemonic(phrase: string) {
    return new Identity({
      key: createKeyFromMnemonic(phrase)
    });
  }

  static fromPassword(
    password: string,
    salt: Buffer,
    rounds?: Number
  ) {
    return new Identity({
      key: createKeyFromPassword(password, salt, rounds)
    });
  }
}
