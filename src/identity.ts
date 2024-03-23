
import { Buffer } from 'buffer'
import Message from "./message";
import { 
  createKey,
  createSeedFromMnemonic,
  createSeedFromPasswordPbkdf2,
  createSeedFromPasswordArgon2
} from "./routines";

export default class Identity implements IIdentity {
  id: string;
  key: IKey;

  constructor(opts = {} as any) {
    this.id = opts.id || "";
    this.key = !opts || !opts.key ? null : opts.key;
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
        hash: this.key.hash,
        public: this.key.public,
        private: !extract ? undefined : this.key.private
      }
    };
  }

  toMini() {
    return {
      hash: this.key.hash,
      type: this.key.type,
      public: this.key.public
    };
  }

  toString() {
    return JSON.stringify(this.toJSON());
  }

  static fromString(input: string) {
    const parsed = JSON.parse(input);
    return new Identity(parsed);
  }

  static async fromRandomSeed(){
    const key = await createKey()

    return new Identity({ key })
  }

  static async fromMnemonic(phrase: string) {
    const key = await createKey(
      await createSeedFromMnemonic(phrase)
    )

    return new Identity({ key })
  }

  static async fromPasswordPbkdf2(
    password: string,
    salt: Buffer,
    rounds?: number
  ) {
    const key = await createKey(
      await createSeedFromPasswordPbkdf2(password, salt, rounds)
    )

    return new Identity({ key })
  }

  static async fromPasswordArgon2(
    argon: any,
    password: string,
    salt?: Uint8Array,
    timeCost?: Number,
    memoryCost?: Number,
    parallelism?: Number,
    type?: string,
    hashLength?: Number
  ) {
    const key = await createKey(
      await createSeedFromPasswordArgon2(
        argon,
        password,
        salt,
        timeCost,
        memoryCost,
        parallelism,
        type,
        hashLength
      )
    )

    return new Identity({ key })
  }
}
