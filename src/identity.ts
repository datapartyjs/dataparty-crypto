import { Buffer } from 'buffer'
import Message from "./message";
import {
  getRandomBuffer,
  getMnemonicFromSeed,
  createKey,
  createSeedFromMnemonic,
  createSeedFromPasswordPbkdf2,
  createSeedFromPasswordArgon2
} from "./routines";

export default class Identity implements IIdentity {
  id: string;
  key: IKey;
  seed?: Buffer;

  constructor(opts = {} as any) {
    this.id = opts.id || "";
    this.key = !opts || !opts.key ? null : opts.key;
    this.seed = !opts || !opts.seed ? null : opts.seed;
  }

  async initialize(){
    if(this.key != null && this.key.private){
      throw new Error('identity already initialized')
    }

    if(!this.seed){ this.seed = await getRandomBuffer(64) }

    let type = undefined
    if(this.key && this.key.type){ type = this.key.type }

    this.key = await createKey(this.seed, true, type)
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
  toJSON(extract: boolean = false) {
    return {
      id: this.id,
      seed: extract==true ? this.seed :  undefined,
      key: {
        type: this.key.type,
        hash: this.key.hash,
        public: this.key.public,
        private: extract == true ? this.key.private : undefined
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
    const seed = await getRandomBuffer(64)
    const key = await createKey(seed)

    return new Identity({ key, seed })
  }

  static async fromMnemonic(phrase: string, password: string, argon2: any) {
    const seed = await createSeedFromMnemonic(phrase, password, argon2)

    console.log('seed type', typeof seed)

    const key = await createKey( seed )

    return new Identity({ key, seed })
  }

  static async fromPasswordPbkdf2(
    password: string,
    salt: Buffer,
    rounds?: number
  ) {
    const seed = await createSeedFromPasswordPbkdf2(password, salt, rounds)
    const key = await createKey( seed )

    return new Identity({ key, seed })
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
    const seed = await createSeedFromPasswordArgon2(
      argon,
      password,
      salt,
      timeCost,
      memoryCost,
      parallelism,
      type,
      hashLength
    )

    const key = await createKey( seed )

    return new Identity({ key, seed })
  }
}
