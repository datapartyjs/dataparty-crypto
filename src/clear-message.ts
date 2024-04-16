

export default class ClearMessage implements IClearMessage {
    data: String | Buffer;
  
    constructor(opts: IClearData) {

      this.data = opts.data
    }

    async sign(signer: IIdentity) {
        // Promise<ISignedMessage>

    }

    async encrypt(from: IIdentity, to: IIdentityProps) {
        // Promise<IEncryptedMessage>
    }
}