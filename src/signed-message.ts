import { hash } from "tweetnacl";

import { signData, verifyData } from "./routines";

export default class SignedMessage implements ISignedMessage {
    msg: IClearData;
    sigs: [ISignature];
  
    constructor(opts: ISignedData) {

      this.msg = opts.msg;
      this.sigs = opts.sigs;
    }

    hash() {
        return hash(this.msg.data)
    }

    async sign(signer: IIdentity, requirePostQuantum: boolean) {
        
    }
}