declare interface IKeyBundle {
  box: string;
  sign: string;
  pqkem?: string;
  pqsign_ml?: string;
  pqsign_slh?: string;
}

declare interface IKey {
  type: string;
  hash: string,
  private?: IKeyBundle;
  public: IKeyBundle;
}

declare interface IIdentityProps {
  id: string;
  key: IKey;
  
}

declare interface IPQSharedSecret {
  cipherText: string;
  sharedSecret: string;
}

declare interface INaclSharedSecret {
  sharedSecret: string;
}

declare interface ISignature {
  timestamp: number;
  sender: IIdentityMiniProps;
  value: string;
  //type: string;   //! type of key used for signing (nacl vs pq_dsa65)
}

declare interface IIdentityMiniProps extends IKey {
  hash: string;
  type: string;
  public: IKeyBundle
}

declare interface IIdentity extends IIdentityProps {
  seed?: Buffer;
  toJSON(extract?: boolean): IIdentityProps;

  toMini(): IIdentityMiniProps;
}

declare interface IEncryptedData {
  enc?: string;
  sig?: string | ISignature;
  msg?: any;
  from?: IIdentityProps;
}

declare interface IMessage extends IEncryptedData {
  verify(verifier: IIdentity): Promise<boolean>;
  sign(signer: IIdentity): Promise<boolean>;
}

declare interface IDecryptedData {
  data: any;
  from: IIdentityProps;
}

declare interface IAESStream {
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
}

/*

declare interface IAESStreamOffer {
  sender: IIdentity;
  pqCipherText: string;
  streamNounce: string;
}


Client      <->      Server
get /identity   ->    |
  |    <-   FullIdentity(root),


*/
