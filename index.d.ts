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

declare interface ISignature {
  timestamp: number;
  sender: IIdentityMiniProps;
  value: string;
  type: string;   //! type of key used for signing (nacl vs pq_dsa65)
}

declare interface IIdentityMiniProps extends IKey {
  hash: string;
  type: string;
  public: IKeyBundle
}

declare interface IIdentity extends IIdentityProps {
  seed?: Buffer;

  assertHasPostQuatumKEM(): void;
  hasPostQuatumKEM(): boolean;

  createStream(to: IIdentity, requirePostQuantum: boolean, info?: Uint8Array | string, salt?: Uint8Array | string): Promise<IAESStreamOffer>;
  recoverStream(offer: IAESStreamOffer,requirePostQuantum: boolean, info?: Uint8Array | string, salt?: Uint8Array | string): Promise<IAESStream>

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

declare interface IPQSharedSecret {
  cipherText: string;
  sharedSecret: string;
}

declare interface INaclSharedSecret {
  sharedSecret: string;
}

declare interface IAESStream {
  rxNonce: Uint8Array;
  txNonce: Uint8Array;
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
}

declare interface IAESStreamOffer {
  sender: IIdentity;
  pqCipherText: string;
  streamNonce: string;
  stream?: IAESStream;
}
