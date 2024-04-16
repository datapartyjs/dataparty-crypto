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
  //id: string;
  key: IKey;
}

declare interface ISignature {
  timestamp: number;
  sender: IIdentityMiniProps;
  value: [string];
  type: string;   //! type of key used for signing (nacl vs pq_dsa65 etc)
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
  toMiniBSON(): Buffer;
}

declare interface IClearData {
  data: Buffer
}

declare interface ISignedData {
  msg: IClearData,
  sigs: [ISignature]
}

declare interface IEncryptedData {
  enc: string;
  sig: ISignature;
  from: IIdentityProps;
}

declare interface ISignedMessage extends ISignedData {
  verify(verifier: IIdentityProps, requirePostQuantum: boolean): Promise<boolean>;
  verifyAll(requirePostQuantum: boolean): Promise<boolean>;
  sign(signer: IIdentity, requirePostQuantum: boolean): Promise<boolean>;
  signers(requirePostQuantum: boolean): Promise<[IIdentityProps]>;
  encrypt(from: IIdentity, requirePostQuantum: boolean): Promise<IEncryptedData>;

  assertVerifyAll(requirePostQuantum: boolean): void; 
  assertVerifySigner(verifier: IIdentityProps, requirePostQuantum: boolean): void;

  hash(): Uint8Array;

  toJSON(): Object;
  toBSON(): Buffer;
}

declare interface IEncryptedMessage extends IEncryptedData {
  decrypt(requirePostQuantum: boolean): Promise<ISignedMessage>;
  verify(verifier: IIdentityProps, requirePostQuantum: boolean): Promise<boolean>;

  hash(): Uint8Array;

  toJSON(): Object;
  toBSON(): Buffer;
}

declare interface IClearMessage extends IClearData {
  sign(signer: IIdentity): Promise<ISignedMessage>;
  encrypt(from: IIdentity, to: IIdentityProps): Promise<IEncryptedMessage>;

  hash(): Uint8Array;

  toJSON(): Object;
  toBSON(): Buffer;
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
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
}

declare interface IAESStreamOffer {
  sender: IIdentity;
  pqCipherText: string;
  streamNonce: string;
  stream?: IAESStream;
}
