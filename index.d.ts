declare interface IKeyBundle {
  box: string;
  sign: string;
}

declare interface IKey {
  type: "nacl";
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

declare interface ISignature {
  timestamp: number;
  sender: IIdentityMiniProps;
  value: string;
  type: string;   //! type of key used for signing (nacl vs pq_dsa65)
}

declare interface IIdentityMiniProps extends IKey {
  id: string;
}

declare interface IIdentity extends IIdentityProps {
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
