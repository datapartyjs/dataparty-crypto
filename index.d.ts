declare interface IKeyBundle {
  box: string;
  sign: string;
}

declare interface IKey {
  type: "ecdsa";
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
