# @dataparty/crypto
[![stable](http://badges.github.io/stability-badges/dist/stable.svg)](http://github.com/badges/stability-badges)[![license](https://img.shields.io/github/license/datapartyjs/dataparty-crypto)](https://github.com/datapartyjs/dataparty-crypto/blob/master/LICENSE)

dataparty cryptography


 * NPM - [npmjs.com/package/@dataparty/crypto](https://www.npmjs.com/package/@dataparty/crypto)
 * Code - [github.com/datapartyjs/dataparty-crypto](https://github.com/datapartyjs/dataparty-crypto)
 * Support - [ko-fi/dataparty](https://ko-fi.com/dataparty)

`It slices, it dices, and it enciphers`

## Features

 * Flexible
   * BSON and JSON supported
   * Classic and Post-Quantum encryption
 * GPU Resistant
   * SHA-512 for hashing
   * AES-512-SIV for streaming encryption
 * Post-Quantum Ready
 * `Identity` contains classic and post quantum key pairs
   * TweetNaCL Box & Sign Keys
   * Crystal-Kybers KEM Key
     * default: ml_kem768
     * Supported: ml_kem512, ml_kem768, ml_kem1024
   * Dilithium Signing Key
     * default: ml_dsa65
     * Supported: ml_dsa44, ml_dsa65, ml_dsa87
   * SPHINCS+ Singing Key 
     * default: slh_dsa_sha2_128f
     * Supported: slh_dsa_sha2_128f, slh_dsa_sha2_128s, slh_dsa_sha2_192f, slh_dsa_sha2_192s, slh_dsa_sha2_256f, slh_dsa_sha2_256s 
 * Mnemonic derived keys seed phrases - [See example](https://github.com/datapartyjs/dataparty-crypto/blob/master/examples/example-seed-phrase.js)
   * bip39 - Phrases are generated using [bip39](https://github.com/bitcoinjs/bip39).
      * argon2 hashing protects seed phrase + password
   * pharses are combined with a password using `argon2` instead of the typical `pbkdf2`
 * Password derived keys
   * `argon2id` - [See example](https://github.com/datapartyjs/dataparty-crypto/blob/master/examples/example-password-argon2.js)
   * `pbkdf2` - [See example](https://github.com/datapartyjs/dataparty-crypto/blob/master/examples/example-password-pbkdf2.js) - [warning this algo is not GPU resistant](https://blog.dataparty.xyz/blog/wtf-is-a-kdf/)

## Quick Start

`npm i --save @dataparty/crypto`


### `dataparty_crypto.Identity`

Interface:

```typescript

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

declare interface IIdentity extends IIdentityProps {
  seed?: Uint8Array;

  assertHasPostQuatumKEM(): void;
  hasPostQuatumKEM(): boolean;

  createStream(to: IIdentity, requirePostQuantum: boolean, info?: Uint8Array | string, salt?: Uint8Array | string): Promise<IAESStreamOffer>;
  recoverStream(offer: IAESStreamOffer,requirePostQuantum: boolean, info?: Uint8Array | string, salt?: Uint8Array | string): Promise<IAESStream>

  toString(extract?: boolean): string;
  toBSON(extract?: boolean): Uint8Array;
  toJSON(extract?: boolean): IIdentityProps;
  toMini(includePostQuantum?: boolean): IIdentityMiniProps;
}
```

Creating a random key pair

```js
const dataparty_crypto = require('@dataparty/crypto')

const alice = await dataparty_crypto.Identity.fromRandomSeed({id:'alice'})
const bob = await dataparty_crypto.Identity.fromRandomSeed({id:'bob'})
```

<details>
<summary>
Example Identity
</summary>

#### Example Identity

```js
Identity {
  id: 'alice',
  key: {
    type: 'nacl,nacl,ml_kem768,ml_dsa65,slh_dsa_sha2_128f',
    hash: 'EVDkJ0Tzxf/Fmk6m/mnyKGyU25DX77RP8lAA6w/SWgyYrhotaWMl14CcDg/4xQhU7vf6HdjNl4q9QB4c12EbWg==',
    public: {
      box: 'jN71VnPrgWRqIy4iBFILOpQcvCM7P6mFRDuIM2cMODQ=',
      sign: 'tZ/qd7uVTGkr4yAzg8GVujL8mYiuZxJv8d31euaPJqE=',
      pqkem: '6ro1vFjMoea1qvPBIqpLnjiMkdNRl1A9A9EPkIZ9d2DJtXvOc9TOKjt0/Bg7Z/M2rSg7JKYonApr+JG+SjtfqqlOmFHEItgLeBA6S1clzXVXX8gnXMVNb0Bq6fKEEOGOtPm+j5F6Y8Y0KUW4mJJ2Y3Nsb0NvU0QbEAxPMliU1eUc4vpvsVMsiBtEMDeaUkkfMZi6UXGWPXnHiawRDAUPr5mjXpcPzcPEVzhdoAIRVrZFzoVdnNS0OBNmptiw/eXOq1FzM5hqYUSaxruA+loo2jR0wjdvzkwp1wlPXQUEJvk0RAE8SirJyzhfC9WLbuA9vBs7iQwJC1SIJptpkEtHLtMclAcclFS1yfsXspFh5ENeaAq194YQQgaez6IWgDxk+Cw5rAZ7xxNjlyFv/jypJzcsNcEFNFUc0tU8Yfds3SkdzTNgTrAaXzVHm8miTPN1AcBj5CQfIDR/6JKt/PV60tyEgSxGgfCHO+JyRcu5RfYs2/Za1vOsftlkBZlOv+lxVudQo1EwF8Gkk8kS8ciMG3tm2aDE97xD1gOgYCIvxAkldbCGppI7uHoIS3EsKeQ+r4ovFbiDE3MljDIGqVmoCAqnWXl2yhK3lTOZ/GQ+5cRf3SqnQNKJZDpMKWKfkHcIgZmZS5ZvwcpLJ3Si+HIkNHHD4ANn4aGc3zxSsuEW8CYgtVpLx0ynXpA8KpMBDNwqFLMsdjtPzEIzFLeiJTh1WFpDRXRuLyljVDIq/HqGNSw+q3oHlpdb54O4d/NSAElSdelY+MK+sFTHohnGsRC135Io0AFnwZZchfSGeSd3nRtqf5ZdH8YQEFoNVQAQ4HyOt/mnk7ODUNZrKDJ4zpJExDbA1XeHS3kn9Ow2ADTFd8J3Uhx7IVY8GpJwu2tWDMNClXI5algd9BtHzLfGLxZB/Mp6unYqYUuDyRV2uFMIsEl6ynwFBGp2KxsYRPuH5YyxrDW4D+iDRzUXuBAnV7IS5bbKQyDEzmCLEFyz2hDKXBGD1OMuK3C8D9OQ4XFJKvOtGseZ+LQgKdmwwgpnsimwmsq+sdh9O7nGEjRBmZefp7h/OUAu4FiZAltCk/OYVEzEBChnzpyifLVbtVQS/0XFgxwXMtU8y5paMnAd6DyjbBcfbBREVxwzeELN5OwUA+Njgxxde8N6vFfGR/Yf/OAFqaU+mtkpcKced6IAa6rJNWxZ6+UKMtZLM/vJCMkPTrcGpUyR/haibkRCr/sRoLS+vvmLtROdetxjiEedhstlxiVhT2kNbXAbuGCAIWcnHhqCJ+plp7pCPeVtHAEAeYEcnix6TdWx6ORSFfu7ZAjNRlGNeJDG99EMxLZcXeTDL5JyTRWDfxAPKQl7fXJXxbMkBUtZzRqqMBub3RZvOGdm7wZzQJIwoHpzH8IATdseo0g4UYWcqHGDUxyJpkoVjPNUJ1esc8Nj5RBXuaavAFOSJQygL3yCvaWBwPh4rDe5JEMO+vBEB0g4dzUPfLYbk5wEihbAZ2lpEUR845AAPezMvrph85ZsC4oOpoJj5QiLOvWCLsTdoSF8xtwBSX3CGoWVgHq0pb2fcZWIs0dOommt9z0=',
      pqsign_ml: 'OOYop5SuCz74F8fMY04AVHxinGyUGMvY8grmkXNsCzqov4uWbk8hS8tRadEqcQs3fXD7m861dCMfTp/ghHyyPovWRit5nF0Ps6tscQSdpdZf1gaNsQJp48L+AHto2pil3QzNZYoeRxHlsCDMPJvJzcOlHHgmERqG5A5W/wkcI0bdPaZ52Df0uUhiVeiTi5YZvFGs/t4bWHaSTWOQaGVBflWol2ko+1/dY8hoPMDsKshO7tNgfpyBwZ6wgjr+KxdYiO8bsSsc7Wu99lzbe6KGB0z/u+yf90NnoI+xbN6RPhXiaABrZZq3fr70tlSIe89WWOJPXfuXZmpVotUIW21tghPpcP+T0c0RrWVsL7J3wQRg/+zPqOnlZvJZskonAS0enkMVMyIuRt+6gZU1CrHLvX/5yMjPKnKY9yJ+u4TGX3LLjo5WwKh5IuUOZDeGR+cxokhG6on/4vfBZvLn5Tpewnu7txYH6b/EkVfqZfElP3RqCRfyB1pUuaK8nFUoWaB8r8zd5BVXynNSOTzQ990iH3+35qDHnTCSKgEzTaaBp2njq/aT3qTtCNWNaCj4s28mYA3AQ0yLzJTjrblIKkDAFzAqLtwGOZ/8OJWawhmlTsqyV5aEjSRN06/FEG1WdmUptbiiz9KPEjff5Tny/r9L+Nayq4pFJgjLTLI/Ow3szWMA96tRJGSMismWHQrBHN1bp+PnDP4SOSUUWdcYngJV8WsTfLUvzEf+n8o8Ng8qeC+tLczOgB/Vck9xj4d+vKPjy0s1KTt7ZGs5SYRPCThqFIEGp6i/MlF9kuND0gaxZH5eBZ2yirQr3fsrlCOInhptpDYJZT2sO8ofMBl/dVZmt7pgPXo4qYvb28/6rs9hTMa8M0BZ9xb065+yLspiP7K5X/knBCZnUVI576fIk8m1xoLC43HGT033bIaoZdLpl4kMK7h25AOwNfSNV6GoQ4hSJMs0nBgemqhGXcHmpHYN+jt7PabWb3QeOPSUFRbxeSiAlXaBYasLLpqOBUk7qgPoVDOdDuvdiHBO2upnPbqVXSOgah9IADuejPJD0rEy8Io6JynJXe/Wy4SlVMqfCAEll7k1+jFRb73uUgBGHr9tr7Kcs63dnxW0Z5cBq6gim5lmSKmX2ga9KAWN4UgMoXAA1oWh7Q/iP1b+rMiNMtgdS8tittWoRgR9ld1ww4s9+Zk48gH6snIqGacrVR6Xi935sG5bq5j3Y+20l3mP6Ir0QKwj5MaEuBP5OLTuwxX+Ij7uM7cf43nz/hFgUFPqrIj64YcDKDoMuVTN61r56rjhvhaS3lp0/MW2aBqrxnHfRlnT2admMZ5Wxaq9M0ZsjHLTB5j3lcMHbG8m+UtKoXwL8b2/ls1GToh5cfrpBjZLlfZZXRVjbUInoPv8y4h0sNhp/0Tu3+j3X3mOnoS6GSEmnGz/4Vx8MG8KnRbn/jk6OaK/Gx8s6+7PIFcUxJAHRBn9TYC6PjyuHhkNySjLdWT9wnQp8sSKdAK6pLCxlpm9b7MkT56p4tdOEyVn9inuwlv3Y9DuB8krVC8rVP4By1sg6vXTnPgmdq3gIr3UMpsgykMRVnEnBvAxb5KNAaukY7nlwEdA8I4UcBW/j9lUoAl72HUJkkYkOMThsPNFyJiMt9G7RrKypbpIDzyDn/03d7oJNkGbZMaRAsXX4QOowgqPqqM84NxQlxFzfnFfYPvsrP04yRXirbXcheexXYe1+BqNnSKf4l0n+lQh/6Mizbk05wZR6t6XTaHPanznYP8Uh/QSdcpoaNlRfNMf5NkpkSjjB/Vq3RRDXIrdbTtNf/+Sdyq0YJM9Y/V58plwQdmJWCsFHzpFrjKrwyZ7fR/rpum5Mb51+TkC1mCLc3kgi//V6FVXEcUFkDUKkRm21Pfrkd57I47q6H9q+164HTccEOlUWm9oXNovmYG4ioNOwxtoQUDYV+/al2kCmInFYcqyMl9daZ0x+vbz88D1RsC43ZNlQ7aunt4ABdlnhvLD0bs/Wwtq6iar5dYj3HOHTgG1SdkK5IOtu1xQZIAg0OW7YTTBAQSNoAyvI9hs8S6f+m1cW6GtNJWN7lmNSeoamLNJQzNummvYj4dfONq1DUlgBued7osJdgG+4q/i9b2pmA52R7sXSsnfEVuVqAXoLsoqNVrAlw60/mAME3p0wKWONIE57bdZ9h2FXvNASoLgUeIQFqEDzuw9y0ia/oeVfG6F1e3I1Mt1cIBnSvtLPvAjmyEJK8TN/+k5PD77sXfLKdQznIkaUm9RrmPr14olbvNyQwvZZw36YIcbEf4yftsQxUp3XC48G5bIygWP5n7cXYXKcOWG9vZJ92U7QtMBS/fAlejsT82fLcQun9Deh1LT8wmWyyPxHBzHRV5b/WEljoyCJMvdNdFpyzhYkchJLZ/c+ez0owAVaB3RnVHyspd6LoI5fKg2yhOwjTdxoGHbYxf1jEVGdD5hyoiqTCUdNqplu9CVJutVJ5OvljIFRnUzxmxXiRdY/eie5/w0jq1YP57c29HweCJQROUGbtb/pWeABomhgIoLDfuwzRqJwFkQuteUUSU6N8F5trXFxFTqeN7Unzt+LEcO99bWt+bw2nb15bU=',
      pqsign_slh: 'sjPSwRTN13yE6BMprCBGdjNlxukf7d6ZYVUS74vBdag='
    },
    private: {
      box: '8hDf6l/adnQciapBGCPZM9319yAdsS6XfBr0EE5BaEQ=',
      sign: 'aklVlHmnAUc3cDgT2gEjfyowBoca1VUKl249EGuO87K1n+p3u5VMaSvjIDODwZW6MvyZiK5nEm/x3fV65o8moQ==',
      pqkem: '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',
      pqsign_ml: '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',
      pqsign_slh: 'pdSMEve5C0UvkktrcnaO0NB44JaNH7xyBl1oDtxC19CyM9LBFM3XfIToEymsIEZ2M2XG6R/t3plhVRLvi8F1qA=='
    }
  },
  seed: Uint8Array(64) [
     79, 147,  65,  32,   0,  40, 157,  82,  88, 205, 169,
     13,  12, 141, 253,  99, 137,  34, 159,  67, 176, 149,
     98,  22,  74, 209,  75, 205, 161,  76, 128, 118, 178,
     85, 122,  22,  33, 121, 239,  69, 135,  18,  94, 155,
    121,  23, 202, 120,  82,  14,  45, 214, 140, 232, 112,
    242, 239,  61, 128, 116,  60, 185, 110, 121
  ]
}
```

</details>


#### Identity derivation from passsword using argon2

```js
const password = 'super-strong-password'
const salt = await dataparty_crypto.Routines.generateSalt() //! Salt would be read from disk after 1st run

const key = await dataparty_crypto.Identity.createKeyFromPasswordArgon2(
    argon2,
    "supersecretpassword123",
    salt
)
```

#### Generating Identity from mnemonic phrase

Identity's can be generated using a bip39 mnemonic phrase along with an optional password.

```js
const argon2 = require('argon2')
const dataparty_crypto = require('@dataparty/crypto')

const phrase = await dataparty_crypto.Routines.generateMnemonic()

console.log('recovery phrase', phrase)

let key = await dataparty_crypto.Identity.fromMnemonic(phrase, 'password123', argon2)

```


### `dataparty_crypto.Message`

Interface:

```typescript
declare interface IEncryptedData {
  enc?: Uint8Array;
  sig?: Uint8Array | ISignature;
  msg?: any;
  from?: IIdentityProps;
}

declare interface IMessage extends IEncryptedData {
  verify(verifier: IIdentity, requirePostQuantum: boolean): Promise<boolean>;
  assertVerified(from: IIdentity, requirePostQuantum: boolean): Promise<void>;
  sign(signer: IIdentity, requirePostQuantum: boolean, pqType: string): Promise<boolean>;
}
```

Example Usage:


```js
const dataparty_crypto = require('@dataparty/crypto')

let encryptedMessage = new dataparty_crypto.Message({
    msg: {
        data: 'hello world'
    }
})
```

#### Encryption

```js
const dataparty_crypto = require('@dataparty/crypto')

const alice = await dataparty_crypto.Identity.fromRandomSeed({id:'alice'})
const bob = await dataparty_crypto.Identity.fromRandomSeed({id:'bob'})


let msgForBob = new dataparty_crypto.Message({msg:{
    myValue: 'hello world'
}})


await msgForBob.encrypt(alice, bob.key)

console.log('bob decrypted value ', value)
```

#### Decryption

```js

//! Later bob decrypts a message

await msgForBob.decrypt(bob)

console.log(`bob read: ${JSON.stringify(msgForBob.msg,null,2)}`)
```

#### Signing

```js
//! Alice signs a message
const signedMsg = await alice.sign({a:'hello world'})

sendToAlice( signedMsg.toJSON() )
```


#### Verifying

```js
const signedMsg = dataparty_crypto.Message.fromJSON(msfFromAlice)

//! Verify that Alice sent the message
const verified = await alice.verify(signedMsg)
console.log('verified?', verified)

//! Verify alice's signature and throw an error if invalid
await signedMsg.assertVerified(alice)
```

### `AESStream`

Interface:

```typescript
declare interface IAESStream {
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
}

declare interface IAESStreamOffer {
  sender: IIdentity;
  pqCipherText: string;
  streamNonce: string;
  stream?: IAESStream;
}
```

Example usage:

```js

const aliceFullKey = await dataparty_crypto.Identity.fromRandomSeed({id: 'alice'})
const bobFullKey = await dataparty_crypto.Identity.fromRandomSeed({id: 'bob'})


const bobPublicKey = bobFullKey.publicIdentity()


const aliceOffer = await aliceFullKey.createStream( bobPublicKey )

console.log(aliceOffer)
console.log('bob has stream')

const aliceMsg = await aliceOffer.stream.encrypt(new TextEncoder().encode('time to party'))
const aliceMsg2 = await aliceOffer.stream.encrypt(new TextEncoder().encode('rock on ninjas!'))
const aliceMsg3 = await aliceOffer.stream.encrypt(new TextEncoder().encode('🖤'))



console.log('aliceMsg1 [', aliceMsg, ']')
console.log('aliceMsg3 [', aliceMsg3, ']')
console.log('aliceMsg2 [', aliceMsg2, ']')

const bobMsg = await bobStream.decrypt(aliceMsg)
const bobMsg2 = await bobStream.decrypt(aliceMsg2)
const bobMsg3 = await bobStream.decrypt(aliceMsg3)


console.log( bobFullKey.key.public )

console.log('msg1 [', new TextDecoder().decode(bobMsg), ']')
console.log('msg3 [', new TextDecoder().decode(bobMsg3), ']')
console.log('msg2 [', new TextDecoder().decode(bobMsg2), ']')
```


# Developing

 * `npm build`
 * `npm watch`
 * `npm test`

# Support

Buy us a coffee!

 * [ko-fi/dataparty](https://ko-fi.com/dataparty)
