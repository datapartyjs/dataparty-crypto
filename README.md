# @dataparty/crypto
[![stable](http://badges.github.io/stability-badges/dist/stable.svg)](http://github.com/badges/stability-badges)[![license](https://img.shields.io/github/license/datapartyjs/dataparty-crypto)](https://github.com/datapartyjs/dataparty-crypto/blob/master/LICENSE)

dataparty cryptography


 * NPM - [npmjs.com/package/@dataparty/crypto](https://www.npmjs.com/package/@dataparty/crypto)
 * Code - [github.com/datapartyjs/dataparty-crypto](https://github.com/datapartyjs/dataparty-crypto)
 * Support - [ko-fi/dataparty](https://ko-fi.com/dataparty)

`It slices, it dices, and it enciphers`

## Features

 * Based on [TweetNaCL](https://www.npmjs.com/package/tweetnacl)
 * Password derived keys
   * `argon2id` - [See example](https://github.com/datapartyjs/dataparty-crypto/blob/master/examples/example-password-argon2.js)
   * `pbkdf2` - [See example](https://github.com/datapartyjs/dataparty-crypto/blob/master/examples/example-password-pbkdf2.js) - [warning outdate](https://medium.com/@alanmeekins/wtf-is-a-kdf-a267bda53e8f)
 * Mnemonic derived keys seed phrases



### Identity

Creating a random key pair

```
const dataparty_crypto = require('@dataparty/crypto')

const alice = new dataparty_crypto.Identity({id:'alice'})
const bob = new dataparty_crypto.Identity({id:'bob'})
```


### Messages


```
let encryptedMessage = new dataparty_crypto.Message({
    msg: {
        data: 'hello world'
    }
})
```

#### Encryption

```
//! Bob encrypts the message
await encryptedMessage.encrypt(bob, alice.toMini())

sendToAlice( encryptedMessage.toJSON() )
```

#### Decryption

```
//! Later alice decrypt a message
const decryptedMessage = new dataparty_crypto.Message(msgFromBob)

await decryptedMessage.decrypt(alice)

console.log(`alice read: ${JSON.stringify(decryptedMessage.msg,null,2)}`)

//! Another way to verify that bob sent the message
await decryptedMessage.assertVerified(bob)
```

#### Signing

```
//! Alice signs a message
const signedMsg = await alice.sign({a:'hello world'})

sendToAlice( signedMsg.toJSON() )
```


#### Verifying

```
const signedMsg = new dataparty_crypto.Message(msfFromAlice)

//! Verify that Alice sent the message
const verified = await alice.verify(signedMsg)
console.log('verified?', verified)

//! Another way to verify that alice sent the message
await signedMsg.assertVerified(alice)
```

#### Password defivation

```
const password = 'super-strong-password'
const salt = await dataparty_crypto.Routines.generateSalt() //! Salt would be read from disk after 1st run

const key = await dataparty_crypto.Routines.createKeyFromPasswordArgon2(
    argon2,
    "supersecretpassword123",
    salt
)
```

# Developing

 * `npm build`
 * `npm watch`
 * `npm test`

# Support

Buy us a coffee!

 * [ko-fi/dataparty](https://ko-fi.com/dataparty)
