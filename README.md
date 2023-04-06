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
 * Mnemonic derived keys seed phrases



### Identity

Creating a random key pair

```
const Crypto = require('@dataparty/crypto')

const alice = new Crypto.Identity({id:'alice'})
const bob = new Crypto.Identity({id:'bob'})
```


### Message


```
let msg1 = new Crypto.Message({
  msg: {
    data: 'hello world'
  }
})

return msg1.encrypt(bob, alice.key.public).then((msg)=>{
  
  return msg.decrypt(alice).then((data)=>{
    console.log(`alice read: ${JSON.stringify(data,null,2)}`)
  })
  
})
```

# Developing

 * `npm build`
 * `npm watch`
 * `npm test`

