# dataparty-crypto
dataparty Cryptography

`It slices, it dices, and it enciphers`


## Identity

```
const Crypto = require('@dataparty/crypto')
const identity = new Crypto.Identity({id:'primary'})
const alice = new Crypto.Identity({id:'alice'})
```


## Message


```
let msg1 = new Message({
  msg: {
    data: 'hello world'
    }
  }
})

return msg1.encrypt(identity, alice.key.public).then((msg)=>{
  
  return msg.decrypt(alice).then((data)=>{
    console.log(`alice read: ${JSON.stringify(data,null,2)}`)
  })
  
})
```

