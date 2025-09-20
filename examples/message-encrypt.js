const argon2 = require('argon2')
const dataparty_crypto = require('../dist')

async function main (){    

    let startMs = Date.now()

    const alice = await dataparty_crypto.Identity.fromRandomSeed({id:'alice'})
    const bob = await dataparty_crypto.Identity.fromRandomSeed({id:'bob'})


    let msg1 = new dataparty_crypto.Message({msg:{
        myValue: 'hello world'
    }})

    await msg1.encrypt(alice, bob.key)


    let value = await msg1.decrypt(bob)

    console.log('bob decrypted value ', value)

    let endMs = Date.now()


    console.log('msg')
    console.log('\t', msg1.toJSON())

    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})