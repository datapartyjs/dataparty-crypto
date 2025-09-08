const argon2 = require('argon2')
const dataparty_crypto = require('../dist')

async function main (){

    

    let startMs = Date.now()

    let alice = await dataparty_crypto.Identity.fromRandomSeed()
    let bob = await dataparty_crypto.Identity.fromRandomSeed()

    //console.log(alice)

    let msg1 = new dataparty_crypto.Message({msg:{
        myValue: 'hello world'
    }})

    await msg1.encrypt(alice, bob.key)

    let pqSig = await dataparty_crypto.Routines.signDataPQ(alice, msg1.enc, 'pqsign_ml')

    let value = await msg1.decrypt(bob)

    console.log('bob decrypted value ', value)

    let endMs = Date.now()


    console.log('msg')
    console.log('\t', msg1.toJSON())

    console.log('\n\npq signatue')
    console.log(pqSig)

    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})