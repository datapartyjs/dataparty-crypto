const argon2 = require('argon2')
let dataparty_crypto = require('../dist')

async function main (){
    let startMs = Date.now()
    
    const phrase = await dataparty_crypto.Routines.generateMnemonic()
    const password = 'super strong password'
    let key = await dataparty_crypto.Identity.fromMnemonic(phrase, password, argon2)

    let endMs = Date.now()

    console.log('phrase')
    console.log('\t', phrase)


    console.log('key')
    console.log('\t', key)


    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})