const argon2 = require('argon2')
let dataparty_crypto = require('../dist/dataparty-crypto.js')

async function main (){

    const password = 'super-strong-password'
    //const salt = await dataparty_crypto.Routines.generateSalt()
    const salt = Buffer.from('26bd99303dee4ee53342e89bd9f01a80c1fecf0d6b0c6c8eefee5a1eeeb8a0ec', 'hex') //! Salt would be read from disk after 1st run

    console.log('salt')
    console.log('\t', salt.toString('hex'))


    let startMs = Date.now()


    const key = await dataparty_crypto.Routines.createKeyFromPasswordArgon2(
        argon2,
        "supersecretpassword123",
        salt
    )

    let endMs = Date.now()


    console.log('key')
    console.log(key)


    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
