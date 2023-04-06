let dataparty_crypto = require('../dist/dataparty-crypto.js')

async function main (){

    const password = 'super-strong-password'
    const salt = await dataparty_crypto.Routines.generateSalt()
    //const salt = Buffer.from('60312b38547ee7141c0f3d79df97663a1e746313e3c3c3d414436b1fc78552d9', 'hex') //! Salt would be read from disk after 1st run

    console.log('salt')
    console.log('\t', salt.toString('hex'))


    let startMs = Date.now()


    let key = await dataparty_crypto.Routines.createKeyFromPassword(password, salt)

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
