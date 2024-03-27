let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    const aliceKey = new dataparty_crypto.Identity()
    const bobKey = new dataparty_crypto.Identity()

    const bobPublicKey = dataparty_crypto.Identity.fromString( JSON.stringify( bobKey.toJSON() ) )

    console.log('pq aliceKey')
    console.log('\t', aliceKey)

    console.log('bob public key')
    console.log(bobPublicKey)

    const aliceToBobSecret = await dataparty_crypto.Routines.createNaclSharedSecret(bobPublicKey, aliceKey)

    console.log('alieToBobSecret', aliceToBobSecret)
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
