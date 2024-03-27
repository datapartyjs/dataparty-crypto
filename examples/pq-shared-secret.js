let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    const aliceFullKey = await dataparty_crypto.Identity.fromRandomSeed()
    const bobFullKey = await dataparty_crypto.Identity.fromRandomSeed()

    const bobPublicKey = bobFullKey.publicIdentity()
    
    console.log('pq aliceKey')
    console.log('\t', aliceFullKey)

    console.log('bob public key')
    console.log(bobPublicKey)

    const aliceToBobSecret = await dataparty_crypto.Routines.createPQSharedSecret(bobPublicKey)

    console.log('alieToBobSecret', aliceToBobSecret)
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
