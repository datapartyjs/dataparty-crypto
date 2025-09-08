let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    const aliceFullKey = await dataparty_crypto.Identity.fromRandomSeed()
    const bobFullKey = await dataparty_crypto.Identity.fromRandomSeed()


    const alicePublicKey = aliceFullKey.publicIdentity()
    const bobPublicKey = bobFullKey.publicIdentity()


    const aliceOffer = await aliceFullKey.createStream( bobPublicKey )
    const bobStream = await bobFullKey.recoverStream(aliceOffer)


    console.log('bob has stream')

    const aliceMsg = await aliceOffer.stream.encrypt(new TextEncoder().encode('time to party'))
    const aliceMsg2 = await aliceOffer.stream.encrypt(new TextEncoder().encode('rock on ninjas!'))
    const aliceMsg3 = await aliceOffer.stream.encrypt(new TextEncoder().encode('🖤'))



    console.log('aliceMsg1 [', aliceMsg, ']')
    console.log('aliceMsg3 [', aliceMsg3, ']')
    console.log('aliceMsg2 [', aliceMsg2, ']')

    const bobMsg = await bobStream.decrypt(aliceMsg)
    const bobMsg2 = await bobStream.decrypt(aliceMsg2)
    const bobMsg3 = await bobStream.decrypt(aliceMsg3)


    console.log( bobFullKey.key.public )

    console.log('msg1 [', new TextDecoder().decode(bobMsg), ']')
    console.log('msg3 [', new TextDecoder().decode(bobMsg3), ']')
    console.log('msg2 [', new TextDecoder().decode(bobMsg2), ']')


}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
