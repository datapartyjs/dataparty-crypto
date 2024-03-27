let dataparty_crypto = require('../dist')

const base64 = require('@stablelib/base64')



async function main (){
    console.log('wooo!')

    const aliceFullKey = await dataparty_crypto.Identity.fromRandomSeed()
    const bobFullKey = await dataparty_crypto.Identity.fromRandomSeed()

    console.log('aliceFullKey')
    console.log(aliceFullKey)

    console.log('bobFullKey')
    console.log(bobFullKey)

    const alicePublicKey = aliceFullKey.publicIdentity()
    const bobPublicKey = bobFullKey.publicIdentity()
    
    console.log('alice PUBLIC')
    console.log(alicePublicKey)

    console.log('bob PUBLIC')
    console.log(bobPublicKey)


    const aliceOffer = await aliceFullKey.createStream( bobPublicKey )


    console.log(aliceOffer)
    console.log('alice offer')


    const bobStream = await bobFullKey.recoverStream(aliceOffer)


    console.log('bob has stream')

    const aliceMsg = aliceOffer.stream.encrypt(new TextEncoder().encode('time to party'))
    const aliceMsg3 = aliceOffer.stream.encrypt(new TextEncoder().encode('🖤'))
    const aliceMsg2 = aliceOffer.stream.encrypt(new TextEncoder().encode('rock on ninjas!'))



    console.log('aliceMsg1 [', aliceMsg, ']')
    console.log('aliceMsg2 [', aliceMsg2, ']')
    console.log('aliceMsg3 [', aliceMsg3, ']')

    const bobMsg2 = bobStream.decrypt(aliceMsg2)

    const bobMsg = bobStream.decrypt(aliceMsg)


    const bobMsg3 = bobStream.decrypt(aliceMsg3)

    console.log( bobFullKey.key.public )

    console.log('msg1 [', new TextDecoder().decode(bobMsg), ']')

    console.log('msg2 [', new TextDecoder().decode(bobMsg2), ']')
    console.log('msg3 [', new TextDecoder().decode(bobMsg3), ']')


}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
