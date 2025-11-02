let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    const aliceFullKey = await dataparty_crypto.Identity.fromRandomSeed({id: 'alice'})
    const bobFullKey = await dataparty_crypto.Identity.fromRandomSeed({id: 'bob'})


    const alicePublicKey = aliceFullKey.publicIdentity()
    const bobPublicKey = bobFullKey.publicIdentity()


    const aliceAesStream = await dataparty_crypto.AESStream.createStream(
        aliceFullKey,
        bobPublicKey,
        true,
        'random'
    )

    console.log('alice stream offer', aliceAesStream.offer)

    let offerMsg = new dataparty_crypto.Message({msg:{
        offer: aliceAesStream.offer
    }})

    const offerSigned = await offerMsg.sign(aliceFullKey, true)

    let secureOfferMsg = new dataparty_crypto.Message({msg:{
        offer: aliceAesStream.offer
    }})

    await secureOfferMsg.encrypt(aliceFullKey, bobPublicKey.key)

    console.log('alice offer msg', offerMsg)

    console.log('secureOfferMsg offer msg', secureOfferMsg)

    const bobAesStream = await dataparty_crypto.AESStream.recoverStream(
        bobFullKey,
        aliceAesStream.offer
    )

    console.log('bob has stream', bobAesStream)


    const aliceMsg = await aliceAesStream.encrypt(new TextEncoder().encode('time to party'))
    const aliceMsg2 = await aliceAesStream.encrypt(new TextEncoder().encode('rock on ninjas!'))
    const aliceMsg3 = await aliceAesStream.encrypt(new TextEncoder().encode('🖤'))



    console.log('aliceMsg1 [', aliceMsg, ']')
    console.log('aliceMsg3 [', aliceMsg3, ']')
    console.log('aliceMsg2 [', aliceMsg2, ']')

    const bobMsg3 = await bobAesStream.decrypt(aliceMsg3)
    const bobMsg = await bobAesStream.decrypt(aliceMsg)
    const bobMsg2 = await bobAesStream.decrypt(aliceMsg2)
    


    console.log( bobFullKey.key.public )

    console.log('msg1 [', new TextDecoder().decode(bobMsg), ']')
    console.log('msg3 [', new TextDecoder().decode(bobMsg3), ']')
    console.log('msg2 [', new TextDecoder().decode(bobMsg2), ']')


}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
