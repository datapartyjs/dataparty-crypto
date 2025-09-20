const dataparty_crypto = require('../dist')

async function main (){    

    let startMs = Date.now()

    let alice = await dataparty_crypto.Identity.fromRandomSeed()

    let aliceMini = alice.toMini()
    let aliceJSON = alice.toJSON(true)
    let aliceBSON = alice.toBSON(true)
    let aliceString = alice.toString(true)
    
    console.log('alice', alice)
    console.log('JSON', aliceJSON)
    console.log('BSON', aliceBSON)
    console.log('String', aliceString)

    let aliceFromString = await dataparty_crypto.Identity.fromString( aliceString )
    let aliceFromBSON = await dataparty_crypto.Identity.fromBSON( aliceBSON )

    
    console.log('fromString', aliceFromString)
    console.log('fromBSON', aliceFromBSON)
    

    let msg1 = await aliceFromBSON.sign('quick test', true)
    let verified1 = await aliceFromString.verify(msg1, true)

    console.log('verified', verified1)

    let msg2 = await aliceFromString.sign('quick test part two', true)
    let verified2 = await aliceFromBSON.verify(msg2, true)

    console.log('verified', verified2)
    
    let endMs = Date.now()
    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
