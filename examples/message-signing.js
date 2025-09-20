const dataparty_crypto = require('../dist')

async function main (){    

    let startMs = Date.now()

    let alice = await dataparty_crypto.Identity.fromRandomSeed({id:'alice'})
    
    let msg1 = new dataparty_crypto.Message({msg:{
        myValue: 'hello world'
    }})

    
    let msg2 = new dataparty_crypto.Message({msg:{
        myValue: 'hello world'
    }})

    let msg3 = new dataparty_crypto.Message({msg:{
        myValue: 'hello world'
    }})
    

    const classicSig1 = await msg1.sign(alice)
    const pqMLSig1 = await msg2.sign(alice, true)
    const pqSLHSig1 = await msg3.sign(alice, true, 'pqsign_slh')

    
    console.log(msg1)
    console.log(msg2)
    console.log(msg3)
    
    let verified1 = await msg1.verify( alice )
    console.log(verified1)
    
    let verified2 = await msg2.verify( alice, true )
    console.log(verified2)
    
    let verified3 = await msg3.verify( alice )
    console.log(verified3)
    
    msg1.assertVerified(alice)
    msg2.assertVerified(alice, true)
    msg3.assertVerified(alice, true)
    
    let endMs = Date.now()
    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})