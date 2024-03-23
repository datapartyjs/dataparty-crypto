let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    


    let startMs = Date.now()
    const phrase = await dataparty_crypto.Routines.generateMnemonic()
    let key = await dataparty_crypto.Identity.fromMnemonic(phrase)

    let endMs = Date.now()

    console.log('phrase')
    console.log('\t', phrase)


    console.log('key')
    console.log('\t', key)


    let recoveredPhrase = await key.getMnemonic()

    console.log('recovered phrase - ', recoveredPhrase)

    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})