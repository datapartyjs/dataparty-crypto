let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    

    const phrase = "current angry nest gown pistol neither loyal face into rebuild vivid autumn pledge aware damp cradle remind tornado wise glory face hip derive coast".trim()

    console.log('phrase')
    console.log('\t', phrase)


    let startMs = Date.now()
    let key = await dataparty_crypto.Identity.fromMnemonic(phrase)

    let endMs = Date.now()

    console.log('key')
    console.log('\t', key)

    console.log(key.seed)

    let recoveredPhrase = await key.getMnemonic()

    console.log('recovered phrase - ', recoveredPhrase)

    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
