let dataparty_crypto = require('../dist')

async function main (){

    let startMs = Date.now()
    let key = await dataparty_crypto.Identity.random()

    let endMs = Date.now()

    console.log('key')
    console.log('\t', key.toJSON(true))


    let recoveredPhrase = await key.getMnemonic()

    console.log('recovered phrase - ', recoveredPhrase)

    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})