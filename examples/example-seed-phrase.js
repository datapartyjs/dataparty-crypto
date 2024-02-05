let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    const phrase = await dataparty_crypto.Routines.generateMnemonic()

    console.log('phrase')
    console.log('\t', phrase)

    let key = await dataparty_crypto.Routines.createKeyFromMnemonic(phrase)

    console.log('key')
    console.log('\t', key)
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
