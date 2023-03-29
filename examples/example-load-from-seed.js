let dataparty_crypto = require('../dist/dataparty-crypto.js')

async function main (){
    console.log('wooo!')

    

    const phrase = " elephant kite ask energy movie finger valley ahead shrug garden screen erosion ".trim()

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
