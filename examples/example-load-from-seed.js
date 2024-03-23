let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    

    const phrase = " elephant kite ask energy movie finger valley ahead shrug garden screen erosion ".trim()

    console.log('phrase')
    console.log('\t', phrase)


    let startMs = Date.now()
    let key = await dataparty_crypto.Identity.fromMnemonic(phrase)

    let endMs = Date.now()

    console.log('key')
    console.log('\t', key)

    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
