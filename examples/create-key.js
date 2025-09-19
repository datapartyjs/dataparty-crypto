const argon2 = require('argon2')
const dataparty_crypto = require('../dist')

async function main (){

    

    let startMs = Date.now()
    const password = 'super strong password'
    const entropy = await dataparty_crypto.Routines.getRandomBuffer(32)
    //const phrase = await dataparty_crypto.Routines.entropyToMnemonic(entropy)
    const phrase = 'spawn assist display rescue number crawl success loud border once extra express quarter finger rare property fiscal ocean normal write large token always flame'
    const seed = await dataparty_crypto.Routines.createSeedFromMnemonic(
        phrase,
        password,
        argon2
    )

    const seed2 = await dataparty_crypto.Routines.createSeedFromMnemonic(
        phrase,
        '',
        argon2
    )

    let key = await dataparty_crypto.Routines.createKey(seed)
    let endMs = Date.now()


    console.log('key')
    console.log('\t', key)

    console.log('entropy len=', entropy.length , entropy)
    console.log('phrase len=', phrase.length, phrase)
    console.log('seed1 len=', seed.length, seed)
    console.log('seed2 len=', seed.length, seed2)

    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})