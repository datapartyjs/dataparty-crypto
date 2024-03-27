const argon2 = require('argon2')
const dataparty_crypto = require('../dist')

async function makeIdentity(i){
    const password = '00000000'+i
    const entropy = await dataparty_crypto.Routines.getRandomBuffer(32)
    const phrase = await dataparty_crypto.Routines.entropyToMnemonic(entropy)
    const seed = await dataparty_crypto.Routines.createSeedFromMnemonic(
        phrase,
        password,
        argon2
    )
    let key = await dataparty_crypto.Routines.createKey(seed)

    return {
        password,
        entropy,
        phrase,
        key,
        seed
    }
}

async function main (){    

    let startMs = Date.now()

    for(let i=0; i<100; i++){
        let bundle = await makeIdentity(i)

        process.stdout.write('.')

        //console.log('IDENTITY -', i)
        //console.log('\t', 'entropy len=', bundle.entropy.length , bundle.entropy)
        //console.log('\t', 'phrase len=', bundle.phrase.length, bundle.phrase)
        //console.log('\t', 'seed1 len=', bundle.seed.length, bundle.seed)
    }

    let endMs = Date.now()

    const deltaMs = endMs - startMs

    console.log('time (ms):', (deltaMs/1000) )
    console.log('identities / second', 100 / (deltaMs/1000))
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})