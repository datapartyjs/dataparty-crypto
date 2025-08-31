const argon2 = require('argon2')
let dataparty_crypto = require('../dist')

async function main (){
    console.log('solving . . . ')

    let startMs = Date.now()

    let input = 'these are words - '+startMs

    let work = await dataparty_crypto.Routines.solveProofOfWork(
      input, argon2,
      { timeCost: 3, memoryCost: 1024*8, parallelism: 1, complexity: 9 }
    )

    let endMs = Date.now()

    console.log('the work')
    console.log('\t', work)


    const deltaMs = endMs - startMs

    console.log('solved in (seconds):', (deltaMs/1000) )

    console.log('verifying . . . ')

    let startMs2 = Date.now()

    let verified = await dataparty_crypto.Routines.verifyProofOfWork(
      input,
      work,
      argon2,
      { timeCost: 3, memoryCost: 1024*8, parallelism: 1, complexity: 9 }
    )

    let endMs2 = Date.now()

    let deltaMs2 = endMs2 - startMs2

    console.log('verified in (seconds):', (deltaMs2/1000))
    console.log('verification:', verified)
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})