const argon2 = require('argon2')
let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    


    let startMs = Date.now()

    let input = 'these are words - '+startMs

    let work = await dataparty_crypto.Routines.solveProofOfWork(
      input, argon2,
      { timeCost: 3, memoryCost: 1024*16, parallelism: 2, complexity: 9 }
    )

    let endMs = Date.now()

    console.log('the work')
    console.log('\t', work)


    const deltaMs = endMs - startMs

    console.log('time (seconds):', (deltaMs/1000) )
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})