let dataparty_crypto = require('./dist')

async function main (){

    let rando = await dataparty_crypto.Routines.getRandomBuffer(32)

    console.log(rando.toString('base64'))
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})