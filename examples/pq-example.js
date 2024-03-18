let dataparty_crypto = require('../dist')

async function main (){
    console.log('wooo!')

    const key = await dataparty_crypto.Routines.createPQKey()

    console.log('pq key')
    console.log('\t', key)

}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
