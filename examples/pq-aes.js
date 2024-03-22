let dataparty_crypto = require('../dist')


const tweetnacl = require('tweetnacl')
const hkdf = require('@panva/hkdf')
const base64 = require('@stablelib/base64')

const { siv } = require('@noble/ciphers/aes')

class FullIdentity {
    constructor(){
        this.naclIdentity = new dataparty_crypto.Identity()
        this.pqIdentity = new dataparty_crypto.PQIdentity()

        this.naclSharedSecret = null
        this.pqSharedSecret = null
    }

    async getStream(toIdentity){

        this.pqSharedSecret = await dataparty_crypto.Routines.createPQSharedSecret(
            toIdentity.pqIdentity
        )

        const salt = 'textandstuffforsalt'
        const info = 'app-quick-test'

        this.streamNonce = base64.encode(tweetnacl.randomBytes(12))
        
        this.stream = await dataparty_crypto.Routines.createAESStream(
            await dataparty_crypto.Routines.createNaclSharedSecret(
                toIdentity.naclIdentity,
                this.naclIdentity
            ),
            this.pqSharedSecret,
            salt,
            info,
            base64.decode(this.streamNonce)
        )
    }

    async recoverStream(fromIdentity, pqCipherText, streamNonce){


        const salt = 'textandstuffforsalt'
        const info = 'app-quick-test'

        this.stream = await dataparty_crypto.Routines.createAESStream(
            await dataparty_crypto.Routines.createNaclSharedSecret(
                fromIdentity.naclIdentity,
                this.naclIdentity
            ),
            await dataparty_crypto.Routines.recoverPQSharedSecret(
                this.pqIdentity,
                pqCipherText
            ),
            salt,
            info,
            base64.decode(streamNonce)
        )
    }
}


async function main (){
    console.log('wooo!')

    const aliceFullKey = new FullIdentity()
    const bobFullKey = new FullIdentity()

    const alicePublicKey = new FullIdentity()
    alicePublicKey.naclIdentity = dataparty_crypto.Identity.fromString( JSON.stringify(aliceFullKey.naclIdentity.toJSON()) )
    alicePublicKey.pqIdentity = dataparty_crypto.PQIdentity.fromString( JSON.stringify(aliceFullKey.pqIdentity.toJSON()) )

    const bobPublicKey = new FullIdentity()
    bobPublicKey.naclIdentity = dataparty_crypto.Identity.fromString( JSON.stringify(bobFullKey.naclIdentity.toJSON()) )
    bobPublicKey.pqIdentity = dataparty_crypto.PQIdentity.fromString( JSON.stringify(bobFullKey.pqIdentity.toJSON()) )

    await aliceFullKey.getStream(bobPublicKey)

    await bobFullKey.recoverStream(alicePublicKey, aliceFullKey.pqSharedSecret.cipherText, aliceFullKey.streamNonce)

    console.log('aliceFullKey')
    console.log(aliceFullKey)

    console.log('bobFullKey')
    console.log(bobFullKey)

    const aliceMsg = aliceFullKey.stream.encrypt(new TextEncoder().encode('time to party'))
    const aliceMsg3 = aliceFullKey.stream.encrypt(new TextEncoder().encode('time to party'))
    const aliceMsg2 = aliceFullKey.stream.encrypt(new TextEncoder().encode('rock on ninjas!'))



    console.log('aliceMsg1 [', aliceMsg, ']')
    console.log('aliceMsg2 [', aliceMsg2, ']')
    console.log('aliceMsg3 [', aliceMsg3, ']')

    const bobMsg2 = bobFullKey.stream.decrypt(aliceMsg2)


    const bobMsg = bobFullKey.stream.decrypt(aliceMsg)

    console.log( bobFullKey.pqIdentity.key.public )

    console.log('msg1 [', new TextDecoder().decode(bobMsg), ']')

    console.log('msg2 [', new TextDecoder().decode(bobMsg2), ']')


}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
