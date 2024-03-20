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
        this.naclSharedSecret = await dataparty_crypto.Routines.createNaclSharedSecret(
            toIdentity.naclIdentity,
            this.naclIdentity
        )

        this.pqSharedSecret = await dataparty_crypto.Routines.createPQSharedSecret(
            toIdentity.pqIdentity
        )

        const salt = 'textandstuffforsalt'
        const info = 'app-quick-test'

        const mergedSecret = Buffer.concat([ 
            base64.decode(this.naclSharedSecret.sharedSecret),
            base64.decode(this.pqSharedSecret.sharedSecret)
        ])
        
        //console.log('merged', mergedSecret)
        
        this.mergedSecret = base64.encode(mergedSecret)
        this.streamKey = base64.encode( await hkdf.hkdf('sha512', mergedSecret, salt, info, 32) )

        this.streamNonce = base64.encode(tweetnacl.randomBytes(12))

        //console.log('streamKey', base64.encode(this.streamKey))

        this.stream = siv(
            base64.decode(this.streamKey),
            base64.decode(this.streamNonce)
        )
    }

    async recoverStream(fromIdentity, pqCipherText, streamNonce){
        this.naclSharedSecret = await dataparty_crypto.Routines.createNaclSharedSecret(
            fromIdentity.naclIdentity,
            this.naclIdentity
        )

        this.pqSharedSecret = await dataparty_crypto.Routines.recoverPQSharedSecret(
            this.pqIdentity,
            pqCipherText
        )

        const mergedSecret = Buffer.concat([ 
            base64.decode(this.naclSharedSecret.sharedSecret),
            base64.decode(this.pqSharedSecret.sharedSecret)
        ])
        

        this.mergedSecret = base64.encode(mergedSecret)

        const salt = 'textandstuffforsalt'
        const info = 'app-quick-test'
        this.streamKey = base64.encode( await hkdf.hkdf('sha512', mergedSecret, salt, info, 32) )
        this.streamNonce =  streamNonce

        this.stream = siv(
            base64.decode(this.streamKey),
            base64.decode(this.streamNonce)
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

    const bobMsg = bobFullKey.stream.decrypt(aliceMsg)

    console.log('msg [', new TextDecoder().decode(bobMsg), ']')
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
