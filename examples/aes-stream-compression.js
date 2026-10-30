let dataparty_crypto = require('../dist')

// a payload with plenty of redundancy, compression should shrink it a lot
const payload = 'the quick brown fox jumps over the lazy dog \n'.repeat(20)

async function main (){

    const alice = await dataparty_crypto.Identity.fromRandomSeed({id:'alice'})
    const bob   = await dataparty_crypto.Identity.fromRandomSeed({id:'bob'})

    const bobPublic = bob.publicIdentity()

    // createStream(identity, to, requirePostQuantum, mode, compression)
    // compression is part of the offer, so bob decompresses without being told twice
    const aliceStream = await dataparty_crypto.AESStream.createStream(
        alice,
        bobPublic,
        true,
        'chain+random',
        'zstd-3'
    )

    console.log('alice stream offer')
    console.log('\tmode:', '\t', aliceStream.offer.mode)
    console.log('\tcompression:', aliceStream.offer.compression)

    const bytes = new TextEncoder().encode(payload)

    const msg1 = await aliceStream.encrypt(bytes)
    const msg2 = await aliceStream.encrypt(new TextEncoder().encode('rock on ninjas!'))

    // bob recovers the exact same stream (same key, same nonce chain, same codec)
    const bobStream = await dataparty_crypto.AESStream.recoverStream(bob, aliceStream.offer)

    const out1 = new TextDecoder().decode(await bobStream.decrypt(msg1))
    const out2 = new TextDecoder().decode(await bobStream.decrypt(msg2))

    console.log('')
    console.log('plaintext bytes:', bytes.byteLength)
    console.log('zstd-3 + aes-gcm-siv ciphertext bytes:', msg1.byteLength)
    console.log('roundtripped ok:', out1 === payload)
    console.log('msg2 [', out2, ']')

    // same bytes, different compression offers - the offer decides how bytes are packed
    console.log('')
    console.log('compression settings travel in the offer')

    for (const compression of ['zstd-1', 'zstd-3', 'zstd-9', null]){

        const stream = await dataparty_crypto.AESStream.createStream(
            alice, bobPublic, true, 'random', compression
        )

        const cipher = await stream.encrypt(bytes)
        const peer = await dataparty_crypto.AESStream.recoverStream(bob, stream.offer)
        const plain = new TextDecoder().decode(await peer.decrypt(cipher))

        console.log('\t',
            String(compression).padEnd(8),
            'offer->', String(stream.offer.compression).padEnd(8),
            'plain:', bytes.byteLength,
            'cipher:', cipher.byteLength,
            'match:', plain === payload
        )
    }
}

main().catch(err=>{
    console.log('ERROR - we crashed')
    console.log(err)
})
