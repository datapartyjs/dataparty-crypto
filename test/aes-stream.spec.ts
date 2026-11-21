import Identity from "../src/identity";
import AESStream from "../src/aes-stream";

import Debug from "debug";
const debug = Debug("test.aes-stream");

//! plenty of redundancy, so compression shrinks it measurably
const PAYLOAD = "the quick brown fox jumps over the lazy dog \n".repeat(20);
const plain = new TextEncoder().encode(PAYLOAD);

it("can compress an aes stream and carry the codec in the offer", async () => {
  const alice = await Identity.fromRandomSeed({ id: "alice" });
  const bob = await Identity.fromRandomSeed({ id: "bob" });

  const aliceStream = await AESStream.createStream(
    alice,
    bob.publicIdentity(),
    true,
    "chain+random",
    "zstd-3"
  );

  expect(aliceStream.offer.mode).toEqual("chain+random");
  expect(aliceStream.offer.compression).toEqual("zstd-3");

  const cipher = await aliceStream.encrypt(plain);

  // a codec that never ran would leave us bigger than the plaintext
  expect(cipher.byteLength).toBeLessThan(plain.byteLength);

  const bobStream = await AESStream.recoverStream(bob, aliceStream.offer);
  expect(bobStream.offer.compression).toEqual(aliceStream.offer.compression);

  const recovered = await bobStream.decrypt(cipher);
  expect(new TextDecoder().decode(recovered)).toEqual(PAYLOAD);
});

it("keeps the nonce chain intact across messages", async () => {
  const alice = await Identity.fromRandomSeed({ id: "alice" });
  const bob = await Identity.fromRandomSeed({ id: "bob" });

  const aliceStream = await AESStream.createStream(
    alice,
    bob.publicIdentity(),
    true,
    "chain+random",
    "zstd-3"
  );

  const msg1 = await aliceStream.encrypt(plain);
  const msg2 = await aliceStream.encrypt(new TextEncoder().encode("rock on ninjas!"));

  const bobStream = await AESStream.recoverStream(bob, aliceStream.offer);

  expect(new TextDecoder().decode(await bobStream.decrypt(msg1))).toEqual(PAYLOAD);
  expect(new TextDecoder().decode(await bobStream.decrypt(msg2))).toEqual("rock on ninjas!");
});

it("roundtrips every compression level alice offers", async () => {
  const alice = await Identity.fromRandomSeed({ id: "alice" });
  const bob = await Identity.fromRandomSeed({ id: "bob" });

  const levels: ICompression[] = ["zstd-1", "zstd-3", "zstd-9", null];

  for (const compression of levels) {
    debug("level", compression);

    const stream = await AESStream.createStream(
      alice,
      bob.publicIdentity(),
      true,
      "random",
      compression
    );

    const cipher = await stream.encrypt(plain);

    const peer = await AESStream.recoverStream(bob, stream.offer);
    expect(peer.offer.compression).toEqual(compression);

    const recovered = await peer.decrypt(cipher);
    expect(new TextDecoder().decode(recovered)).toEqual(PAYLOAD);
  }
});

it("stores bytes as-is when the offer has no codec", async () => {
  const alice = await Identity.fromRandomSeed({ id: "alice" });
  const bob = await Identity.fromRandomSeed({ id: "bob" });

  const aliceStream = await AESStream.createStream(
    alice,
    bob.publicIdentity(),
    true,
    "random",
    null
  );

  expect(aliceStream.offer.compression).toEqual(null);

  const cipher = await aliceStream.encrypt(plain);

  // uncompressed payload plus the bson/gcmsiv envelope
  expect(cipher.byteLength).toBeGreaterThan(plain.byteLength);

  const bobStream = await AESStream.recoverStream(bob, aliceStream.offer);

  const recovered = await bobStream.decrypt(cipher);
  expect(new TextDecoder().decode(recovered)).toEqual(PAYLOAD);
});
