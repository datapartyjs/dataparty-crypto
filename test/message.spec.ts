import { box, sign } from "tweetnacl";

import Message from "../src/message";
import Identity from "../src/identity";

import * as base64 from "@stablelib/base64";

import { pingPong, pingPongSign, extractKeys, sanitizeMessage } from "./utils";

const nonceSignSize = box.nonceLength + sign.publicKeyLength;

const nonceSignBoxSize = nonceSignSize + box.publicKeyLength;

const debug = require("debug")("test.routines");

it("can construct Identity", () => {
  let identity = new Identity();

  expect(identity.key).toBeDefined();
  expect(identity.key.type).toEqual("ecdsa");
  expect(identity.key.public).toBeDefined();
  expect(identity.key.private).toBeDefined();

  const keyLengthList = extractKeys(identity.key).map(k => k.length);

  expect(keyLengthList[0]).toEqual(sign.publicKeyLength);
  expect(keyLengthList[1]).toEqual(sign.secretKeyLength);

  expect(keyLengthList[2]).toEqual(box.publicKeyLength);
  expect(keyLengthList[3]).toEqual(box.secretKeyLength);
});

it("can send encrypted message from alice to bob", async () => {
  const TEST_STRING = "From Alice to Bob";

  const alice = new Identity({ id: "alice" });
  const bob = new Identity({ id: "bob" });

  const aliceMessage = new Message({
    msg: {
      data: TEST_STRING
    }
  });

  await aliceMessage.encrypt(alice, bob.key);

  const bobReceivedMessage = new Message(sanitizeMessage(aliceMessage));

  await bobReceivedMessage.decrypt(bob);

  expect(bobReceivedMessage.msg.data).toEqual(TEST_STRING);
});

it("cannot send tampered message from alice to bob", async () => {
  const TEST_STRING = "From Alice to Bob";

  const alice = new Identity({ id: "alice" });
  const bob = new Identity({ id: "bob" });

  const aliceMessage = new Message({
    msg: {
      data: TEST_STRING
    }
  });

  await aliceMessage.encrypt(alice, bob.key);

  const bobReceivedMessage = new Message(sanitizeMessage(aliceMessage));
  //console.log(JSON.stringify(msg2))

  await expect(bobReceivedMessage.decrypt(bob)).resolves.toBeDefined();

  expect(bobReceivedMessage.msg.data).toEqual(TEST_STRING);

  const fullMessage = base64.decode(bobReceivedMessage.enc);

  // Try to extract the data and reconstruct it with a false message
  const tamperedFullMessage = new Uint8Array(fullMessage.length);

  // Tampered message is a binary message of same length
  const tamperedMessage = new Uint8Array(fullMessage.length - nonceSignBoxSize);
  fullMessage.set(tamperedMessage, nonceSignBoxSize);

  bobReceivedMessage.enc = base64.encode(tamperedFullMessage);

  //console.log(JSON.stringify(msg2))

  await expect(bobReceivedMessage.decrypt(bob)).rejects.toEqual(
    new Error("signed message hash verification failed")
  );
});

it("send signed message from alice to bob", async () => {
  const TEST_STRING = "From Alice to Bob";
  const alice = new Identity({ id: "alice" });

  let aliceMessage = new Message({
    msg: {
      data: TEST_STRING
    }
  });

  await expect(aliceMessage.sign(alice)).resolves.toBeTruthy();

  const originalSig = aliceMessage.sig;

  const bobReceivedMessage = new Message(sanitizeMessage(aliceMessage));

  expect(bobReceivedMessage.sig).toEqual(originalSig);

  await bobReceivedMessage.verify(alice)

  await expect(bobReceivedMessage.verify(alice)).resolves.toBeTruthy();
});

it("send 100 messages between alice and bob", async done => {
  const alice = new Identity({ id: "alice" });
  const bob = new Identity({ id: "bob" });

  for (let i = 0; i < 100; i++) {
    //debug(i)
    await pingPong(alice, bob);
  }

  done();
});
