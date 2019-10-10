import {lorem} from 'faker';
import Identity from '../src/identity';
import * as base64 from "@stablelib/base64";

export const extractKeys = (key : IKey) => [
  key.public.sign,
  key.private.sign,
  key.public.box,
  key.private.box
].map(base64.decode)

export const sanitizeMessage = (msg: IMessage) => JSON.parse(JSON.stringify(msg))

export const pingPong = async function(actor1: Identity, actor2: Identity) {
  const text1 = lorem.sentences();

  // Actor 1 creates a msg for Actor 2
  let msg1 = await actor1.encrypt(text1, actor2);
  expect(msg1.msg).toEqual(null);

  // Actor 2 decrypts message
  await msg1.decrypt(actor2);
  //debug(msg1)
  expect(msg1.msg).toEqual(text1);

  const text2 = lorem.paragraphs();

  // Actor 2 creates a msg for Actor 1
  let msg2 = await actor2.encrypt(text2, actor1);
  expect(msg2.msg).toEqual(null);

  // Actor 2 decrypts message
  await msg2.decrypt(actor1);
  expect(msg2.msg).toEqual(text2);
};

export const pingPongSign = async function(actor1: Identity, actor2: Identity) {
  const text1 = lorem.sentences();

  // Actor 1 creates a msg for Actor 2
  let msg1 = await actor1.sign(text1);
  expect(msg1.msg).toEqual(null);

  // Actor 2 decrypts message
  await msg1.decrypt(actor2);
  //debug(msg1)
  expect(msg1.msg).toEqual(text1);

  const text2 = lorem.paragraphs();

  // Actor 2 creates a msg for Actor 1
  let msg2 = await actor2.encrypt(text2, actor1);
  expect(msg2.msg).toEqual(null);

  // Actor 2 decrypts message
  await msg2.decrypt(actor1);
  expect(msg2.msg).toEqual(text2);
};
