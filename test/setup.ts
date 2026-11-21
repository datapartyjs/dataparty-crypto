import { webcrypto } from "crypto";

//! jest-environment-node predates globalThis.crypto, and globals are JSON
//! serialized to workers, so the routines' encoders must arrive via setup
const missing: any = {};

if (typeof (globalThis as any).crypto?.getRandomValues !== "function") {
  missing.crypto = webcrypto;
}

if (typeof (globalThis as any).TextEncoder !== "function") {
  missing.TextEncoder = require("util").TextEncoder;
  missing.TextDecoder = require("util").TextDecoder;
}

Object.assign(globalThis, missing);
