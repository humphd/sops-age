const { decryptSops } = require("../../../dist/index.cjs");
const { readFile } = require("node:fs/promises");
const { describe, before, it } = require("node:test");
const { deepStrictEqual } = require("node:assert");

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

describe("node.js CommonJS", async () => {
  let original;

  before(async () => {
    original = JSON.parse(await readFile("tests/data/secret.json", "utf-8"));
  });

  it("should decrypt a file path with a given fileType", async () => {
    const decrypted = await decryptSops({
      path: "tests/data/secret.enc.json",
      fileType: "json",
      secretKey: AGE_SECRET_KEY,
    });

    deepStrictEqual(decrypted, original);
  });

  it("should decrypt a file path and infer type", async () => {
    const decrypted = await decryptSops({
      path: "tests/data/secret.enc.json",
      secretKey: AGE_SECRET_KEY,
    });

    deepStrictEqual(decrypted, original);
  });
});
