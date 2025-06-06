// @ts-ignore - need to build before this will exist
import { decryptSops } from "../../../dist/index.js";
import { describe, test, expect, beforeAll } from "bun:test";

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

// TODO: blocked on https://github.com/oven-sh/bun/issues/20148
describe.skip("bun module", () => {
  let original: any;

  beforeAll(async () => {
    // @ts-ignore
    original = JSON.parse(await Bun.file("tests/data/secret.json").text());
  });

  test("should decrypt a file path with a given fileType", async () => {
    const decrypted = await decryptSops({
      path: "tests/data/secret.enc.json",
      fileType: "json",
      secretKey: AGE_SECRET_KEY,
    });

    expect(decrypted).toEqual(original);
  });

  test("should decrypt a file path and infer type", async () => {
    const decrypted = await decryptSops({
      path: "tests/data/secret.enc.json",
      secretKey: AGE_SECRET_KEY,
    });

    expect(decrypted).toEqual(original);
  });
});
