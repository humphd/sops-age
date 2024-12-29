import { decryptSops } from "../../../dist/index.js";
// @ts-ignore
import { assertEquals } from "https://deno.land/std/assert/mod.ts";

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

Deno.test("deno module", async (t) => {
  const original = JSON.parse(
    await Deno.readTextFile("tests/data/secret.json"),
  );

  await t.step("should decrypt a file path with a given fileType", async () => {
    const decrypted = await decryptSops({
      path: "tests/data/secret.enc.json",
      fileType: "json",
      secretKey: AGE_SECRET_KEY,
    });

    assertEquals(decrypted, original);
  });

  await t.step("should decrypt a file path and infer type", async () => {
    const decrypted = await decryptSops({
      path: "tests/data/secret.enc.json",
      secretKey: AGE_SECRET_KEY,
    });

    assertEquals(decrypted, original);
  });
});
