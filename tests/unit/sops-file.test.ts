import { describe, expect, test } from "vitest";

import test_secret_enc_json from "../data/secret.enc.json" with { type: "json" };
import test_secret_json from "../data/secret.json" with { type: "json" };
import { decrypt } from "../../src/decrypt.js";
import { parseSops, type SOPS } from "../../src/sops-file.js";

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

describe("parseSops() with different input types", () => {
  const testString = JSON.stringify(test_secret_enc_json);

  async function verifyParsedResult(result: SOPS) {
    const decrypted = await decrypt(result, { secretKey: AGE_SECRET_KEY });
    expect(decrypted).toEqual(test_secret_json);
  }

  test("string input", async () => {
    const result = await parseSops(testString, "json");
    await verifyParsedResult(result);
  });

  test("Uint8Array input", async () => {
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(testString);
    const result = await parseSops(uint8Array, "json");
    await verifyParsedResult(result);
  });

  test("ArrayBuffer input", async () => {
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(testString);
    const arrayBuffer = uint8Array.buffer;
    const result = await parseSops(arrayBuffer, "json");
    await verifyParsedResult(result);
  });

  test("Buffer input", async () => {
    const buffer = Buffer.from(testString);
    const result = await parseSops(buffer, "json");
    await verifyParsedResult(result);
  });

  test("ReadableStream input", async () => {
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(testString);
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(uint8Array);
        controller.close();
      },
    });
    const result = await parseSops(stream, "json");
    await verifyParsedResult(result);
  });

  test("Blob input", async () => {
    const blob = new Blob([testString], { type: "application/json" });
    const result = await parseSops(blob, "json");
    await verifyParsedResult(result);
  });

  test("File input", async () => {
    const blob = new Blob([testString], { type: "application/json" });
    const file = new File([blob], "test.json", { type: "application/json" });
    const result = await parseSops(file, "json");
    await verifyParsedResult(result);
  });

  test("invalid input", async () => {
    // @ts-expect-error Testing invalid input
    await expect(parseSops(123)).rejects.toThrow();
  });
});
