import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test, vi } from "vitest";

import test_secret_enc_json from "./data/secret.enc.json" with { type: "json" };
import test_secret_json from "./data/secret.json" with { type: "json" };

import { decryptSops } from "./index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

describe("decryptSops()", () => {
  test("with direct input", async () => {
    const value = await decryptSops(JSON.stringify(test_secret_enc_json), {
      secretKey: AGE_SECRET_KEY,
      fileType: "json",
    });
    expect(value).toEqual(test_secret_json);
  });

  test("with path option", async () => {
    const value = await decryptSops({
      path: resolve(__dirname, "./data/secret.enc.json"),
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toEqual(test_secret_json);
  });

  test("with URL option", async () => {
    // Mock fetch for testing
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(JSON.stringify(test_secret_enc_json)),
    });

    const value = await decryptSops({
      url: "https://example.com/config.enc.json",
      secretKey: AGE_SECRET_KEY,
      fileType: "json",
    });
    expect(value).toEqual(test_secret_json);
  });

  test("with keyPath", async () => {
    const value = await decryptSops({
      path: resolve(__dirname, "./data/secret.enc.json"),
      secretKey: AGE_SECRET_KEY,
      keyPath: "complex.value",
    });
    expect(value).toBe("this is a secret");
  });
});
