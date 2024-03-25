import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { decrypt } from "./decrypt.js";
import { loadJsonSopsFile, loadYamlSopsFile } from "./sops-file.js";

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe("decrypt()", () => {
  test("Able to decrypt string value from SOPS JSON file", async () => {
    const sops = await loadJsonSopsFile(
      resolve(__dirname, "./data/secret.enc.json"),
    );
    const value = await decrypt(sops, AGE_SECRET_KEY, "secret");
    expect(value).toEqual("this is a secret");
  });

  test("Able to decrypt string value from SOPS YAML file", async () => {
    const sops = await loadYamlSopsFile(
      resolve(__dirname, "./data/secret.enc.yaml"),
    );
    const value = await decrypt(sops, AGE_SECRET_KEY, "secret");
    expect(value).toEqual("this is a secret");
  });
});
