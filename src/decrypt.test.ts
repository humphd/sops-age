import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import test_json_import from "./data/secret.enc.json" with { type: "json" };
import { decrypt } from "./decrypt.js";
import { loadSopsFile, parseSopsJson } from "./sops-file.js";

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const EXPECTED_DECRYPTED_SECRET_JSON = JSON.parse(
  await readFile(resolve(__dirname, "./data/secret.json"), "utf-8"),
);

const sopsFile = () =>
  loadSopsFile(resolve(__dirname, "./data/secret.enc.json"));

describe("loadSopsFile() with explicit type", () => {
  test("json", () => {
    expect(() =>
      loadSopsFile(resolve(__dirname, "./data/secret.enc.json"), "json"),
    ).not.toThrow();
  });

  test("yaml", () => {
    expect(() =>
      loadSopsFile(resolve(__dirname, "./data/secret.enc.yaml"), "yaml"),
    ).not.toThrow();
  });

  test("env", () => {
    expect(() =>
      loadSopsFile(resolve(__dirname, "./data/secret.enc.env"), "env"),
    ).not.toThrow();
  });

  test("ini", () => {
    expect(() =>
      loadSopsFile(resolve(__dirname, "./data/secret.enc.ini"), "ini"),
    ).not.toThrow();
  });
});

describe("secretKey from env or options", () => {
  test("decrypt using secretKey from env", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "boolean",
    });
    expect(value).toBe(true);
  });

  test("decrypt using secretKey from options", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "boolean",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toBe(true);
  });

  test("decrypt without secretKey throws", async () => {
    const sops = await sopsFile();
    // Clear the key from the env before decrypting (see vitest.config.ts for `env`)
    process.env.SOPS_AGE_KEY = "";
    await expect(() =>
      decrypt(sops, { secretKey: undefined }),
    ).rejects.toThrow();
  });
});

describe("JSON File", () => {
  test("decrypt all values from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, { secretKey: AGE_SECRET_KEY });
    expect(value).toEqual(EXPECTED_DECRYPTED_SECRET_JSON);
  });

  test("decrypt import", async () => {
    const value = await decrypt(parseSopsJson(test_json_import), {
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toEqual(EXPECTED_DECRYPTED_SECRET_JSON);
  });

  test("decrypt a specific string value from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "complex.value",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toEqual("this is a secret");
  });

  test("decrypt an int value from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "int",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toBe(7);
  });

  test("decrypt a float value from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "float",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toBe(3.14);
  });

  test("decrypt a bool value from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "boolean",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toBe(true);
  });
});

describe("YAML File", () => {
  const sopsFile = () =>
    loadSopsFile(resolve(__dirname, "./data/secret.enc.yaml"));

  test("decrypt all values from SOPS YAML file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, { secretKey: AGE_SECRET_KEY });
    expect(value).toEqual({
      boolean: true,
      complex: {
        array: ["one", "two", "three"],
        value: "this is a secret",
      },
      float: 3.14,
      int: 7,
      secret: "this is a secret",
      string: "string",
    });
  });

  test("decrypt a specific string value from SOPS YAML file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "complex.value",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toEqual("this is a secret");
  });

  test("decrypt an int value from SOPS YAML file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "int",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toBe(7);
  });

  test("decrypt a float value from SOPS YAML file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "float",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toBe(3.14);
  });

  test("decrypt a bool value from SOPS YAML file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "boolean",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toBe(true);
  });
});

/**
INI files are basically broken in SOPS.
They add a DEFAULT section for top-level keys
and if you have an actual DEFAULT section, it gets combined
We would need a more clever key naming algo to deal with this.
DEFAULT:secret: ENC[AES256_GCM,data:lqBKPgtSKHgUIdEz9x1rbA==,iv:mzSoH/7XrD1u12bvJ9hgTJMG4JY68Y7Lv13+4hO08Xg=,tag:cC3Cm4bwlSlilJm6GkxPXw==,type:str]
complex:string: ENC[AES256_GCM,data:rrCuH5h+,iv:1e/nDuSgbiqKG7TeqcTjH5dsD2rPyVcLWQDXTOr2tzI=,tag:QJOXdlT9sWgpzQkZD+Cqbg==,type:str]
 */
describe.skip("INI File", () => {
  const sopsFile = () =>
    loadSopsFile(resolve(__dirname, "./data/secret.enc.ini"));

  test("decrypt all values from SOPS INI file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, { secretKey: AGE_SECRET_KEY });
    expect(value).toEqual({
      complex: {
        string: "string",
      },
      secret: "this is a secret",
    });
  });

  test("decrypt a specific string value from SOPS INI file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "complex.string",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toEqual("string");
  });
});

describe("ENV File", () => {
  const sopsFile = () =>
    loadSopsFile(resolve(__dirname, "./data/secret.enc.env"));

  test("decrypt all values from SOPS ENV file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, { secretKey: AGE_SECRET_KEY });
    expect(value).toEqual({
      another_secret: "7",
      secret: "this is a secret",
    });
  });

  test("decrypt a specific string value from SOPS ENV file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, {
      keyPath: "another_secret",
      secretKey: AGE_SECRET_KEY,
    });
    expect(value).toEqual("7");
  });
});
