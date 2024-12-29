import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import test_secret_enc_json from "./data/secret.enc.json" with { type: "json" };
import test_secret_json from "./data/secret.json" with { type: "json" };
import { decrypt } from "./decrypt.js";
import { loadSopsFile, parseSops } from "./sops-file.js";

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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
    expect(value).toEqual(test_secret_json);
  });

  test("decrypt import", async () => {
    const value = await decrypt(
      await parseSops(JSON.stringify(test_secret_enc_json), "json"),
      {
        secretKey: AGE_SECRET_KEY,
      },
    );
    expect(value).toEqual(test_secret_json);
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
