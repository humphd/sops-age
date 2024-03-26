import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { decrypt } from "./decrypt.js";
import { loadSopsFile } from "./sops-file.js";

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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

describe("JSON File", () => {
  const sopsFile = () =>
    loadSopsFile(resolve(__dirname, "./data/secret.enc.json"));

  test("decrypt all values from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY);
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

  test("decrypt a specific string value from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY, "complex.value");
    expect(value).toEqual("this is a secret");
  });

  test("decrypt an int value from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY, "int");
    expect(value).toBe(7);
  });

  test("decrypt a float value from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY, "float");
    expect(value).toBe(3.14);
  });

  test("decrypt a bool value from SOPS JSON file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY, "boolean");
    expect(value).toBe(true);
  });
});

describe("YAML File", () => {
  const sopsFile = () =>
    loadSopsFile(resolve(__dirname, "./data/secret.enc.yaml"));

  test("decrypt all values from SOPS YAML file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY);
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
    const value = await decrypt(sops, AGE_SECRET_KEY, "complex.value");
    expect(value).toEqual("this is a secret");
  });

  test("decrypt an int value from SOPS YAML file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY, "int");
    expect(value).toBe(7);
  });

  test("decrypt a float value from SOPS YAML file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY, "float");
    expect(value).toBe(3.14);
  });

  test("decrypt a bool value from SOPS YAML file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY, "boolean");
    expect(value).toBe(true);
  });
});

describe("INI File", () => {
  const sopsFile = () =>
    loadSopsFile(resolve(__dirname, "./data/secret.enc.ini"));

  test("decrypt all values from SOPS INI file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY);
    expect(value).toEqual({
      complex: {
        string: "string",
      },
      secret: "this is a secret",
    });
  });

  test("decrypt a specific string value from SOPS INI file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY, "complex.string");
    expect(value).toEqual("string");
  });
});

describe("ENV File", () => {
  const sopsFile = () =>
    loadSopsFile(resolve(__dirname, "./data/secret.enc.env"));

  test("decrypt all values from SOPS ENV file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY);
    expect(value).toEqual({
      another_secret: "7",
      secret: "this is a secret",
    });
  });

  test("decrypt a specific string value from SOPS ENV file", async () => {
    const sops = await sopsFile();
    const value = await decrypt(sops, AGE_SECRET_KEY, "another_secret");
    expect(value).toEqual("7");
  });
});
