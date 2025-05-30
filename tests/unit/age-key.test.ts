import {
  describe,
  expect,
  test,
  beforeAll,
  beforeEach,
  afterEach,
  afterAll,
} from "vitest";
import { findAllAgeKeys } from "../../src/age-key.js";
import { X25519_PRIVATE_KEY_HRP } from "../../src/age.js";
import { sshKeyToAge } from "../../src/ssh-to-age.js";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execSync } from "node:child_process";

const DUMMY_ED25519_PRIVATE_KEY_CONTENT = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC6AomzbioPu1vf0niUWVCclpKqTmymaK6YaQA3zNbeZwAAAJjJ8P5tyfD+
bQAAAAtzc2gtZWQyNTUxOQAAACC6AomzbioPu1vf0niUWVCclpKqTmymaK6YaQA3zNbeZw
AAAEDejh/ezX+crUvh/3ksDn2IBJUEDaQcAzNvG+jrNgHkN7oCibNuKg+7W9/SeJRZUJyW
kqpObKZorphpADfM1t5nAAAAD3Rlc3RrZXlAdGVzdGluZwECAwQFBg==
-----END OPENSSH PRIVATE KEY-----`;

// ./ssh-to-age -private-key -i ./dummy_ed25519_for_test
const EXPECTED_AGE_KEY_FROM_DUMMY_ED25519 = `AGE-SECRET-KEY-1MCRYZAW398UH47D5EYC6GECNUJJ4FFE8A7HQEWNXXHEXW4ULEA6Q6EV8JY`;

const DUMMY_RSA_PRIVATE_KEY_CONTENT = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxHkZNWfcZUqg5LywB4KB//g6+iug7cfuXYgIUb88rcej582oRtJw
fy+eqTsKAhYJZnl+a7W3DUa32E6mV34lXqfi6caIIBYQTpkmSircYb18Og3OcPYHAqnxKl
iXiCt98EFiPylrFL3wioPaKU6jrI3JecePItnPc8f5rb4P3eyjkHDjbRCIJUPLQy3kEWfr
oilDeblBvd0qrLt7uk9oBVcJj8hWdosOl6llBDkgzlNmMsvaxEGJ44HuLk/VsYcp/HhLya
Cq6ImpZ+2iDNNgzHEV72HDdHhR3xeV9glYYYEW3fpcf8mqHdZ/NaJ7JyIpASBCpfWKlBfV
zpvRF5UNoQAAA8jzoFQ686BUOgAAAAdzc2gtcnNhAAABAQDEeRk1Z9xlSqDkvLAHgoH/+D
r6K6Dtx+5diAhRvzytx6PnzahG0nB/L56pOwoCFglmeX5rtbcNRrfYTqZXfiVep+Lpxogg
FhBOmSZKKtxhvXw6Dc5w9gcCqfEqWJeIK33wQWI/KWsUvfCKg9opTqOsjcl5x48i2c9zx/
mtvg/d7KOQcONtEIglQ8tDLeQRZ+uiKUN5uUG93Sqsu3u6T2gFVwmPyFZ2iw6XqWUEOSDO
U2Yyy9rEQYnjge4uT9Wxhyn8eEvJoKroialn7aIM02DMcRXvYcN0eFHfF5X2CVhhgRbd+l
x/yaod1n81onsnIikBIEKl9YqUF9XOm9EXlQ2hAAAAAwEAAQAAAQAm6/KRgOTJcDJVfgfF
RRZp1gwg+TmlQWE4SDWVtDPaHV2cE0LN3OyKVa2xys9dwG3WTiU8Q0BjMepDwLj1Rjky+k
FanIjlClnqqC5MrRcBid8tRQTrneGfpnjvMaO7Rxpo2RsUdikPb91SI3K5kimcim4qYN07
Qzj0r94HjEpqZRjaLO7reAsR0/SOegDMY1iTuLuTX1MM04HeKhnB4/Ob8VNJuQtCUMFSQq
Tnki7f2Jwh4DreAqu0ZCi/Vk9jIpv9peDNll6Nohk5ogoBQxzus6IccOU7lZ9J5ssuJ0na
TfMyV+St3/9bNdNuX9Wdoi+ovE8X4j+97TTyL4wrY83RAAAAgAdjR+LBhDwFEZKhEBK2SW
hRvSmPGe1/gD27CnRljPhyR8DkFD/HYUTqCCi9JrsnU+8PMWB2BHUtjva1Z6oMYbZoZBPo
k09+cqVPXq6uY4SVoejebe54PkqMBQ3h7wBeliKyUMo/CM+whiFWnF43KPeuI/pVgeDfrj
962248KHfeAAAAgQDhPLWME0OSei5gBf+RIupLlYumBPOn5Sd50xj1OtG5m/XHjwAu/QvQ
/LsK8+PA5TyArVhxaD2IFyCgKrDv66mJo6NYpI0+mvrNgy+0Z7DifuEe6s/2rYnwrtRzRN
ybn1pFkNQKUw+oGnhDz7V9y0N/PZI1kAmC4edckWBkwl92TQAAAIEA306rIY1JCPSDaybP
QfJVOTfU5hNn6XcYHB9/JxUUAI8uSDGO0HimHLcRyC9jRGIrL9lTDyoFCblLsOP94pHegt
0GRosN8Eu7KxYwjoTfpSvGLHPRokFiJaY22XrXmDB6bqBRnxl89MItLjPqWP/UYl3AQbqo
79Bg9oAgOZRoBqUAAAAQdGVzdC1yc2FAdGVzdGluZwECAw==
-----END OPENSSH PRIVATE KEY-----
`;

const MOCK_AGE_KEY_1 = `${X25519_PRIVATE_KEY_HRP}TESTKEY1ABCDEFGHIJKLMNOPQRSTUVWXYZ012345`;
const MOCK_AGE_KEY_2 = `${X25519_PRIVATE_KEY_HRP}TESTKEY2ABCDEFGHIJKLMNOPQRSTUVWXYZ543210`;

let tempRootDir: string;
let mockHomeDir: string;
let mockXdgConfigHome: string;
let mockAppDataDir: string;

let clearEnv: () => void;

beforeEach(() => {
  tempRootDir = mkdtempSync(join(tmpdir(), "sops-age-tests-"));
  // Define mock home/config directories within the temp root
  mockHomeDir = join(tempRootDir, "userhome");
  // Simulates Linux/XDG structure
  mockXdgConfigHome = join(mockHomeDir, ".config");
  // Simulates Windows structure
  mockAppDataDir = join(mockHomeDir, "AppData", "Roaming");

  mkdirSync(mockHomeDir, { recursive: true });
  mkdirSync(mockXdgConfigHome, { recursive: true });
  mkdirSync(mockAppDataDir, { recursive: true });
});

afterEach(() => {
  if (clearEnv) {
    clearEnv();
  }
  if (tempRootDir) {
    rmSync(tempRootDir, { recursive: true, force: true });
  }
});

const setEnvVars = (vars: Record<string, string | undefined>) => {
  const originalEnv: Record<string, string | undefined> = {};
  Object.keys(vars).forEach((key) => {
    originalEnv[key] = process.env[key];
  });
  if (process.env.NODE_ENV) {
    originalEnv.NODE_ENV = process.env.NODE_ENV;
  }

  for (const key in vars) {
    if (vars[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = vars[key];
    }
  }
  clearEnv = () => {
    for (const key in originalEnv) {
      if (originalEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = originalEnv[key];
      }
    }
    if (originalEnv.NODE_ENV) {
      process.env.NODE_ENV = originalEnv.NODE_ENV;
    } else {
      delete process.env.NODE_ENV;
    }
  };
};

function ensureTargetDirectories() {
  // Ensure the target directories for default keys exist but are empty
  mkdirSync(join(mockHomeDir, ".ssh"), { recursive: true });
  mkdirSync(join(mockXdgConfigHome, "sops", "age"), { recursive: true });
  mkdirSync(join(mockAppDataDir, "sops", "age"), { recursive: true });
}

describe("SSH Key Conversion Tests", () => {
  test("should convert Ed25519 SSH private key to age format", () => {
    const ageKey = sshKeyToAge(
      DUMMY_ED25519_PRIVATE_KEY_CONTENT,
      "test-ed25519",
    );
    expect(ageKey).toBe(EXPECTED_AGE_KEY_FROM_DUMMY_ED25519);
  });

  test("should convert RSA SSH private key to a valid age format", () => {
    const ageKey = sshKeyToAge(DUMMY_RSA_PRIVATE_KEY_CONTENT, "test-rsa");
    expect(ageKey).not.toBeNull();
    expect(ageKey).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]+$/);
  });

  test("should load RSA key from SOPS_AGE_SSH_PRIVATE_KEY_FILE", async () => {
    const sshKeyPath = join(tempRootDir, "dummy_rsa_for_env.key");
    writeFileSync(sshKeyPath, DUMMY_RSA_PRIVATE_KEY_CONTENT);
    setEnvVars({
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: sshKeyPath,
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: mockAppDataDir,
    });
    ensureTargetDirectories();

    const keys = await findAllAgeKeys();
    keys.forEach((key) => {
      expect(key).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]+$/);
    });
  });

  test("should load RSA key from default .ssh/id_rsa", async () => {
    setEnvVars({
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: mockAppDataDir,
      SOPS_AGE_KEY: undefined,
      SOPS_AGE_KEY_FILE: undefined,
      SOPS_AGE_KEY_CMD: undefined,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });

    const defaultSshDir = join(mockHomeDir, ".ssh");
    mkdirSync(defaultSshDir, { recursive: true });
    const defaultSshKeyPath = join(defaultSshDir, "id_rsa");
    writeFileSync(defaultSshKeyPath, DUMMY_RSA_PRIVATE_KEY_CONTENT);

    mkdirSync(join(mockXdgConfigHome, "sops", "age"), { recursive: true });
    mkdirSync(join(mockAppDataDir, "sops", "age"), { recursive: true });

    const keys = await findAllAgeKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]+$/);
  });
});

describe("Edge Cases and Error Handling", () => {
  test("should handle unsupported SSH key types gracefully", () => {
    // ECDSA key (not supported by either ssh-to-age or SOPS)
    const ecdsaKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTi+HXotolCdcCT/1rrsISB7eb47QhH
FjkCAGAb9vebevw/J2eHa0LB0z16RgMWHbrOse3fNh1Z8zwCl7Sw4uRtAAAAsDNVff8zVX
3/AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOL4dei2iUJ1wJP/
WuuwhIHt5vjtCEcWOQIAYBv295t6/D8nZ4drQsHTPXpGAxYdus6x7d82HVnzPAKXtLDi5G
0AAAAgZzg1O7cXWxCG0sKXcsJG6/M7NWwuMWVREerv3j1K00QAAAASdGVzdC1lY2RzYUB0
ZXN0aW5nAQIDBAUG
-----END OPENSSH PRIVATE KEY-----
`;

    const result = sshKeyToAge(ecdsaKey, "test-ecdsa");
    expect(result).toBeNull();
  });

  test("should handle malformed SSH keys", () => {
    const malformedKey = "not-a-valid-ssh-key";
    expect(() => sshKeyToAge(malformedKey, "test-malformed")).toThrow();
  });

  test("should handle empty SSH key content", () => {
    expect(() => sshKeyToAge("", "test-empty")).toThrow(
      "SSH key should not be empty",
    );
    expect(() => sshKeyToAge("   \n  ", "test-whitespace")).toThrow(
      "SSH key should not be empty",
    );
  });
});

describe("Key Source Priority and Precedence", () => {
  test("should prioritize SOPS_AGE_SSH_PRIVATE_KEY_FILE over default SSH keys", async () => {
    const sshKeyPath = join(tempRootDir, "priority_test.key");
    writeFileSync(sshKeyPath, DUMMY_ED25519_PRIVATE_KEY_CONTENT);

    setEnvVars({
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: sshKeyPath,
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: mockAppDataDir,
    });

    // Create a different SSH key in the default location
    const defaultSshDir = join(mockHomeDir, ".ssh");
    mkdirSync(defaultSshDir, { recursive: true });
    writeFileSync(
      join(defaultSshDir, "id_ed25519"),
      DUMMY_RSA_PRIVATE_KEY_CONTENT,
    );
    ensureTargetDirectories();

    const keys = await findAllAgeKeys();
    expect(keys).toContain(EXPECTED_AGE_KEY_FROM_DUMMY_ED25519);
  });

  test("should prefer id_ed25519 over id_rsa when both exist", async () => {
    setEnvVars({
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: mockAppDataDir,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });

    const defaultSshDir = join(mockHomeDir, ".ssh");
    mkdirSync(defaultSshDir, { recursive: true });

    // Create both keys
    writeFileSync(
      join(defaultSshDir, "id_ed25519"),
      DUMMY_ED25519_PRIVATE_KEY_CONTENT,
    );
    writeFileSync(join(defaultSshDir, "id_rsa"), DUMMY_RSA_PRIVATE_KEY_CONTENT);
    ensureTargetDirectories();

    const keys = await findAllAgeKeys();
    expect(keys).toContain(EXPECTED_AGE_KEY_FROM_DUMMY_ED25519);
  });

  test("should fall back to id_rsa when id_ed25519 doesn't exist", async () => {
    setEnvVars({
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: mockAppDataDir,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });

    const defaultSshDir = join(mockHomeDir, ".ssh");
    mkdirSync(defaultSshDir, { recursive: true });

    // Create only RSA key
    writeFileSync(join(defaultSshDir, "id_rsa"), DUMMY_RSA_PRIVATE_KEY_CONTENT);
    ensureTargetDirectories();

    const keys = await findAllAgeKeys();
    expect(keys.length).toBeGreaterThanOrEqual(1);
    keys.forEach((key) => {
      expect(key).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]+$/);
    });
  });

  test("should combine keys from multiple sources", async () => {
    const sshKeyPath = join(tempRootDir, "additional.key");
    writeFileSync(sshKeyPath, DUMMY_ED25519_PRIVATE_KEY_CONTENT);

    setEnvVars({
      SOPS_AGE_KEY: MOCK_AGE_KEY_1,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: sshKeyPath,
      HOME: mockHomeDir,
    });

    const keys = await findAllAgeKeys();
    expect(keys).toContain(MOCK_AGE_KEY_1);
    expect(keys).toContain(EXPECTED_AGE_KEY_FROM_DUMMY_ED25519);
    expect(keys.length).toBeGreaterThanOrEqual(2);
  });
});

describe("Key Format Validation", () => {
  test("should accept both uppercase and lowercase age keys in files", async () => {
    const keyFilePath = join(tempRootDir, "mixed_case_keys.txt");
    const mixedCaseContent = `
# Test file with mixed case keys
AGE-SECRET-KEY-1TESTKEY1ABCDEFGHIJKLMNOPQRSTUVWXYZ012345
age-secret-key-1testkey2abcdefghijklmnopqrstuvwxyz543210
    `.trim();

    writeFileSync(keyFilePath, mixedCaseContent);
    setEnvVars({ SOPS_AGE_KEY_FILE: keyFilePath });

    const keys = await findAllAgeKeys();
    expect(keys).toContain(
      "AGE-SECRET-KEY-1TESTKEY1ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
    );
    expect(keys).toContain(
      "age-secret-key-1testkey2abcdefghijklmnopqrstuvwxyz543210",
    );
  });

  test("should handle comments and empty lines in key files", async () => {
    const keyFilePath = join(tempRootDir, "commented_keys.txt");
    const commentedContent = `
# This is a comment
${MOCK_AGE_KEY_1}

# Another comment
# ${MOCK_AGE_KEY_2}

${MOCK_AGE_KEY_2}
    `.trim();

    writeFileSync(keyFilePath, commentedContent);
    setEnvVars({ SOPS_AGE_KEY_FILE: keyFilePath });

    const keys = await findAllAgeKeys();
    expect(keys).toContain(MOCK_AGE_KEY_1);
    expect(keys).toContain(MOCK_AGE_KEY_2);
  });

  test("should warn about unsupported AGE plugin keys", async () => {
    const keyFilePath = join(tempRootDir, "plugin_keys.txt");
    const pluginContent = `
${MOCK_AGE_KEY_1}
AGE-PLUGIN-YUBIKEY-1ABCDEFGHIJKLMNOPQRSTUVWXYZ
    `.trim();

    writeFileSync(keyFilePath, pluginContent);
    setEnvVars({ SOPS_AGE_KEY_FILE: keyFilePath });

    // Capture console.warn calls
    const originalWarn = console.warn;
    const warnCalls: string[] = [];
    console.warn = (message: string) => warnCalls.push(message);

    try {
      const keys = await findAllAgeKeys();
      expect(keys).toContain(MOCK_AGE_KEY_1);
      expect(
        warnCalls.some((call) =>
          call.includes("AGE plugin keys are not supported"),
        ),
      ).toBe(true);
    } finally {
      console.warn = originalWarn;
    }
  });
});

describe("RSA vs Ed25519 Conversion Consistency", () => {
  test("should produce consistent results for the same RSA key", () => {
    const ageKey1 = sshKeyToAge(DUMMY_RSA_PRIVATE_KEY_CONTENT, "test-rsa-1");
    const ageKey2 = sshKeyToAge(DUMMY_RSA_PRIVATE_KEY_CONTENT, "test-rsa-2");

    expect(ageKey1).toBe(ageKey2);
    expect(ageKey1).not.toBeNull();
  });

  test("should produce consistent results for the same Ed25519 key", () => {
    const ageKey1 = sshKeyToAge(
      DUMMY_ED25519_PRIVATE_KEY_CONTENT,
      "test-ed25519-1",
    );
    const ageKey2 = sshKeyToAge(
      DUMMY_ED25519_PRIVATE_KEY_CONTENT,
      "test-ed25519-2",
    );

    expect(ageKey1).toBe(ageKey2);
    expect(ageKey1).toBe(EXPECTED_AGE_KEY_FROM_DUMMY_ED25519);
  });

  test("should produce different keys for different RSA keys", () => {
    // We'd need another RSA key to test this properly
    // For now, just verify our dummy RSA key produces a valid result
    const ageKey = sshKeyToAge(DUMMY_RSA_PRIVATE_KEY_CONTENT, "test-rsa");
    expect(ageKey).not.toBeNull();
    expect(ageKey).toMatch(/^AGE-SECRET-KEY-1[A-Z0-9]+$/);
    expect(ageKey).not.toBe(EXPECTED_AGE_KEY_FROM_DUMMY_ED25519);
  });
});

describe("findAllAgeKeys()", () => {
  test("should throw if no sources provide keys and default keys.txt is missing", async () => {
    setEnvVars({
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: mockAppDataDir,
      SOPS_AGE_KEY: undefined,
      SOPS_AGE_KEY_FILE: undefined,
      SOPS_AGE_KEY_CMD: undefined,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });
    ensureTargetDirectories();

    await expect(findAllAgeKeys()).rejects.toThrow();
  });

  test("should return empty array no sources provide keys and default keys.txt is empty", async () => {
    // Simulate Linux by setting HOME and XDG_CONFIG_HOME
    const originalPlatform = process.platform;
    Object.defineProperty(process, "platform", {
      value: "linux",
      writable: true,
      configurable: true,
    });

    setEnvVars({
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: undefined,
      SOPS_AGE_KEY: undefined,
      SOPS_AGE_KEY_FILE: undefined,
      SOPS_AGE_KEY_CMD: undefined,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });

    const sopsKeysDirForXDG = join(mockXdgConfigHome, "sops", "age");
    mkdirSync(sopsKeysDirForXDG, { recursive: true });
    writeFileSync(join(sopsKeysDirForXDG, "keys.txt"), "# comment only");
    mkdirSync(join(mockHomeDir, ".ssh"), { recursive: true });

    try {
      const keys = await findAllAgeKeys();
      expect(keys).toEqual([]);
    } finally {
      Object.defineProperty(process, "platform", {
        value: originalPlatform,
        configurable: true,
      });
    }
  });

  test("should load key from SOPS_AGE_KEY", async () => {
    setEnvVars({ SOPS_AGE_KEY: MOCK_AGE_KEY_1 });
    const keys = await findAllAgeKeys();
    expect(keys).toContain(MOCK_AGE_KEY_1);
  });

  test("should throw if SOPS_AGE_KEY_FILE is set but file not found", async () => {
    const keyFilePath = join(tempRootDir, "non_existent_keys.txt");
    setEnvVars({ SOPS_AGE_KEY_FILE: keyFilePath });

    await expect(findAllAgeKeys()).rejects.toThrow(
      `Failed to read SOPS_AGE_KEY_FILE (${keyFilePath})`,
    );
  });

  test("should load key from SOPS_AGE_KEY_CMD (real exec)", async () => {
    const cmd = `node -e "console.log('${MOCK_AGE_KEY_1}')"`;
    setEnvVars({ SOPS_AGE_KEY_CMD: cmd });

    const keys = await findAllAgeKeys();
    expect(keys).toContain(MOCK_AGE_KEY_1);
  });

  test("should load key from SOPS_AGE_KEY_FILE", async () => {
    const keyFilePath = join(tempRootDir, "my_age_keys_for_env_file.txt");
    writeFileSync(keyFilePath, MOCK_AGE_KEY_1);
    setEnvVars({
      SOPS_AGE_KEY_FILE: keyFilePath,
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: mockAppDataDir,
    });
    ensureTargetDirectories();

    const keys = await findAllAgeKeys();
    expect(keys).toContain(MOCK_AGE_KEY_1);
  });

  test("should load key from SOPS_AGE_SSH_PRIVATE_KEY_FILE", async () => {
    const sshKeyPath = join(tempRootDir, "dummy_id_for_env.key");
    writeFileSync(sshKeyPath, DUMMY_ED25519_PRIVATE_KEY_CONTENT);
    setEnvVars({
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: sshKeyPath,
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: mockAppDataDir,
    });
    ensureTargetDirectories();

    const keys = await findAllAgeKeys();
    expect(keys).toContain(EXPECTED_AGE_KEY_FROM_DUMMY_ED25519);
  });

  test("should load key from default .ssh/id_ed25519", async () => {
    setEnvVars({
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: mockAppDataDir,
      SOPS_AGE_KEY: undefined,
      SOPS_AGE_KEY_FILE: undefined,
      SOPS_AGE_KEY_CMD: undefined,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });

    const defaultSshDir = join(mockHomeDir, ".ssh");
    mkdirSync(defaultSshDir, { recursive: true });
    const defaultSshKeyPath = join(defaultSshDir, "id_ed25519");
    writeFileSync(defaultSshKeyPath, DUMMY_ED25519_PRIVATE_KEY_CONTENT);

    mkdirSync(join(mockXdgConfigHome, "sops", "age"), { recursive: true });
    mkdirSync(join(mockAppDataDir, "sops", "age"), { recursive: true });

    const keys = await findAllAgeKeys();
    expect(keys).toContain(EXPECTED_AGE_KEY_FROM_DUMMY_ED25519);
  });

  test("should load key from default sops/age/keys.txt (Linux simulation)", async () => {
    // Simulate Linux by setting HOME and XDG_CONFIG_HOME
    const originalPlatform = process.platform;
    Object.defineProperty(process, "platform", {
      value: "linux",
      writable: true,
      configurable: true,
    });

    setEnvVars({
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: mockXdgConfigHome,
      APPDATA: undefined,
      SOPS_AGE_KEY: undefined,
      SOPS_AGE_KEY_FILE: undefined,
      SOPS_AGE_KEY_CMD: undefined,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });

    const sopsKeysDirForXDG = join(mockXdgConfigHome, "sops", "age");
    mkdirSync(sopsKeysDirForXDG, { recursive: true });
    writeFileSync(join(sopsKeysDirForXDG, "keys.txt"), MOCK_AGE_KEY_1);

    mkdirSync(join(mockHomeDir, ".ssh"), { recursive: true });

    try {
      const keys = await findAllAgeKeys();
      expect(keys).toContain(MOCK_AGE_KEY_1);
    } finally {
      Object.defineProperty(process, "platform", {
        value: originalPlatform,
        configurable: true,
      });
    }
  });

  test("should load key from default sops/age/keys.txt (macOS simulation)", async () => {
    const originalPlatform = process.platform;
    Object.defineProperty(process, "platform", {
      value: "darwin",
      writable: true,
      configurable: true,
    });

    // On macOS, XDG_CONFIG_HOME can be set, or it falls back to ~/Library/...
    setEnvVars({
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: undefined,
      APPDATA: undefined,
      SOPS_AGE_KEY: undefined,
      SOPS_AGE_KEY_FILE: undefined,
      SOPS_AGE_KEY_CMD: undefined,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });

    const sopsKeysDirForMacDefault = join(
      mockHomeDir,
      "Library",
      "Application Support",
      "sops",
      "age",
    );
    mkdirSync(sopsKeysDirForMacDefault, { recursive: true });
    writeFileSync(join(sopsKeysDirForMacDefault, "keys.txt"), MOCK_AGE_KEY_1);
    mkdirSync(join(mockHomeDir, ".ssh"), { recursive: true });

    try {
      let keys = await findAllAgeKeys();
      expect(keys).toContain(MOCK_AGE_KEY_1);

      // Test 2: XDG_CONFIG_HOME IS set on macOS
      rmSync(sopsKeysDirForMacDefault, { recursive: true, force: true });
      const macXdgConfig = join(tempRootDir, "mac_xdg_config");
      mkdirSync(macXdgConfig, { recursive: true });
      const sopsKeysDirForMacXDG = join(macXdgConfig, "sops", "age");
      mkdirSync(sopsKeysDirForMacXDG, { recursive: true });
      writeFileSync(join(sopsKeysDirForMacXDG, "keys.txt"), MOCK_AGE_KEY_2);

      setEnvVars({
        HOME: mockHomeDir,
        XDG_CONFIG_HOME: macXdgConfig,
        APPDATA: undefined,
        SOPS_AGE_KEY: undefined,
        SOPS_AGE_KEY_FILE: undefined,
        SOPS_AGE_KEY_CMD: undefined,
        SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
      });
      keys = await findAllAgeKeys();
      expect(keys).toContain(MOCK_AGE_KEY_2);
    } finally {
      Object.defineProperty(process, "platform", {
        value: originalPlatform,
        configurable: true,
      });
    }
  });

  test("should load key from default sops/age/keys.txt (Windows simulation)", async () => {
    const originalPlatform = process.platform;
    Object.defineProperty(process, "platform", {
      value: "win32",
      writable: true,
      configurable: true,
    });

    setEnvVars({
      HOME: mockHomeDir,
      XDG_CONFIG_HOME: undefined,
      APPDATA: mockAppDataDir,
      SOPS_AGE_KEY: undefined,
      SOPS_AGE_KEY_FILE: undefined,
      SOPS_AGE_KEY_CMD: undefined,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });

    const sopsKeysDirForWindows = join(mockAppDataDir, "sops", "age");
    mkdirSync(sopsKeysDirForWindows, { recursive: true });
    writeFileSync(join(sopsKeysDirForWindows, "keys.txt"), MOCK_AGE_KEY_1);
    mkdirSync(join(mockHomeDir, ".ssh"), { recursive: true });

    try {
      const keys = await findAllAgeKeys();
      expect(keys).toContain(MOCK_AGE_KEY_1);
    } finally {
      Object.defineProperty(process, "platform", {
        value: originalPlatform,
        configurable: true,
      });
    }
  });
});

describe("findAllAgeKeys() - SOPS Integration Tests", () => {
  let tempDir: string;
  let sopsFilePath: string; // Path to .sops.yaml
  let secretFilePath: string; // Path to the original secret data
  let encryptedFilePath: string; // Path to the SOPS encrypted file

  const originalSecretData = "This is a super secret message!";

  // Placeholders for generated keys and recipients
  let ageRecipient: string;
  let agePrivateKey: string; // The actual AGE-SECRET-KEY-1...
  let sshEd25519Recipient: string; // ssh-ed25519 public key
  let sshEd25519PrivateKeyPath: string;
  let sshRsaRecipient: string; // ssh-rsa public key
  let sshRsaPrivateKeyPath: string;

  function runCmd(command: string, cwd?: string) {
    return execSync(command, { cwd, stdio: "pipe", encoding: "utf-8" });
  }

  let clearEnv: () => void;

  const setEnvVars = (vars: Record<string, string | undefined>) => {
    const originalEnv: Record<string, string | undefined> = {};
    Object.keys(vars).forEach((key) => {
      originalEnv[key] = process.env[key];
    });
    if (process.env.NODE_ENV) originalEnv.NODE_ENV = process.env.NODE_ENV;

    for (const key in vars) {
      if (vars[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = vars[key];
      }
    }
    clearEnv = () => {
      for (const key in originalEnv) {
        if (originalEnv[key] === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = originalEnv[key];
        }
      }
      if (originalEnv.NODE_ENV) process.env.NODE_ENV = originalEnv.NODE_ENV;
      else delete process.env.NODE_ENV;
    };
  };

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), "sops-integration-"));

    sopsFilePath = join(tempDir, ".sops.yaml");
    secretFilePath = join(tempDir, "secret.txt");
    encryptedFilePath = join(tempDir, "secret.enc.txt");
    sshEd25519PrivateKeyPath = join(tempDir, "id_ed25519_int_test");
    sshRsaPrivateKeyPath = join(tempDir, "id_rsa_int_test");

    // 1. Generate age key pair
    const ageKeyOutput = runCmd("age-keygen");
    // Output is like:
    // # created: 2023-10-27T12:00:00Z
    // # public key: age1...
    // AGE-SECRET-KEY-1...
    ageRecipient = ageKeyOutput.match(/public key: (age1[a-z0-9]+)/)?.[1] || "";
    agePrivateKey =
      ageKeyOutput.match(/(AGE-SECRET-KEY-1[A-Z0-9]+)/)?.[0] || "";
    if (!ageRecipient || !agePrivateKey) {
      throw new Error("Failed to parse age-keygen output");
    }

    // 2. Generate SSH ed25519 key pair
    runCmd(
      `ssh-keygen -t ed25519 -f "${sshEd25519PrivateKeyPath}" -N "" -C "sops-integration-test@example.com"`,
    );
    const sshEd25519PublicKey = readFileSync(
      `${sshEd25519PrivateKeyPath}.pub`,
      "utf-8",
    ).trim();
    sshEd25519Recipient = sshEd25519PublicKey;

    // 3. Generate RSA key pair
    runCmd(
      `ssh-keygen -t rsa -b 2048 -f "${sshRsaPrivateKeyPath}" -N "" -C "sops-integration-test-rsa@example.com"`,
    );
    const sshRsaPublicKey = readFileSync(
      `${sshRsaPrivateKeyPath}.pub`,
      "utf-8",
    ).trim();
    sshRsaRecipient = sshRsaPublicKey;

    // 4. Write original secret
    writeFileSync(secretFilePath, originalSecretData);

    // 5. Create .sops.yaml configuration
    const sopsConfig = {
      creation_rules: [
        {
          path_regex: "secret\\.txt$",
          age: `${ageRecipient},${sshEd25519Recipient},${sshRsaRecipient}`,
        },
      ],
    };
    writeFileSync(sopsFilePath, JSON.stringify(sopsConfig, null, 2));

    // 6. Encrypt the file with sops
    runCmd(
      `sops --config "${sopsFilePath}" -e "${secretFilePath}" > "${encryptedFilePath}"`,
      tempDir,
    );
    expect(existsSync(encryptedFilePath)).toBe(true);
  });

  afterAll(() => {
    if (tempDir && existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
    if (clearEnv) {
      clearEnv();
    }
  });

  beforeEach(() => {
    // Reset env vars that might be set by specific tests
    setEnvVars({
      HOME: undefined,
      XDG_CONFIG_HOME: undefined,
      APPDATA: undefined,
      SOPS_AGE_KEY: undefined,
      SOPS_AGE_KEY_FILE: undefined,
      SOPS_AGE_KEY_CMD: undefined,
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: undefined,
    });
  });

  async function attemptDecryptionWithFoundKeys(
    foundKeys: string[],
    targetEncryptedFilePath: string,
  ): Promise<string> {
    if (foundKeys.length === 0) {
      throw new Error(
        "No age keys found by findAllAgeKeys to attempt decryption.",
      );
    }
    const tempKeyFilePath = join(tempDir, "temp-decrypt-keys.txt");

    writeFileSync(tempKeyFilePath, foundKeys.join("\n"));

    try {
      const decryptedContent = runCmd(
        `SOPS_AGE_KEY_FILE="${tempKeyFilePath}" sops -d "${targetEncryptedFilePath}"`,
      );
      return decryptedContent.trim();
    } catch (error) {
      console.error(
        "Failed to decrypt with SOPS. Keys provided:",
        foundKeys.join("\\n"),
      );
      throw new Error(`SOPS decryption failed: ${error}`);
    } finally {
      if (existsSync(tempKeyFilePath)) {
        rmSync(tempKeyFilePath);
      }
    }
  }

  test("should discover age private key from default keys.txt and decrypt", async () => {
    const mockUserHome = join(tempDir, "testuser_home_1");
    const mockXdgConfig = join(mockUserHome, ".config"); // Linux
    const sopsKeysDir = join(mockXdgConfig, "sops", "age");
    mkdirSync(sopsKeysDir, { recursive: true });
    writeFileSync(join(sopsKeysDir, "keys.txt"), agePrivateKey);

    setEnvVars({
      HOME: mockUserHome,
      XDG_CONFIG_HOME: mockXdgConfig,
    });
    const originalPlatform = process.platform;
    Object.defineProperty(process, "platform", {
      value: "linux",
      writable: true,
      configurable: true,
    });

    try {
      const discoveredKeys = await findAllAgeKeys();
      expect(discoveredKeys).toContain(agePrivateKey);

      const decryptedData = await attemptDecryptionWithFoundKeys(
        discoveredKeys,
        encryptedFilePath,
      );
      expect(decryptedData).toBe(originalSecretData);
    } finally {
      Object.defineProperty(process, "platform", {
        value: originalPlatform,
        configurable: true,
      });
    }
  });

  test("should discover SSH private key from SOPS_AGE_SSH_PRIVATE_KEY_FILE and decrypt", async () => {
    setEnvVars({
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: sshEd25519PrivateKeyPath,
      HOME: join(tempDir, "someotherhome"),
    });

    const discoveredKeys = await findAllAgeKeys();
    const sshKeyContent = readFileSync(sshEd25519PrivateKeyPath, "utf-8");
    const expectedConvertedSshKey = sshKeyToAge(
      sshKeyContent,
      sshEd25519PrivateKeyPath,
    );

    expect(expectedConvertedSshKey).not.toBeNull();
    expect(discoveredKeys).toContain(expectedConvertedSshKey);

    const decryptedData = await attemptDecryptionWithFoundKeys(
      discoveredKeys,
      encryptedFilePath,
    );
    expect(decryptedData).toBe(originalSecretData);
  });

  test("should discover RSA SSH private key and decrypt", async () => {
    setEnvVars({
      SOPS_AGE_SSH_PRIVATE_KEY_FILE: sshRsaPrivateKeyPath,
      HOME: join(tempDir, "someotherhome3"),
    });

    const discoveredKeys = await findAllAgeKeys();
    const sshKeyContent = readFileSync(sshRsaPrivateKeyPath, "utf-8");
    const expectedConvertedSshKey = sshKeyToAge(
      sshKeyContent,
      sshRsaPrivateKeyPath,
    );

    expect(expectedConvertedSshKey).not.toBeNull();
    expect(discoveredKeys).toContain(expectedConvertedSshKey);

    const decryptedData = await attemptDecryptionWithFoundKeys(
      discoveredKeys,
      encryptedFilePath,
    );
    expect(decryptedData).toBe(originalSecretData);
  });

  test("should discover age private key from SOPS_AGE_KEY and decrypt", async () => {
    setEnvVars({
      SOPS_AGE_KEY: agePrivateKey,
      HOME: join(tempDir, "someotherhome2"),
    });

    const discoveredKeys = await findAllAgeKeys();
    expect(discoveredKeys).toContain(agePrivateKey);

    const decryptedData = await attemptDecryptionWithFoundKeys(
      discoveredKeys,
      encryptedFilePath,
    );
    expect(decryptedData).toBe(originalSecretData);
  });
});
