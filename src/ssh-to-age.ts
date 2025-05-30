import { sha256, sha512 } from "@noble/hashes/sha2";
import { bech32 } from "@scure/base";
import * as sshpk from "sshpk";
import { readFile } from "node:fs/promises";

function clampX25519PrivateKey(key: Uint8Array): void {
  if (key.length !== 32) {
    throw new Error("X25519 private key must be 32 bytes for clamping.");
  }
  key[0] &= 248;
  key[31] &= 127;
  key[31] |= 64;
}

function encodeX25519Bech32PrivateKey(privateKeyBytes: Uint8Array): string {
  if (privateKeyBytes.length !== 32) {
    throw new Error("X25519 private key must be 32 bytes for Bech32 encoding.");
  }
  const encoded = bech32.encode(
    "AGE-SECRET-KEY-",
    bech32.toWords(privateKeyBytes),
  );
  return encoded.toUpperCase();
}

function convertEd25519SeedToX25519PrivateKey(
  ed25519Seed: Uint8Array,
): Uint8Array {
  if (ed25519Seed.length !== 32) {
    throw new Error("ed25519 seed must be 32 bytes.");
  }
  const hashedSeed = sha512(ed25519Seed);
  // The X25519 private key is the first 32 bytes of the SHA-512 hash of the Ed25519 seed.
  const x25519Sk = hashedSeed.slice(0, 32);
  return x25519Sk;
}

function convertRsaPublicKeyToX25519PrivateKey(
  rsaN: Uint8Array,
  rsaE: Uint8Array,
): Uint8Array {
  const hasher = sha256.create();
  hasher.update(rsaN);
  hasher.update(rsaE);
  const x25519Sk = hasher.digest();
  clampX25519PrivateKey(x25519Sk);
  return x25519Sk;
}

/**
 * Parses SSH private key content, converts to an X25519 Bech32 private key string.
 * Returns the Bech32 string or null if the key is unsupported or file is empty.
 * Throws an error if parsing/conversion fails for a supported type.
 */
export function sshKeyToAge(
  keyFileContent: string,
  filePathForErrorMsg: string,
): string | null {
  try {
    // Empty file? Nothing to parse.
    if (keyFileContent.trim() === "") {
      return null;
    }

    const sshPk = sshpk.parsePrivateKey(keyFileContent, "auto", {
      filename: filePathForErrorMsg,
    });
    let x25519SkBytes: Uint8Array;

    if (sshPk.type === "ed25519") {
      // sshpk provides the 32-byte private seed directly as part "k".
      // Part "A" is the 32-byte public key.
      const seedPart = sshPk.parts.find(
        (part) => part.name === "k" && part.data && part.data.length === 32,
      );

      if (!seedPart || !seedPart.data) {
        console.error(
          `Failed to find 32-byte "k" part (seed) for Ed25519 key. SSHPK Parts for ${filePathForErrorMsg}:`,
        );
        sshPk.parts.forEach((part, index) => {
          console.error(
            `  Part ${index}: Name: "${part.name}", Type: ${typeof part.data}, Length: ${part.data?.length}`,
          );
        });
        throw new Error(
          `Could not extract 32-byte seed (part "k") from Ed25519 key in ${filePathForErrorMsg}.`,
        );
      }
      const ed25519Seed = Uint8Array.from(seedPart.data);
      x25519SkBytes = convertEd25519SeedToX25519PrivateKey(ed25519Seed);
    } else if (sshPk.type === "rsa") {
      // Access RSA components (N, E) from the `parts` array
      const rsaNPart = sshPk.parts.find((part) => part.name === "n");
      const rsaEPart = sshPk.parts.find((part) => part.name === "e");

      if (!rsaNPart || !rsaEPart || !rsaNPart.data || !rsaEPart.data) {
        throw new Error(
          `Could not extract N or E (modulus or public exponent) from RSA key in ${filePathForErrorMsg}.`,
        );
      }
      const rsaN = Uint8Array.from(rsaNPart.data);
      const rsaE = Uint8Array.from(rsaEPart.data);
      x25519SkBytes = convertRsaPublicKeyToX25519PrivateKey(rsaN, rsaE);
    } else {
      console.warn(
        `Unsupported SSH key type "${sshPk.type}" for age conversion in ${filePathForErrorMsg}. Skipping.`,
      );
      return null;
    }
    return encodeX25519Bech32PrivateKey(x25519SkBytes);
  } catch (error: any) {
    throw new Error(
      `Failed to parse/convert SSH key from ${filePathForErrorMsg}: ${
        error.message || error
      }`,
      { cause: error },
    );
  }
}

/**
 * Reads an SSH private key file, parses, and converts to age (X25519 Bech32 string).
 */
export async function sshKeyFileToAge(
  filePath: string,
): Promise<string | null> {
  const content = await readFile(filePath, "utf-8");
  return sshKeyToAge(content, filePath);
}
