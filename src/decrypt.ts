// TODO: sort out the various TypeScript/ESLint rules I've disabled...

/* eslint-disable eslint-comments/disable-enable-pair */
/* eslint-disable eslint-comments/no-duplicate-disable */
/* eslint-disable eslint-comments/disable-enable-pair */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable eslint-comments/disable-enable-pair */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { createDecipheriv } from "crypto";
import { toPath } from "lodash-es";
import cloneDeep from "lodash-es/cloneDeep.js";
import get from "lodash-es/get.js";

import type { SOPS } from "./sops-file.js";

import { decryptAgeEncryptionKey, getPublicAgeKey } from "./age.js";
import { decryptSOPS } from "./cipher-noble.js";

async function getSopsEncryptionKeyForRecipient(sops: SOPS, secretKey: string) {
  const pubKey = await getPublicAgeKey(secretKey);

  const recipient = sops.sops.age.find((config) => config.recipient === pubKey);
  if (!recipient) {
    throw new Error("no matching recipient found in age config");
  }

  return decryptAgeEncryptionKey(recipient.enc, secretKey);
}

/**
 * Converts a path array to SOPS' Go-style path format.
 * Filters out numeric indices and joins remaining path segments with colons.
 * @param path Array of path segments
 * @returns Path string in format "path:to:key:"
 */
function path2gopath(path: string[]): string {
  return `${path.filter(x => !/^\d+$/.test(x)).join(":")}:`;
}

/**
 *
 * @param value
 * @param decryptionKey
 * @param path equivalent to additionalData param in https://github.com/getsops/sops/blob/73fadcf6b49006b0b77ba811f05eae8d740ed511/aes/cipher.go#L79 . This gets joined into "path:to:key:" to match format of additionalData
 * @param aad
 * @returns
 */
function decryptValue(
  value: string,
  decryptionKey: Uint8Array,
  path: string[],
): Uint8Array | boolean | number | string {
  const key = decryptionKey;
  const aad = path2gopath(path);

  let result;
  try {
    result = decryptSOPS(value, key, aad);
  } catch (e) {
    console.error(JSON.stringify(path), value, e);
    throw e;
  }

  return result;
}

function decryptObject(obj: any, decryptionKey: Uint8Array, path: string[] = []) {
  if (typeof obj !== "object" || obj === null) {
    return obj;
  }

  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (typeof value === "string" && value.startsWith("ENC[AES256_GCM,data:")) {
      obj[key] = decryptValue(value, decryptionKey, [...path, key]);
    } else if (typeof value === "object") {
      // Recursively decrypt objects and arrays
      obj[key] = decryptObject(value, decryptionKey, [...path, key]);
    }
  }

  return obj;
}

/**
 * Options for decrypting SOPS encrypted data
 */
export interface DecryptOptions {
  /**
   * A path to a specific key in the SOPS file to decrypt.
   * See https://lodash.com/docs/#get for format
   */
  keyPath?: string;

  /**
   * The secret key (e.g., AGE key) to use when decrypting.
   * If not specified the `SOPS_AGE_KEY` env var will be used, if available.
   */
  secretKey?: string;
}

export async function decrypt(sops: SOPS, options: DecryptOptions) {
  const keyPath = options.keyPath;
  const secretKey = options.secretKey ?? process.env.SOPS_AGE_KEY;
  if (!secretKey) {
    throw new Error(
      "A secretKey is required to decrypt. Set one on options or via the SOPS_AGE_KEY environment variable",
    );
  }

  const decryptionKey = await getSopsEncryptionKeyForRecipient(sops, secretKey);

  // If we have a path to a specific key, only decrypt that
  if (keyPath) {
    const value = get(sops, keyPath);
    if (typeof value !== "string") {
      throw new Error(`Unable to get sops value at keyPath="${keyPath}"`);
    }

    return decryptValue(value, decryptionKey, toPath(keyPath));
  }

  // Otherwise, decrypt the whole thing, stripping out the sops metadata
  // and only use the rest of the keys
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { sops: _, ...data } = sops;
  // Deep clone the object so we can decrypt in-place:
  const cloned = cloneDeep(data);
  const decryptedData = decryptObject(cloned, decryptionKey);

  if (sops.sops.mac && sops.sops.lastmodified) {
    // TODO: decrypt mac and compare to hash of all values.
    //
    // Message Authentication Code - https://github.com/getsops/sops/?tab=readme-ov-file#message-authentication-code
    //
    // In addition to authenticating branches of the tree using keys
    // as additional data, SOPS computes a MAC on all the values to
    // ensure that no value has been added or removed fraudulently.
    // The MAC is stored encrypted with AES_GCM and the data key
    // under tree -> sops -> mac. This behavior can be modified
    // using --mac-only-encrypted flag or .sops.yaml config file
    // which makes SOPS compute a MAC only over values it encrypted
    // and not all values.
  }

  return decryptedData;
}
