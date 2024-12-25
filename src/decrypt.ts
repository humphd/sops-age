// TODO: sort out the various TypeScript/ESLint rules I've disabled...

/* eslint-disable eslint-comments/disable-enable-pair */
/* eslint-disable eslint-comments/no-duplicate-disable */
/* eslint-disable eslint-comments/disable-enable-pair */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable eslint-comments/disable-enable-pair */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { toPath } from "lodash-es";
import cloneDeep from "lodash-es/cloneDeep.js";
import get from "lodash-es/get.js";

import type { SOPS } from "./sops-file.js";

import { decryptAgeEncryptionKey, getPublicAgeKey } from "./age.js";
import { type EncryptedData, decryptAesGcm } from "./cipher-noble.js";

// Valid SOPS data types
export enum SOPSDataType {
  Boolean = "bool",
  Bytes = "bytes",
  Float = "float",
  Integer = "int",
  String = "str",
}

export interface ParsedEncryptedData extends EncryptedData {
  datatype: SOPSDataType;
}

/** Type representing all possible decrypted values */
export type DecryptedValue = Uint8Array | boolean | number | string;

/** Converts decrypted string value to appropriate type based on SOPS datatype */
export function convertDecryptedValue(
  value: string,
  datatype: SOPSDataType,
): DecryptedValue {
  switch (datatype) {
    case SOPSDataType.Boolean:
      return value.toLowerCase() === "true";
    case SOPSDataType.Bytes:
      return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
    case SOPSDataType.Float:
      return Number.parseFloat(value);
    case SOPSDataType.Integer:
      return Number.parseInt(value, 10);
    case SOPSDataType.String:
      return value;
    default:
      throw new Error(`Unknown datatype: ${datatype}`);
  }
}

// Regular expression for SOPS format from https://github.com/getsops/sops/blob/73fadcf6b49006b0b77ba811f05eae8d740ed511/aes/cipher.go#L54
const encre = /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]$/;

function parse(value: string): ParsedEncryptedData {
  const matches = value.match(encre);
  if (!matches) {
    throw new Error(`Input string ${value} does not match sops' data format`);
  }

  try {
    const data = Uint8Array.from(atob(matches[1]), (c) => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(matches[2]), (c) => c.charCodeAt(0));
    const tag = Uint8Array.from(atob(matches[3]), (c) => c.charCodeAt(0));
    const rawDatatype = matches[4];

    // Validate the datatype is a valid SOPSDataType
    if (!Object.values(SOPSDataType).includes(rawDatatype as SOPSDataType)) {
      throw new Error(`Invalid SOPS data type: ${rawDatatype}`);
    }

    const datatype = rawDatatype as SOPSDataType;

    return { data, datatype, iv, tag };
  } catch (err) {
    throw new Error(
      `Error decoding base64: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

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
  return `${path.filter((x) => !/^\d+$/.test(x)).join(":")}:`;
}

/**
 * Decrypts SOPS-encrypted string using provided key and additional data.
 * Handles parsing the SOPS format and converting to the appropriate data type.
 * @param ciphertext Encrypted string in SOPS format
 * @param decryptionKey Key used for decryption
 * @param path Path to the encrypted value for additional authentication
 * @returns Decrypted value converted to appropriate type
 */
function decryptSOPSValue(
  ciphertext: string,
  decryptionKey: Uint8Array,
  path: string[],
): DecryptedValue {
  if (!ciphertext) {
    return "";
  }

  const encryptedValue = parse(ciphertext);
  const aad = path2gopath(path);
  let decrypted: Uint8Array;
  try {
    decrypted = decryptAesGcm(
      encryptedValue,
      decryptionKey,
      new TextEncoder().encode(aad),
    );
  } catch (err) {
    throw new Error(
      `AES-GCM decryption failed at path ${JSON.stringify(path)} for value "${ciphertext}": ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  const decryptedValue = new TextDecoder().decode(decrypted);
  return convertDecryptedValue(decryptedValue, encryptedValue.datatype);
}

function decryptObject(
  obj: any,
  decryptionKey: Uint8Array,
  path: string[] = [],
) {
  if (typeof obj !== "object" || obj === null) {
    return obj;
  }

  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (typeof value === "string" && value.startsWith("ENC[AES256_GCM,data:")) {
      obj[key] = decryptSOPSValue(value, decryptionKey, [...path, key]);
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

/**
 * Decrypts a SOPS-encrypted data structure using an AGE key.
 *
 * If a keyPath is provided, only that specific value will be decrypted and returned.
 * Otherwise, the entire data structure (excluding SOPS metadata) will be decrypted.
 *
 * @param sops - The SOPS data structure containing encrypted values and metadata
 * @param options - Configuration options for decryption
 * @param options.keyPath - Optional path to decrypt a specific value (lodash path format)
 * @param options.secretKey - AGE secret key for decryption (falls back to SOPS_AGE_KEY env var)
 * @returns The decrypted value (if keyPath provided) or object with all values decrypted
 */
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

    return decryptSOPSValue(value, decryptionKey, toPath(keyPath));
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
