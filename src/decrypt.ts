import cloneDeep from "lodash/cloneDeep.js";
import get from "lodash/get.js";
import toPath from "lodash/toPath.js";

import type { SOPS } from "./sops-file.js";
import { decryptAgeEncryptionKey, getPublicAgeKey } from "./age.js";
import { type EncryptedData, decryptAesGcm } from "./cipher-noble.js";
import { getEnvVar } from "./runtime.js";
import { findAllAgeKeys } from "./age-key.js";

export type SOPSDataType = "bool" | "bytes" | "float" | "int" | "str";

function isValidSOPSDataType(value: string): value is SOPSDataType {
  return ["bool", "bytes", "float", "int", "str"].includes(value);
}

export interface ParsedEncryptedData extends EncryptedData {
  data: Uint8Array;
  datatype: SOPSDataType;
  iv: Uint8Array;
  tag: Uint8Array;
}

/** Type representing all possible decrypted values */
export type DecryptedValue = Uint8Array | boolean | number | string;

/** Converts decrypted string value to appropriate type based on SOPS datatype */
function convertDecryptedValue(
  value: string,
  datatype: SOPSDataType,
): DecryptedValue {
  switch (datatype) {
    case "bool":
      return value.toLowerCase() === "true";
    case "bytes":
      return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
    case "float":
      return Number.parseFloat(value);
    case "int":
      return Number.parseInt(value, 10);
    case "str":
      return value;
  }
}

// Regular expression for SOPS format from https://github.com/getsops/sops/blob/73fadcf6b49006b0b77ba811f05eae8d740ed511/aes/cipher.go#L54
const encRegex = /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]$/;

function parse(value: string): ParsedEncryptedData {
  const matches = value.match(encRegex);
  if (!matches) {
    throw new Error(`Input string ${value} does not match sops' data format`);
  }

  try {
    const data = Uint8Array.from(atob(matches[1]), (c) => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(matches[2]), (c) => c.charCodeAt(0));
    const tag = Uint8Array.from(atob(matches[3]), (c) => c.charCodeAt(0));
    const rawDatatype = matches[4];

    if (!isValidSOPSDataType(rawDatatype)) {
      throw new Error(`Invalid SOPS data type: ${rawDatatype}`);
    }

    return { data, datatype: rawDatatype, iv, tag };
  } catch (err) {
    throw new Error(
      `Error decoding base64: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Attempts to find a matching age recipient and decrypt the encryption key
 * using all available secret keys until one works.
 */
async function getSopsEncryptionKey(
  sops: SOPS,
  secretKeys: string[],
): Promise<Uint8Array> {
  const errors: string[] = [];

  for (const secretKey of secretKeys) {
    try {
      const pubKey = await getPublicAgeKey(secretKey);
      const recipient = sops.sops.age.find(
        (config) => config.recipient === pubKey,
      );

      if (!recipient) {
        errors.push(`No matching recipient found for key: ${pubKey}`);
        continue;
      }

      return await decryptAgeEncryptionKey(recipient.enc, secretKey);
    } catch (error) {
      errors.push(
        `Failed to decrypt with key ${secretKey.substring(0, 20)}...: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  throw new Error(
    `Failed to decrypt with any available age keys. Errors:\n${errors.join("\n")}`,
  );
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

  /* The secret key (e.g., AGE key) to use when decrypting.
   * If not specified, all available keys will be discovered and tried.
   */
  secretKey?: string;
}

/**
 * Decrypts a SOPS-encrypted data structure using an AGE key.
 *
 * If no secretKey is provided, all available age keys will be discovered
 * using the same logic as SOPS:
 * - SSH keys (converted to age format)
 * - SOPS_AGE_KEY environment variable
 * - SOPS_AGE_KEY_FILE environment variable
 * - SOPS_AGE_KEY_CMD environment variable
 * - Default config file (~/.config/sops/age/keys.txt)
 *
 * @param sops - The SOPS data structure containing encrypted values and metadata
 * @param options - Configuration options for decryption
 * @param options.keyPath - Optional path to decrypt a specific value (lodash path format)
 * @param options.secretKey - AGE secret key for decryption (falls back to SOPS_AGE_KEY env var)
 * @returns The decrypted value (if keyPath provided) or object with all values decrypted
 */
export async function decrypt(sops: SOPS, options: DecryptOptions) {
  const { keyPath, secretKey } = options;

  // Determine which secret keys to use
  let secretKeys: string[];
  if (secretKey) {
    // Use the explicitly provided key
    secretKeys = [secretKey];
  } else {
    // Discover all available keys using SOPS logic
    try {
      secretKeys = await findAllAgeKeys();
    } catch (error) {
      throw new Error(
        `Failed to find age keys: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    if (secretKeys.length === 0) {
      throw new Error(
        "No age keys found. Provide a secretKey option or set age keys via " +
          "environment variables, SSH keys, or the default sops keys.txt config file.",
      );
    }
  }

  // Try to decrypt the SOPS encryption key with available secret keys
  const decryptionKey = await getSopsEncryptionKey(sops, secretKeys);

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
