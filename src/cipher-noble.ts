import { gcm } from "@noble/ciphers/aes";
import { bytesToUtf8, utf8ToBytes } from "@noble/ciphers/utils";


function isEmpty(v) {
  if (v === null || v === undefined) {
    return true;
  }

  switch (typeof v) {
    case "string":
      return v === "";
    case "number":
      return v === 0;
    case "boolean":
      return false;
    default:
      return false;
  }
}

// Base type for encrypted data needed by decrypt
export interface EncryptedData {
  data: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

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

/** Decrypts data using AES-GCM with the provided key and additional data */
function decrypt(
  encryptedValue: EncryptedData,
  key: Uint8Array,
  additionalData: Uint8Array,
): Uint8Array {
  // Combine data and tag for noble-ciphers format
  const combined = new Uint8Array(
    encryptedValue.data.length + encryptedValue.tag.length,
  );
  combined.set(encryptedValue.data);
  combined.set(encryptedValue.tag, encryptedValue.data.length);

  const aes = gcm(key, encryptedValue.iv, additionalData);
  return aes.decrypt(combined);
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
      return value.toLowerCase() === 'true';
    case SOPSDataType.Bytes:
      return Uint8Array.from(atob(value), c => c.charCodeAt(0));
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

/** Decrypts SOPS-encrypted string using provided key and additional data *
 * @param ciphertext SOPS-encrypted "ENC[AES256_GCM,...]" string
 * @param key AES key to use for decryption
 * @param path Path to the value being decrypted, used as additional data for decryption
 * @returns Decrypted value as a string, number, boolean, or Buffer
 * */
export function decryptSOPS(ciphertext: string, key: Uint8Array, path: string) {
  if (isEmpty(ciphertext)) {
    return "";
  }

  const encryptedValue = parse(ciphertext);
  const aad = utf8ToBytes(path);
  const decrypted = decrypt(encryptedValue, key, aad);
  const decryptedValue = bytesToUtf8(decrypted);
  return convertDecryptedValue(decryptedValue, encryptedValue.datatype);
}

// Regular expression for SOPS format from https://github.com/getsops/sops/blob/73fadcf6b49006b0b77ba811f05eae8d740ed511/aes/cipher.go#L54
const encre = /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]$/;

function parse(value: string): ParsedEncryptedData {
  const matches = value.match(encre);
  if (!matches) {
    throw new Error(`Input string ${value} does not match sops' data format`);
  }

  try {
    const data = Uint8Array.from(atob(matches[1]), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(matches[2]), c => c.charCodeAt(0));
    const tag = Uint8Array.from(atob(matches[3]), c => c.charCodeAt(0));
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

/*
in unlikely case we ever need to encrypt data:

function uint8ArrayToBase64(bytes) {
  const binString = Array.from(bytes, (x) => String.fromCodePoint(x)).join("");
  return btoa(binString);
}

function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  additionalData?: string
): { data: Uint8Array; tag: Uint8Array } {
  // Convert additionalData to Uint8Array if provided
  const aad = additionalData ? utf8ToBytes(additionalData) : undefined;

  const aes = gcm(key, iv, aad);
  const encrypted = aes.encrypt(plaintext);

  // Noble's GCM implementation returns concatenated ciphertext+tag
  // We need to split them
  return {
    data: encrypted.slice(0, -16),
    tag: encrypted.slice(-16)
  };
}

function encryptConvenient(plaintext: string | number | boolean, key: Uint8Array, iv: Uint8Array, additionalData?: string): string {
  if (isEmpty(plaintext)) {
    return "";
  }

  let plainBytes: Uint8Array;
  let encryptedType: string;

  switch (typeof plaintext) {
    case "string":
      encryptedType = "str";
      plainBytes = utf8ToBytes(plaintext);
      break;
    case "number":
      if (Number.isInteger(plaintext)) {
        encryptedType = "int";
        plainBytes = utf8ToBytes(plaintext.toString());
      } else {
        encryptedType = "float";
        plainBytes = utf8ToBytes(plaintext.toString());
      }
      break;
    case "boolean":
      encryptedType = "bool";
      plainBytes = utf8ToBytes(plaintext ? "True" : "False");
      break;
    default:
      throw new Error(
        `Value to encrypt has unsupported type ${typeof plaintext}`,
      );
  }

  const { data, tag } = encrypt(plainBytes, key, iv, additionalData);

  // Convert to base64 strings
  const dataBase64 = uint8ArrayToBase64(data);
  const ivBase64 = uint8ArrayToBase64(iv);
  const tagBase64 = uint8ArrayToBase64(tag);

  return `ENC[AES256_GCM,data:${dataBase64},iv:${ivBase64},tag:${tagBase64},type:${encryptedType}]`;
}
  */
