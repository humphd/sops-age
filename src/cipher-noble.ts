import { gcm } from "@noble/ciphers/aes";
import {
  bytesToHex,
  bytesToUtf8,
  hexToBytes,
  utf8ToBytes,
} from "@noble/ciphers/utils";

function uint8ArrayToBase64(bytes) {
  const binString = Array.from(bytes, (x) => String.fromCodePoint(x)).join("");
  return btoa(binString);
}

function base64ToUint8Array(base64) {
  const binString = atob(base64);
  return new Uint8Array(binString.split("").map((c) => c.charCodeAt(0)));
}

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

// Extended type that includes datatype, used by parse
export enum SOPSDataType {
  Boolean = "bool",
  Float = "float",
  Integer = "int",
  String = "str"
}

export interface ParsedEncryptedData extends EncryptedData {
  datatype: SOPSDataType;
}

function decrypt(
  encryptedValue: EncryptedData,
  key: Uint8Array,
  additionalData?: string
): string {
  // Convert additionalData to Uint8Array if provided
  const aad = additionalData ? utf8ToBytes(additionalData) : undefined;

  // Combine data and tag for noble-ciphers format
  const combined = new Uint8Array(encryptedValue.data.length + encryptedValue.tag.length);
  combined.set(encryptedValue.data);
  combined.set(encryptedValue.tag, encryptedValue.data.length);

  const aes = gcm(key, encryptedValue.iv, aad);
  const decrypted = aes.decrypt(combined);
  return bytesToUtf8(decrypted);
}

function convertDecryptedValue(value: string, datatype: SOPSDataType): boolean | number | string {
  switch (datatype) {
    case SOPSDataType.String:
      return value;
    case SOPSDataType.Integer:
      return Number.parseInt(value, 10);
    case SOPSDataType.Float:
      return Number.parseFloat(value);
    case SOPSDataType.Boolean:
      return value.toLowerCase() === "true";
  }
}

function decryptSOPS(ciphertext: string, key: Uint8Array, additionalData?: string) {
  if (isEmpty(ciphertext)) {
    return "";
  }

  const encryptedValue = parse(ciphertext);
  const decryptedValue = decrypt(encryptedValue, key, additionalData);
  return convertDecryptedValue(decryptedValue, encryptedValue.datatype);
}

/*
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

// Regular expression for SOPS format from https://github.com/getsops/sops/blob/73fadcf6b49006b0b77ba811f05eae8d740ed511/aes/cipher.go#L54
const encre = /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]$/;

function parse(value: string): ParsedEncryptedData {
  const matches = value.match(encre);
  if (!matches) {
    throw new Error(`Input string ${value} does not match sops' data format`);
  }

  try {
    const data = base64ToUint8Array(matches[1]);
    const iv = base64ToUint8Array(matches[2]);
    const tag = base64ToUint8Array(matches[3]);
    const datatype = matches[4] as SOPSDataType;

    return { data, datatype, iv, tag };
  } catch (err) {
    throw new Error(`Error decoding base64: ${err instanceof Error ? err.message : String(err)}`);
  }
}

