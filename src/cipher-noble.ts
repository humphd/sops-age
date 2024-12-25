import { gcm } from "@noble/ciphers/aes";

// Base type for encrypted data needed by decrypt
export interface EncryptedData {
  data: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

/** Decrypts data using AES-GCM with the provided key and additional data */
export function decryptAesGcm(
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
