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

// Regular expression for SOPS format
const encre = /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]$/;

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

class Cipher {
  decrypt(ciphertext, key, additionalData) {
    if (isEmpty(ciphertext)) {
      return "";
    }

    const encryptedValue = this.parse(ciphertext);

    // Convert additionalData to Uint8Array if provided
    const aad = additionalData ? utf8ToBytes(additionalData) : undefined;

    // Combine data and tag for noble-ciphers format
    const combined = new Uint8Array(
      encryptedValue.data.length + encryptedValue.tag.length,
    );
    combined.set(encryptedValue.data);
    combined.set(encryptedValue.tag, encryptedValue.data.length);

    const aes = gcm(key, encryptedValue.iv, aad);
    const decrypted = aes.decrypt(combined);
    const decryptedValue = bytesToUtf8(decrypted);

    switch (encryptedValue.datatype) {
      case "str":
        return decryptedValue;
      case "int":
        return parseInt(decryptedValue, 10);
      case "float":
        return parseFloat(decryptedValue);
      case "bool":
        return decryptedValue.toLowerCase() === "true";
      default:
        throw new Error(`Unknown datatype: ${encryptedValue.datatype}`);
    }
  }

  encrypt(plaintext, key, iv, additionalData) {
    if (isEmpty(plaintext)) {
      return "";
    }

    let plainBytes;
    let encryptedType;

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

    // Convert additionalData to Uint8Array if provided
    const aad = additionalData ? utf8ToBytes(additionalData) : undefined;

    const aes = gcm(key, iv, aad);
    const encrypted = aes.encrypt(plainBytes);

    // Noble's GCM implementation returns concatenated ciphertext+tag
    // We need to split them for SOPS format
    const dataBytes = encrypted.slice(0, -16);
    const tagBytes = encrypted.slice(-16);

    // Convert to base64 strings
    const dataBase64 = uint8ArrayToBase64(dataBytes);
    const ivBase64 = uint8ArrayToBase64(iv);
    const tagBase64 = uint8ArrayToBase64(tagBytes);

    return `ENC[AES256_GCM,data:${dataBase64},iv:${ivBase64},tag:${tagBase64},type:${encryptedType}]`;
  }

  parse(value) {
    const matches = value.match(encre);
    if (!matches) {
      throw new Error(`Input string ${value} does not match sops' data format`);
    }

    try {
      const data = base64ToUint8Array(matches[1]);
      const iv = base64ToUint8Array(matches[2]);
      const tag = base64ToUint8Array(matches[3]);
      const datatype = matches[4];

      return { data, datatype, iv, tag };
    } catch (err) {
      throw new Error(`Error decoding base64: ${err.message}`);
    }
  }
}

// Example usage
function main() {
  const cipher = new Cipher();

  // Fixed 32-byte key (AES-256)
  const key = new Uint8Array([
    0x79, 0x82, 0xc4, 0x88, 0xb1, 0x50, 0x9e, 0x98, 0xd8, 0x92, 0xc5, 0x93,
    0x88, 0xaa, 0x70, 0xbf, 0x6b, 0x0a, 0x87, 0x0f, 0x96, 0x25, 0xbe, 0x45,
    0xa3, 0xf6, 0x98, 0xd9, 0x8a, 0x97, 0xb3, 0x07,
  ]);

  // Fixed 32-byte IV/nonce
  const iv = new Uint8Array([
    49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50,
  ]);

  try {
    // const encrypted = cipher.encrypt("Hello, World!", key, iv, "some-auth-data");
    const encrypted =
      "ENC[AES256_GCM,data:s0/KBsFec29XLrGbAnLiNA==," +
      "iv:k5oP3kb8tTbZaL3PxbFWN8ToOb8vfv2b1EuPz1LbmYU=," +
      "tag:n1RlTSRKGgoB909D4I3n+A==,type:str]";
    console.log("Encrypted:", encrypted);

    const decrypted = cipher.decrypt(encrypted, key, "secret:");
    console.log("Decrypted:", decrypted);
  } catch (err) {
    console.error("Error:", err);
  }
}

// Run the example
main();
