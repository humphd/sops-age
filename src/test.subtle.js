// Regular expression for SOPS format
const encre = /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]$/;

const NONCE_SIZE = 32;

function isEmpty(v) {
  if (v === null || v === undefined) return true;
  switch (typeof v) {
    case 'string':
      return v === '';
    case 'number':
      return v === 0;
    case 'boolean':
      return false;
    default:
      return false;
  }
}

function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function uint8ArrayToBase64(uint8Array) {
  const binary = String.fromCharCode.apply(null, uint8Array);
  return btoa(binary);
}

function stringToUint8Array(str) {
  return new TextEncoder().encode(str);
}

function uint8ArrayToString(uint8Array) {
  return new TextDecoder().decode(uint8Array);
}

class Cipher {
  async encrypt(plaintext, key, iv, additionalData) {
    if (isEmpty(plaintext)) {
      return '';
    }

    let plainBytes;
    let encryptedType;

    switch (typeof plaintext) {
      case 'string':
        encryptedType = 'str';
        plainBytes = stringToUint8Array(plaintext);
        break;
      case 'number':
        if (Number.isInteger(plaintext)) {
          encryptedType = 'int';
          plainBytes = stringToUint8Array(plaintext.toString());
        } else {
          encryptedType = 'float';
          plainBytes = stringToUint8Array(plaintext.toString());
        }
        break;
      case 'boolean':
        encryptedType = 'bool';
        plainBytes = stringToUint8Array(plaintext ? 'True' : 'False');
        break;
      default:
        throw new Error(`Value to encrypt has unsupported type ${typeof plaintext}`);
    }

    const algorithm = {
      name: 'AES-GCM',
      iv: iv,
      additionalData: stringToUint8Array(additionalData),
      tagLength: 128
    };

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      'AES-GCM',
      false,
      ['encrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
      algorithm,
      cryptoKey,
      plainBytes
    );

    // Split the result into ciphertext and tag
    const encryptedArray = new Uint8Array(encrypted);
    const dataBytes = encryptedArray.slice(0, -16);
    const tagBytes = encryptedArray.slice(-16);

    return `ENC[AES256_GCM,data:${uint8ArrayToBase64(dataBytes)},iv:${uint8ArrayToBase64(iv)},tag:${uint8ArrayToBase64(tagBytes)},type:${encryptedType}]`;
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

      return { data, iv, tag, datatype };
    } catch (err) {
      throw new Error(`Error decoding base64: ${err.message}`);
    }
  }

  async decrypt(ciphertext, key, additionalData) {
    if (isEmpty(ciphertext)) {
      return '';
    }

    const encryptedValue = this.parse(ciphertext);

    // Combine data and tag for decryption
    const combined = new Uint8Array(encryptedValue.data.length + encryptedValue.tag.length);
    combined.set(encryptedValue.data);
    combined.set(encryptedValue.tag, encryptedValue.data.length);

    const algorithm = {
      name: 'AES-GCM',
      iv: encryptedValue.iv,
      additionalData: stringToUint8Array(additionalData),
      tagLength: 128
    };

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      'AES-GCM',
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      algorithm,
      cryptoKey,
      combined
    );

    const decryptedValue = uint8ArrayToString(new Uint8Array(decrypted));

    switch (encryptedValue.datatype) {
      case 'str':
        return decryptedValue;
      case 'int':
        return parseInt(decryptedValue, 10);
      case 'float':
        return parseFloat(decryptedValue);
      case 'bytes':
        return new Uint8Array(decrypted);
      case 'bool':
        return decryptedValue.toLowerCase() === 'true';
      default:
        throw new Error(`Unknown datatype: ${encryptedValue.datatype}`);
    }
  }
}

// Example usage
async function main() {
  const cipher = new Cipher();
  
  // Fixed 32-byte key (AES-256)
  const key = new Uint8Array(32).fill(0x12);
  
  // Fixed 32-byte IV/nonce
  const iv = new Uint8Array(32).fill(0x12);
  
  try {
    const encrypted = await cipher.encrypt("Hello, World!", key, iv, "some-auth-data");
    console.log("Encrypted:", encrypted);
    
    const decrypted = await cipher.decrypt(encrypted, key, "some-auth-data");
    console.log("Decrypted:", decrypted);
  } catch (err) {
    console.error("Error:", err);
  }
}

// Run the example
main();
