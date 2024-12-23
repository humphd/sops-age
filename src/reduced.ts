import { createDecipheriv } from "crypto";

const uintDecryptionKey = new Uint8Array([
  0x79, 0x82, 0xc4, 0x88, 0xb1, 0x50, 0x9e, 0x98, 0xd8, 0x92, 0xc5, 0x93, 0x88,
  0xaa, 0x70, 0xbf, 0x6b, 0x0a, 0x87, 0x0f, 0x96, 0x25, 0xbe, 0x45, 0xa3, 0xf6,
  0x98, 0xd9, 0x8a, 0x97, 0xb3, 0x07,
]);

const eValue =
  "ENC[AES256_GCM,data:s0/KBsFec29XLrGbAnLiNA==," +
  "iv:k5oP3kb8tTbZaL3PxbFWN8ToOb8vfv2b1EuPz1LbmYU=," +
  "tag:n1RlTSRKGgoB909D4I3n+A==,type:str]";

const match = eValue.match(
  /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]/,
);

if (match) {
  const [, encValue, ivBase64, tagBase64, dataType] = match;
  console.log(dataType);
  if (!encValue || !ivBase64 || !tagBase64) {
    throw new Error("Invalid ENC format");
  }

  const base64ToUint8Array = (base64) => {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    return bytes;
  };

  const iv = base64ToUint8Array(ivBase64);
  const tag = base64ToUint8Array(tagBase64);
  console.log(`iv length: ${iv.length}, value: ${ivBase64}`);

  const decipher = createDecipheriv("aes-256-gcm", uintDecryptionKey, iv);
  decipher.setAuthTag(tag);
  decipher.setAAD(new Uint8Array());

  const encValueBytes = base64ToUint8Array(encValue);
  const decryptedBytes = decipher.update(encValueBytes);
  const decrypted = new TextDecoder().decode(decryptedBytes);

  console.log(decrypted);
}
