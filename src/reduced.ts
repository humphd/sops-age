import { createDecipheriv } from "crypto";

const uintDecryptionKey = new Uint8Array([
  0x79, 0x82, 0xc4, 0x88, 0xb1, 0x50, 0x9e, 0x98, 0xd8, 0x92, 0xc5, 0x93, 0x88,
  0xaa, 0x70, 0xbf, 0x6b, 0x0a, 0x87, 0x0f, 0x96, 0x25, 0xbe, 0x45, 0xa3, 0xf6,
  0x98, 0xd9, 0x8a, 0x97, 0xb3, 0x07,
]);
const eValue =
  "ENC[AES256_GCM,data:s0/KBsFec29XLrGbAnLiNA==,iv:k5oP3kb8tTbZaL3PxbFWN8ToOb8vfv2b1EuPz1LbmYU=,tag:n1RlTSRKGgoB909D4I3n+A==,type:str]";
const decryptionKey = Buffer.from(uintDecryptionKey);
const match = eValue.match(
  /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]/,
);
if (match) {
  const [, encValue, ivBase64, tagBase64, dataType] = match;
  console.log(dataType);
  if (!encValue || !ivBase64 || !tagBase64) {
    throw new Error("Invalid ENC format");
  }

  const iv = Buffer.from(ivBase64, "base64");
  const tag = Buffer.from(tagBase64, "base64");
  console.log(`iv length: ${iv.length}, value: ${iv.toString("base64")}`);
  const decipher = createDecipheriv("aes-256-gcm", decryptionKey, iv);
  decipher.setAuthTag(tag);
  decipher.setAAD(Buffer.from(""));
  const decrypted = decipher.update(encValue, "base64", "utf8");
  console.log(decrypted);
}
