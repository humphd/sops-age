import age from "age-encryption";
import { createDecipheriv } from "crypto";
import get from "lodash-es/get.js";

import type { SOPS } from "./sops-file.js";

export async function getPublicAgeKey(privateAgeKey: string) {
  const { identityToRecipient } = await age();
  return identityToRecipient(privateAgeKey);
}

async function decryptAgeEncryptionKey(
  encryptedKey: string,
  secretKey: string,
) {
  const { Decrypter } = await age();

  const decrypter = new Decrypter();
  decrypter.addIdentity(secretKey);

  const regex =
    /-----BEGIN AGE ENCRYPTED FILE-----\s*([\s\S]*?)\s*-----END AGE ENCRYPTED FILE-----/;
  const matches = encryptedKey.match(regex);
  if (!matches?.[1]) {
    throw new Error("unable to extract age encryption key");
  }

  const base64String = matches[1].trim();
  const encrypted = Buffer.from(base64String, "base64");
  const decryptionKey = decrypter.decrypt(encrypted, "uint8array");

  return Buffer.from(decryptionKey);
}

export async function getSopsEncryptionKeyForRecipient(
  sops: SOPS,
  secretKey: string,
) {
  const pubKey = await getPublicAgeKey(secretKey);

  const recipient = sops.sops.age.find((config) => config.recipient === pubKey);
  if (!recipient) {
    throw new Error("no matching recipient found in age config");
  }

  return decryptAgeEncryptionKey(recipient.enc, secretKey);
}

function decryptValue(
  value: string,
  key: Buffer,
  aad = "",
): Buffer | boolean | number | string {
  const match = value.match(
    /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]/,
  );
  if (!match) {
    return value;
  }

  const [, encValue, ivBase64, tagBase64, valtype] = match;
  if (!encValue || !ivBase64 || !tagBase64) {
    throw new Error("Invalid ENC format");
  }

  const iv = Buffer.from(ivBase64, "base64");
  const tag = Buffer.from(tagBase64, "base64");

  const decryptor = createDecipheriv("aes-256-gcm", key, iv);
  decryptor.setAuthTag(tag);
  decryptor.setAAD(Buffer.from(aad));

  const decrypted = decryptor.update(encValue, "base64", "utf8");

  switch (valtype) {
    case "bytes":
      return Buffer.from(decrypted, "utf8");
    case "str":
      return decrypted;
    case "int":
      return parseInt(decrypted, 10);
    case "float":
      return parseFloat(decrypted);
    case "bool":
      return decrypted === "true";
    default:
      throw new Error(`Unknown type ${valtype}`);
  }
}

// secretKey is an age X25519 identity
export async function decrypt(sops: SOPS, secretKey: string, keyPath: string) {
  const decryptionKey = await getSopsEncryptionKeyForRecipient(sops, secretKey);
  const value = get(sops, keyPath);
  if (typeof value !== "string") {
    throw new Error(`Unable to get sops value at ${keyPath}`);
  }

  const decrypted = decryptValue(value, decryptionKey);

  // TODO: calculate checksum and confirm...

  return decrypted;
}
