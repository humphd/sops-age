import * as age from "age-encryption";

export async function getPublicAgeKey(privateAgeKey: string) {
  return age.identityToRecipient(privateAgeKey);
}

export async function decryptAgeEncryptionKey(
  encryptedKey: string,
  secretKey: string,
): Promise<Uint8Array> {
  const decrypter = new age.Decrypter();
  decrypter.addIdentity(secretKey);

  const regex =
    /-----BEGIN AGE ENCRYPTED FILE-----\r?\n([\s\S]+?)\r?\n-----END AGE ENCRYPTED FILE-----/;
  const matches = encryptedKey.match(regex);
  if (!matches?.[1]) {
    throw new Error("unable to extract age encryption key");
  }

  const base64String = matches[1].trim();
  const encrypted = Uint8Array.from(atob(base64String), (c) => c.charCodeAt(0));
  return decrypter.decrypt(encrypted, "uint8array");
}
