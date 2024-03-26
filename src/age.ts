import age from "age-encryption";

export async function getPublicAgeKey(privateAgeKey: string) {
  const { identityToRecipient } = await age();
  return identityToRecipient(privateAgeKey);
}

export async function decryptAgeEncryptionKey(
  encryptedKey: string,
  secretKey: string,
) {
  const { Decrypter } = await age();

  const decrypter = new Decrypter();
  decrypter.addIdentity(secretKey);

  const regex =
    /-----BEGIN AGE ENCRYPTED FILE-----\r?\n([\s\S]+?)\r?\n-----END AGE ENCRYPTED FILE-----/;
  const matches = encryptedKey.match(regex);
  if (!matches?.[1]) {
    throw new Error("unable to extract age encryption key");
  }

  const base64String = matches[1].trim();
  const encrypted = Buffer.from(base64String, "base64");
  const decryptionKey = decrypter.decrypt(encrypted, "uint8array");

  return Buffer.from(decryptionKey);
}
