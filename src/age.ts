import * as age from "age-encryption";

export async function getPublicAgeKey(privateAgeKey: string) {
  return age.identityToRecipient(privateAgeKey);
}

export async function decryptAgeEncryptionKey(
  encryptedKey: string,
  secretKey: string,
): Promise<Uint8Array> {
  const decoded = age.armor.decode(encryptedKey);

  const decrypter = new age.Decrypter();
  decrypter.addIdentity(secretKey);

  return decrypter.decrypt(decoded, "uint8array");
}
