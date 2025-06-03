// @ts-ignore - need to build before this will exist
import { decryptSops, sshKeyToAge } from "../../../dist/index.js";
// @ts-ignore
import {
  assertEquals,
  assertMatch,
  assertExists,
  // @ts-ignore
} from "https://deno.land/std/assert/mod.ts";

// See ../../key.txt
const AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1QXRVEJH9S4NQU0FPD6V79ESZQ8S6PXH3L8V40EVPTHFH6KNKD4DQ7SKC4P";

Deno.test("deno module", async (t) => {
  const original = JSON.parse(
    await Deno.readTextFile("tests/data/secret.json"),
  );

  await t.step("should decrypt a file path with a given fileType", async () => {
    const decrypted = await decryptSops({
      path: "tests/data/secret.enc.json",
      fileType: "json",
      secretKey: AGE_SECRET_KEY,
    });

    assertEquals(decrypted, original);
  });

  await t.step("should decrypt a file path and infer type", async () => {
    const decrypted = await decryptSops({
      path: "tests/data/secret.enc.json",
      secretKey: AGE_SECRET_KEY,
    });

    assertEquals(decrypted, original);
  });

  await t.step("should convert RSA SSH key to age", async () => {
    const rsaPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
    MIICWgIBAAKBgGE7yz6kLzX/E485sihL1NUYYII9aRXvWIZAc+FhiPb+SeuqvA6O
    xu7ZL42BU8K926732IGGsFO+DS81MxWIjUw+68y6PzRo/yszigiYlXkHcSz5mFev
    gU3hQUbe614A8fkxFRjnbmhik9vaFn7eF4MkoYTVRG4q08GOnWgsR19tAgMBAAEC
    gYBb5ZtuFNbZ/b6Ku0j6dNEupd9wuIG9TX0pRXlAJmLArg1HQxKB38d8rqAW6Yg0
    oiQi9fQWVyoHu7PSTkF9tJV1tCs6mJGI+UuQdnGP02b6YiARFjtECJWEjql6GEt+
    wzxYVCOjA63DF5biO6MuYT7Si+WYabaEc16nwLfHO3EGgQJBAKCmnDIVmUm0o9MX
    FuTfYwKhfTwTkjSaWswzs4AZJKSXsV0lSXzcwinCcvd799Ycg6MtXXH9LiB+BSKj
    SGmO9AkCQQCa8YaMpGZ0qSsA4osMzs+Jq3wAdK0g/nhUmBhhbTuycGs82YuBUF53
    iGE4aoKEIbvUFKm63rVk5s8fSVRm8xFFAkBnr2C8Sohms7nQceSKz0qd1hB4B8Gj
    RcQ4a1383T1zJZyJm5k0h16hiSieZlpszHaBiLP48AknW26BDpWb23HRAkBGiLCh
    ka16ahBDhN2b5QGhQElgw7yUioMor1xZ7aoBXx/SQY46PeXjMFhhoErt75VbxFRH
    115oIpIjQfSEMR6pAkAYuV+W0vbd4w3kx0hNF0xEnUy9Agsmpb387+mR66RZr4z8
    eiNZoolFXO03noUQfi+OMgSqb5IqHroT+O77a2rh
    -----END RSA PRIVATE KEY-----`;

    const ageKey = await sshKeyToAge(rsaPrivateKey);
    assertExists(ageKey);
    assertMatch(ageKey, /^AGE-SECRET-KEY-1[A-Z0-9]+$/);
  });

  await t.step("should convert ED25519 SSH key to age", async () => {
    const ed25519PrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACAaOBlHKXxlsDKVAzkqYGrXufSF6APO0W51VxfOVdK5lQAAAJDz1Ohe89To
    XgAAAAtzc2gtZWQyNTUxOQAAACAaOBlHKXxlsDKVAzkqYGrXufSF6APO0W51VxfOVdK5lQ
    AAAEBJLLk4EIlQidqRSemrWXaBwaAeSdm7bsCzMhF689tpvRo4GUcpfGWwMpUDOSpgate5
    9IXoA87RbnVXF85V0rmVAAAABm5vbmFtZQECAwQFBgc=
    -----END OPENSSH PRIVATE KEY-----`;
    const expectedAgeKey =
      "AGE-SECRET-KEY-1K4D6SYCRQLZQD868WJ7CC3C2ZKUJ9HMLH73ETJW6MFDF24YCSC6QGMZ4JY";
    const actualAgeKey = await sshKeyToAge(ed25519PrivateKey);
    assertExists(actualAgeKey);
    assertEquals(actualAgeKey, expectedAgeKey);
  });
});
