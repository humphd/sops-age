# sops-age

`sops-age` is a Node.js library designed to decrypt files encrypted with [SOPS](https://github.com/getsops/sops) (Secrets OPerationS) and the [age](https://github.com/FiloSottile/age) encryption tool. This library provides an easy way to decrypt environment variables, configuration files, and other sensitive data encrypted with SOPS and age in your Node.js applications.

## Features

- Supports decryption of SOPS files encrypted with `age`.
- Compatible with various file formats including `.env`, `.json`, and `.yaml`.
- Provides utility functions for loading and decrypting different types of SOPS files or strings.
- Allows decrypted all or part of a SOPS encrypted data.

## Installation

To install `sops-age`, run the following command in your project directory:

```sh
npm install sops-age
```

## Usage

### Decrypting a SOPS File

To decrypt a SOPS file, you first need to load the encrypted file and then decrypt it (or parts of it) using a [secret age key](https://github.com/FiloSottile/age?tab=readme-ov-file#usage):

```js
import { decrypt, loadSopsFile } from "sops-age";

async function decryptSopsFile(filePath, secretKey) {
  try {
    // Load the SOPS file (auto-detects file types env, json, yaml from extension)
    const sopsData = await loadSopsFile(filePath);

    // Decrypt the data using the secret key
    const decryptedData = await decrypt(sopsData, { secretKey });

    console.log("Decrypted Data:", decryptedData);
  } catch (error) {
    console.error("Error decrypting SOPS file:", error);
  }
}

const filePath = "./config.enc.yaml";
const secretKey = "YOUR_SECRET_AGE_KEY_HERE";
decryptSopsFile(filePath, secretKey);
```

### Supported File Types

`sops-age` supports the following file types:

- `.env`
- `.json`
- `.yaml` / `.yml`

The library automatically detects the file type based on the file extension. You can also manually specify the file type when loading a SOPS file.

## API Reference

### `loadSopsFile(path, [sopsFileType])`

Loads a SOPS file from the specified path. The `sopsFileType` parameter is optional and can be used to manually specify the file type (`env`, `json`, `yaml`) when it can't be inferred from the file extension.

### `decrypt(sops, { secretKey: "AGE-key...", [keyPath] })`

Decrypts the data from a loaded SOPS object using the provided secret key. If no `secretKey` is provided in the `options`, the `SOPS_AGE_KEY` will be used instead.

If `keyPath` is specified, only the value at the given path is decrypted and returned; otherwise, all decrypted data is returned.

```js
const sopsData = await loadSopsFile(filePath);

// Decrypt only the DB_URI value secret key
const DB_URI = await decrypt(sopsData, { secretKey, keyPath: "DB_URI" });
```

### Parsing Functions

- `parseSopsEnv(envString)`
- `parseSopsJson(json)`
- `parseSopsYaml(yamlString)`

These functions parse the strings of the specified type into a SOPS object that can be decrypted. Use this if you aren't working with files (e.g., SOPS data in a database).

```js
// Assuming `env` contains a string in the form on an ENV file
const sopsData = parseSopsEnv(env);

const decryptedEnv = await decrypt(sopsData, { secretKey });
```

## License

`sops-age` is released under the MIT License. See the [LICENSE](./LICENSE.md) file for more details.
