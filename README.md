# sops-age

`sops-age` is a TypeScript library designed to decrypt files encrypted with [SOPS](https://github.com/getsops/sops) (Secrets OPerationS) and the [age](https://github.com/FiloSottile/age) encryption tool. This library provides an easy way to decrypt environment variables, configuration files, and other sensitive data encrypted with SOPS and age in your applications. It works in most JavaScript runtimes (node.js, the browser, Deno, Bun, etc).

## Features

- Supports decryption of SOPS files encrypted with `age`
- Automatic age key discovery, following SOPS conventions
- SSH key support, automatically converting Ed25519 and RSA SSH keys to age format
- Compatible with various file formats including `.env`, `.json`, and `.yaml`
- Supports multiple input types (`string`, `Buffer`, `File`, `Blob`, streams, etc.)
- Works across different JavaScript runtimes (Node.js, Deno, Bun, browser)
- Simple, unified API for decrypting SOPS data from files, URLs, or raw content
- Automatic file type detection with optional manual override

## Installation

Install `sops-age` using your preferred package manager:

```sh
# npm
npm install sops-age

# pnpm
pnpm add sops-age

# yarn
yarn add sops-age
```

## Usage

The library can be used in various JavaScript environments and supports multiple module formats:

### ESM (recommended)

```js
import { decryptSops } from "sops-age";

// Decrypt from a local file (keys auto-discovered from env and file system)
const config = await decryptSops({
  path: "./config.enc.json",
});

// Or with explicit age key
const config = await decryptSops({
  path: "./config.enc.json",
  secretKey: "AGE-SECRET-KEY-1qgdy...",
});
```

### CommonJS

```js
const { decryptSops } = require("sops-age");

// Decrypt from a URL
const config = await decryptSops({
  url: "https://example.com/config.enc.yaml",
  secretKey: "AGE-SECRET-KEY-1qgdy...",
});
```

### Browser (CDN)

```html
<!-- Add to your HTML -->
<script src="https://unpkg.com/sops-age/dist/index.global.js"></script>

<script>
  // The library is available as window.decryptSops
  async function loadConfig() {
    const config = await decryptSops({
      url: "https://example.com/config.enc.json",
      secretKey: "AGE-SECRET-KEY-1qgdy...",
    });
    console.log(config);
  }
</script>
```

### TypeScript

The library includes TypeScript type definitions:

```ts
import { decryptSops, type DecryptSopsOptions } from "sops-age";

const options: DecryptSopsOptions = {
  secretKey: "AGE-SECRET-KEY-1qgdy...",
  fileType: "json",
};

const config = await decryptSops(jsonString, options);
```

### Basic Usage

The library provides a unified `decryptSops` function that can handle various input types:

```js
import { decryptSops } from "sops-age";

// Decrypt from a local file, auto-discovering age keys
const config = await decryptSops({
  path: "./config.enc.json",
});

// Decrypt from a URL with explicit age key
const remoteConfig = await decryptSops({
  url: "https://example.com/config.enc.yaml",
  secretKey: "AGE-SECRET-KEY-1qgdy...",
});

// Decrypt from string content
const content = '{"sops": {...}}';
const data = await decryptSops(content, {
  secretKey: "AGE-SECRET-KEY-1qgdy...",
  fileType: "json",
});
```

### Supported File Types

`sops-age` supports the following file types:

- `.env`
- `.json`
- `.yaml` / `.yml`

The library automatically detects the file type based on file extension or content. You can also manually specify the file type using the `fileType` option.

## Input Types

`sops-age` supports various input types for the SOPS-encrypted content:

- `string`: Raw string content of a SOPS file
- `File`: File object (in browser environments)
- `Blob`: Binary data
- `ArrayBuffer`: Raw binary data
- `Uint8Array`: Typed array of bytes
- `Buffer`: Node.js Buffer (in Node.js environment)
- `ReadableStream<Uint8Array>`: Stream of binary data

## Age Key Discovery

`sops-age` automatically discovers age keys using the same logic as SOPS itself. When no `secretKey` is explicitly provided, the library will search for keys in the following order:

### 1. SSH Keys (Converted to Age Format)

The library can automatically convert SSH private keys to age format:

- **Environment variable**: `SOPS_AGE_SSH_PRIVATE_KEY_FILE` - path to SSH private key
- **Default locations**: `~/.ssh/id_ed25519` and `~/.ssh/id_rsa` (in that order)
- **Supported types**: Ed25519 and RSA keys

```js
// Set environment variable to use specific SSH key
process.env.SOPS_AGE_SSH_PRIVATE_KEY_FILE = "/path/to/my/ssh/key";

// Keys will be auto-discovered and converted
const config = await decryptSops({ path: "./config.enc.json" });
```

### 2. Age Keys from Environment Variables

- **`SOPS_AGE_KEY`**: Direct age private key
- **`SOPS_AGE_KEY_FILE`**: Path to file containing age keys
- **`SOPS_AGE_KEY_CMD`**: Command that outputs age keys

```js
// Direct key
process.env.SOPS_AGE_KEY = "AGE-SECRET-KEY-1qgdy...";

// Key file
process.env.SOPS_AGE_KEY_FILE = "/path/to/keys.txt";

// Command that outputs keys
process.env.SOPS_AGE_KEY_CMD = "my-key-manager get-age-key";
```

### 3. Default Config File

The library checks for age keys in the default SOPS config directory:

- **Linux/Unix**: `~/.config/sops/age/keys.txt` (or `$XDG_CONFIG_HOME/sops/age/keys.txt`)
- **macOS**: `~/Library/Application Support/sops/age/keys.txt` (or `$XDG_CONFIG_HOME/sops/age/keys.txt` if set)
- **Windows**: `%APPDATA%\sops\age\keys.txt`

Example `keys.txt` file:

```text
# Created: 2024-01-15T10:30:00Z
# Public key: age1je6kjhzuhdjy3fqptpttxjh5k8q46vygzlgtpuq3030c947pc5tqz9dqvr
AGE-SECRET-KEY-1QGDY7NWZDM5HG2QMSKQHQZPQF2QJLTQHQZPQF2QJLTQHQZPQF2QJLTQHQZ

# Another key
AGE-SECRET-KEY-1ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOP
```

## Key Discovery Priority

When no explicit `secretKey` is provided, keys are discovered in this order:

1. **SSH Keys**: `SOPS_AGE_SSH_PRIVATE_KEY_FILE` → `~/.ssh/id_ed25519` → `~/.ssh/id_rsa`
2. **Age Keys**: `SOPS_AGE_KEY` → `SOPS_AGE_KEY_FILE` → `SOPS_AGE_KEY_CMD`
3. **Default Config**: Platform-specific `sops/age/keys.txt` file

The library will try all discovered keys until one successfully decrypts the file.

## Age Key Utilities

The library includes utilities for discovering age keys and converting SSH keys to age format:

```js
import { sshKeyToAge, sshKeyFileToAge, findAllAgeKeys } from "sops-age";

// Convert SSH key content to age format
const sshKeyContent = "-----BEGIN OPENSSH PRIVATE KEY-----\n...";
const ageKey = sshKeyToAge(sshKeyContent);

// Convert SSH key file to age format
const ageKey = await sshKeyFileToAge("/path/to/ssh/key");

// Discover all available age keys
const allKeys = await findAllAgeKeys();
console.log("Found keys:", allKeys);
```

## API Reference

### `decryptSops(input, options?)`

Decrypts SOPS-encrypted content directly from a string, Buffer, or other supported input types.

```js
// With auto-discovered keys
const decrypted = await decryptSops(jsonString, {
  fileType: "json",
});

// With explicit key
const decrypted = await decryptSops(jsonString, {
  secretKey: "AGE-SECRET-KEY-1qgdy...",
  fileType: "json",
});
```

### `decryptSops({ path: "...", ... })`

Decrypts a SOPS-encrypted file from the local filesystem.

```js
const decrypted = await decryptSops({
  path: "/path/to/config.enc.json",
  // secretKey optional - will auto-discover
});
```

### `decryptSops({ url: "https://...", ... })`

Decrypts a SOPS-encrypted file from a URL.

```js
const decrypted = await decryptSops({
  url: "https://example.com/config.enc.json",
  secretKey: "AGE-SECRET-KEY-1qgdy...", // or auto-discover
});
```

### `decryptSops(sopsObject, options?)`

Decrypts SOPS-encrypted content directly from a pre-parsed SOPS object.

```js
const sopsObject = {
  secret:
    "ENC[AES256_GCM,data:trrpgezXug4Dq9T/inwkMA==,iv:glPwxoY2UuHO91vlJRaqYtFkPY1VsWvkJtfkEKZJdns=,tag:v7DbOYl7C5gdQRdW6BVoLw==,type:str]",
  sops: {
    // ... SOPS metadata
  },
};

// Auto-discovers keys from environment/config
const decrypted = await decryptSops(sopsObject);
```

### `DecryptSopsOptions`

The `decryptSops` function accepts the following options:

- `secretKey`: The age secret key for decryption (optional - will auto-discover if not provided)
- `fileType`: Optional file type ('env', 'json', or 'yaml'). Auto-detected if not specified
- `keyPath`: Optional path to decrypt only a specific value
- `path`: Path to local SOPS file (when using file-based decryption)
- `url`: URL of SOPS file (when using URL-based decryption)

### Utility Functions

#### `findAllAgeKeys()`

Discovers all available age keys (including converted SSH keys) using SOPS logic:

```js
import { findAllAgeKeys } from "sops-age";

const keys = await findAllAgeKeys();
console.log("Available age keys:", keys);
```

#### `sshKeyToAge(keyContent, filePath)`

Converts SSH private key content to age format:

```js
import { sshKeyToAge } from "sops-age";

const sshKey = "-----BEGIN OPENSSH PRIVATE KEY-----\n...";
const ageKey = sshKeyToAge(sshKey, "id_ed25519");
// Returns: "AGE-SECRET-KEY-1..." or null for unsupported keys
```

#### `sshKeyFileToAge(filePath)`

Converts SSH private key file to age format:

```js
import { sshKeyFileToAge } from "sops-age";

const ageKey = await sshKeyFileToAge("~/.ssh/id_ed25519");
// Returns: "AGE-SECRET-KEY-1..." or null
```

## License

`sops-age` is released under the MIT License. See the [LICENSE](./LICENSE.md) file for more details.
