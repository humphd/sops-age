# sops-age

`sops-age` is a TypeScript library designed to decrypt files encrypted with [SOPS](https://github.com/getsops/sops) (Secrets OPerationS) and the [age](https://github.com/FiloSottile/age) encryption tool. This library provides an easy way to decrypt environment variables, configuration files, and other sensitive data encrypted with SOPS and age in your applications. It works in most JavaScript runtimes (node.js, the browser, Deno, Bun, etc).

## Features

- Supports decryption of SOPS files encrypted with `age`
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

// Decrypt from a local file
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

// Decrypt from a local file
const config = await decryptSops({
  path: "./config.enc.json",
  secretKey: "AGE-SECRET-KEY-1qgdy...",
});

// Decrypt from a URL
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

## API Reference

### `decryptSops(input, options?)`

Decrypts SOPS-encrypted content directly from a string, Buffer, or other supported input types.

```js
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
  secretKey: "AGE-SECRET-KEY-1qgdy...",
});
```

### `decryptSops({ url: "https://...", ... })`

Decrypts a SOPS-encrypted file from a URL.

```js
const decrypted = await decryptSops({
  url: "https://example.com/config.enc.json",
  secretKey: "AGE-SECRET-KEY-1qgdy...",
});
```

### Options

The `decryptSops` function accepts the following options:

- `secretKey`: The age secret key for decryption (required unless `SOPS_AGE_KEY` env var is set)
- `fileType`: Optional file type ('env', 'json', or 'yaml'). Auto-detected if not specified
- `keyPath`: Optional path to decrypt only a specific value
- `path`: Path to local SOPS file (when using file-based decryption)
- `url`: URL of SOPS file (when using URL-based decryption)

## Environment Variables

- `SOPS_AGE_KEY`: If set, this environment variable will be used as the default secret key when none is provided in the options.

## License

`sops-age` is released under the MIT License. See the [LICENSE](./LICENSE.md) file for more details.
