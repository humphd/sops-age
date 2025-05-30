import {
  isSopsInput,
  loadSopsFile,
  parseSops,
  type SOPS,
  type SopsFileType,
  type SopsInput,
} from "./sops-file.js";
import { decrypt, type DecryptOptions } from "./decrypt.js";

export { SopsInput, SopsFileType };

/**
 * Options for decrypting SOPS data, extending base decrypt options with an optional file type.
 */
export interface DecryptSopsOptions extends DecryptOptions {
  /**
   * The type of SOPS file being decrypted ('env', 'json', or 'yaml').
   * If not provided, the type will be auto-detected.
   */
  fileType?: SopsFileType;
}

/**
 * Options for decrypting a SOPS file from the local filesystem.
 */
export interface DecryptSopsFileOptions extends DecryptSopsOptions {
  /** Path to the SOPS encrypted file */
  path: string;
}

/**
 * Options for decrypting a SOPS file from a URL.
 */
export interface DecryptSopsUrlOptions extends DecryptSopsOptions {
  /** URL of the SOPS encrypted file */
  url: string | URL;
}

/**
 * Decrypts SOPS-encrypted data from various sources.
 *
 * @param input - The SOPS-encrypted content to decrypt (i.e., contents of SOPS file)
 * @param options - Options for decryption including secret key and file type
 * @returns The decrypted data
 *
 * @example
 * // Decrypt from string content
 * const decrypted = await decryptSops(jsonString, {
 *   secretKey: AGE_SECRET_KEY,
 *   fileType: "json"
 * });
 */
export function decryptSops(
  input: SopsInput,
  options?: DecryptSopsOptions,
): Promise<any>;

/**
 * Decrypts a SOPS-encrypted file from the local filesystem.
 *
 * @param options - Options including file path and decryption settings
 * @returns The decrypted data
 *
 * @example
 * // Decrypt from local file
 * const decrypted = await decryptSops({
 *   path: "/secrets/config.enc.json",
 *   secretKey: AGE_SECRET_KEY
 * });
 */
export function decryptSops(options: DecryptSopsFileOptions): Promise<any>;

/**
 * Decrypts a SOPS-encrypted file from a URL.
 *
 * @param options - Options including URL and decryption settings
 * @returns The decrypted data
 *
 * @example
 * // Decrypt from URL
 * const decrypted = await decryptSops({
 *   url: "https://example.com/config.enc.json",
 *   secretKey: AGE_SECRET_KEY
 * });
 */
export function decryptSops(options: DecryptSopsUrlOptions): Promise<any>;

/**
 * Implementation of decryptSops that handles all overloaded cases.
 *
 * @param inputOrOptions - Either the input content or options with path/url
 * @param options - Optional decryption options when using direct input
 * @returns The decrypted data
 * @throws {Error} When invalid options are provided or HTTP fetch fails
 */
export async function decryptSops(
  inputOrOptions: SopsInput | DecryptSopsFileOptions | DecryptSopsUrlOptions,
  options?: DecryptSopsOptions,
): Promise<any> {
  // Case 1. Direct input with options
  if (options && isSopsInput(inputOrOptions)) {
    const sopsData = await parseSops(inputOrOptions, options.fileType);
    return decrypt(sopsData, options);
  }

  // Case 2. Options object with one of `path` or `url`
  if (
    inputOrOptions &&
    typeof inputOrOptions === "object" &&
    ("path" in inputOrOptions || "url" in inputOrOptions)
  ) {
    const opts = inputOrOptions as
      | DecryptSopsFileOptions
      | DecryptSopsUrlOptions;

    // Load or fetch() the SOPS data
    let sopsData: SOPS;
    if ("path" in opts) {
      sopsData = await loadSopsFile(opts.path, opts.fileType);
    } else {
      const response = await fetch(opts.url);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const content = await response.text();
      sopsData = await parseSops(content, opts.fileType);
    }

    const { fileType: _, ...decryptOptions } = opts;
    return decrypt(sopsData, decryptOptions);
  }

  // Case 3. An bare input object with no options (AGE key must be set in the env)
  if (inputOrOptions && isSopsInput(inputOrOptions)) {
    const sopsData = await parseSops(inputOrOptions);
    return decrypt(sopsData, {});
  }

  throw new Error(
    "Invalid options: when no input given, you must specify one of `path` or `url`",
  );
}

/**
 * Useful utilities for finding and converting to age keys
 */
export { findAllAgeKeys } from "./age-key.js";
export { sshKeyToAge, sshKeyFileToAge } from "./ssh-to-age.js";
