/**
 * Helper functions for working with different runtimes
 */

/**
 * Load a text file at the given path
 * @param path
 * @returns text of file
 */
export async function loadFromFile(path: string): Promise<string> {
  // Deno
  if (globalThis.Deno) {
    return Deno.readTextFile(path);
  }

  // Bun
  if (globalThis.Bun) {
    return Bun.file(path).text();
  }

  // Node.js
  if (typeof process !== "undefined" && process.versions?.node) {
    const fs = await import("fs/promises");
    return fs.readFile(path, "utf-8");
  }

  throw new Error(`Unable to determine method to load file "${path}"`);
}

/**
 * Gets the value of an environment variable
 */
export function getEnvVar(name: string): string | undefined {
  // Deno
  if (globalThis.Deno) {
    return Deno.env.get(name);
  }

  // Bun
  if (globalThis.Bun) {
    return Bun.env[name];
  }

  // Node.js
  if (typeof process !== "undefined" && process.versions?.node) {
    return process.env[name];
  }

  return undefined;
}
