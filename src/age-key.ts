import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { platform, homedir } from "node:os";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { X25519_PRIVATE_KEY_HRP } from "./age.js";
import { sshKeyFileToAge } from "./ssh-to-age.js";

const execAsync = promisify(exec);
const SOPS_AGE_KEY_USER_CONFIG_PATH = "sops/age/keys.txt";

/**
 * Parses content (e.g., from keys.txt or env var) for age keys (X25519 Bech32 key strings).
 * Returns an array of valid X25519 Bech32 private key strings.
 */
function parseX25519KeysFromString(
  content: string,
  sourceName: string,
): string[] {
  const keyStrings: string[] = [];
  const lines = content.split("\n");
  for (const line of lines) {
    const trimmedLine = line.trim();
    if (trimmedLine === "" || trimmedLine.startsWith("#")) {
      continue;
    }
    if (
      trimmedLine.toUpperCase().startsWith(X25519_PRIVATE_KEY_HRP.toUpperCase())
    ) {
      keyStrings.push(trimmedLine);
    } else if (trimmedLine.startsWith("AGE-PLUGIN-")) {
      console.warn(
        `AGE plugin keys are not supported: ${trimmedLine.substring(0, 30)}... from ${sourceName}`,
      );
    } else if (trimmedLine.length > 0) {
      console.warn(
        `Skipping unrecognized line in ${sourceName}: ${trimmedLine.substring(
          0,
          30,
        )}...`,
      );
    }
  }
  return keyStrings;
}

// getUserConfigDir function (remains the same as your original)
async function getUserConfigDir(): Promise<string> {
  if (platform() === "darwin") {
    const xdgConfigHome = process.env.XDG_CONFIG_HOME;
    if (xdgConfigHome && xdgConfigHome.trim() !== "") return xdgConfigHome;
  }
  switch (platform()) {
    case "win32":
      const appData = process.env.APPDATA;
      if (!appData) throw new Error("APPDATA env var not set");
      return appData;
    case "darwin":
      return join(homedir(), "Library", "Application Support");
    default:
      const xdgConfigHome = process.env.XDG_CONFIG_HOME;
      if (xdgConfigHome && xdgConfigHome.trim() !== "") return xdgConfigHome;
      return join(homedir(), ".config");
  }
}

/**
 * Finds all age secret keys (X25519 strings) according to SOPS rules, see:
 * https://github.com/getsops/sops?tab=readme-ov-file#encrypting-using-age
 *
 * - Converts SSH keys (Ed25519, RSA) to X25519 format using either
 * SOPS_AGE_SSH_PRIVATE_KEY_FILE or .ssh/id_ed25519, .ssh/id_rsa.
 *
 * - Uses SOPS_AGE_KEY or SOPS_AGE_KEY_FILE or SOPS_AGE_KEY_CMD to get an
 * age key or keys.
 *
 * - Looks in the sops/age/keys.txt config dir for age keys.
 */
export async function findAllAgeKeys(): Promise<string[]> {
  // Track if any potential key source is identified
  let foundKeySource = false;

  // 1. SSH Keys (converted to X25519 Bech32 strings)
  const convertedSshKeys: string[] = [];
  const sshKeyFilePathEnv = process.env.SOPS_AGE_SSH_PRIVATE_KEY_FILE;
  if (sshKeyFilePathEnv) {
    try {
      const x25519KeyStr = await sshKeyFileToAge(sshKeyFilePathEnv);
      if (x25519KeyStr) {
        convertedSshKeys.push(x25519KeyStr);
        foundKeySource = true;
      }
    } catch (error) {
      throw new Error(
        `Error processing SOPS_AGE_SSH_PRIVATE_KEY_FILE (${sshKeyFilePathEnv}): ${
          (error as Error).message
        }`,
        { cause: error },
      );
    }
  } else {
    const userHomeDir = homedir();
    if (userHomeDir) {
      const defaultSshPaths = [
        join(userHomeDir, ".ssh", "id_ed25519"),
        join(userHomeDir, ".ssh", "id_rsa"),
      ];
      for (const sshPath of defaultSshPaths) {
        // NOTE: if an SSH key was already loaded (from env var), SOPS doesn't
        // bother looking for default SSH keys.
        if (foundKeySource && convertedSshKeys.length > 0) {
          break;
        }

        try {
          const x25519KeyStr = await sshKeyFileToAge(sshPath);
          if (x25519KeyStr) {
            convertedSshKeys.push(x25519KeyStr);
            foundKeySource = true;
            // SOPS uses the first default SSH key found
            break;
          }
        } catch (error: any) {
          if (error.code === "ENOENT") {
            // Ignore default ssh keys not being found
            continue;
          }

          throw new Error(
            `Error processing default SSH key file (${sshPath}): ${
              (error as Error).message
            }`,
            { cause: error },
          );
        }
      }
    }
  }

  const sopsAgeKeyContents: { sourceName: string; content: string }[] = [];

  // 2. SOPS_AGE_KEY environment variable
  const ageKeyEnv = process.env.SOPS_AGE_KEY;
  if (ageKeyEnv) {
    sopsAgeKeyContents.push({
      sourceName: "SOPS_AGE_KEY (environment variable)",
      content: ageKeyEnv,
    });
    foundKeySource = true;
  }

  // 3. SOPS_AGE_KEY_FILE environment variable
  const ageKeyFileEnv = process.env.SOPS_AGE_KEY_FILE;
  if (ageKeyFileEnv) {
    try {
      const content = await readFile(ageKeyFileEnv, "utf-8");
      sopsAgeKeyContents.push({
        sourceName: `SOPS_AGE_KEY_FILE (${ageKeyFileEnv})`,
        content,
      });
      foundKeySource = true;
    } catch (error) {
      throw new Error(
        `Failed to read SOPS_AGE_KEY_FILE (${ageKeyFileEnv}): ${
          (error as Error).message
        }`,
        { cause: error },
      );
    }
  }

  // 4. SOPS_AGE_KEY_CMD environment variable
  const ageKeyCmdEnv = process.env.SOPS_AGE_KEY_CMD;
  if (ageKeyCmdEnv) {
    try {
      const { stdout } = await execAsync(ageKeyCmdEnv);
      sopsAgeKeyContents.push({
        sourceName: `SOPS_AGE_KEY_CMD output (${ageKeyCmdEnv})`,
        content: stdout,
      });
      foundKeySource = true;
    } catch (error) {
      throw new Error(
        `Failed to execute SOPS_AGE_KEY_CMD (${ageKeyCmdEnv}): ${
          (error as Error).message
        }`,
        { cause: error },
      );
    }
  }

  // 5. Default user config file (sops/age/keys.txt)
  let userConfigDirPath: string | null = null;
  try {
    userConfigDirPath = await getUserConfigDir();
  } catch (error) {
    if (!foundKeySource && convertedSshKeys.length === 0) {
      throw new Error(
        `User config directory not determinable, and no other key sources found: ${
          (error as Error).message
        }`,
      );
    }
  }

  if (userConfigDirPath) {
    const sopsKeysFilePath = join(
      userConfigDirPath,
      SOPS_AGE_KEY_USER_CONFIG_PATH,
    );
    try {
      const content = await readFile(sopsKeysFilePath, "utf-8");
      sopsAgeKeyContents.push({
        sourceName: `Default keys.txt (${sopsKeysFilePath})`,
        content,
      });
      foundKeySource = true;
    } catch (error: any) {
      if (error.code === "ENOENT") {
        if (
          !foundKeySource &&
          convertedSshKeys.length === 0 && // No SSH keys found
          sopsAgeKeyContents.length === 0 // No env/cmd keys found
        ) {
          throw new Error(
            `Default sops keys file (${sopsKeysFilePath}) not found, and no other key sources specified.`,
            { cause: error },
          );
        }
      } else {
        throw new Error(
          `Failed to read default sops keys file (${sopsKeysFilePath}): ${error.message}`,
          { cause: error },
        );
      }
    }
  }

  // Parse X25519 key strings from the collected sops age key contents
  const sopsKeys = sopsAgeKeyContents
    .map((sopsAgeKeyContent) => {
      const keysFromContent = parseX25519KeysFromString(
        sopsAgeKeyContent.content,
        sopsAgeKeyContent.sourceName,
      );
      return keysFromContent;
    })
    .flat();

  return [...new Set([...sopsKeys, ...convertedSshKeys])];
}
