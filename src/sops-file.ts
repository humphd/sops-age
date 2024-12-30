import dotenv from "dotenv";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

import { loadFromFile } from "./runtime.js";

export type SopsInput =
  | string
  | File
  | Blob
  | ArrayBufferLike
  | Uint8Array
  | Buffer
  | ReadableStream<Uint8Array>;

export type SopsFileType = "env" | "json" | "yaml";

/**
 * Type guard function to check if a value is a valid SopsInput type
 *
 * @param value - Any value to check
 * @returns true if value is a valid SopsInput type, false otherwise
 */
export function isSopsInput(value: unknown): value is SopsInput {
  if (!value) {
    return false;
  }

  // Check for string
  if (typeof value === "string") {
    return true;
  }

  // Check for object types
  if (typeof value === "object") {
    return (
      value instanceof File ||
      value instanceof Blob ||
      value instanceof ArrayBuffer ||
      value instanceof Uint8Array ||
      value instanceof Buffer ||
      value instanceof ReadableStream
    );
  }

  return false;
}

const AgeRecipientSchema = z.object({
  enc: z.string(),
  recipient: z.string(),
});

const SopsSchema = z
  .object({
    sops: z.object({
      // We only care about age recipients
      age: z.array(AgeRecipientSchema),
      lastmodified: z.string(),
      mac: z.string().optional(),
      unencrypted_suffix: z.string().optional(),
      version: z.string(),
    }),
  })
  .passthrough();

export type SOPS = z.infer<typeof SopsSchema>;

async function inputToString(input: SopsInput): Promise<string> {
  if (typeof input === "string") {
    return input;
  }

  // File, Blob handling
  if (input instanceof File || input instanceof Blob) {
    return await input.text();
  }

  // ArrayBuffer, Uint8Array handling
  if (input instanceof ArrayBuffer || input instanceof Uint8Array) {
    return new TextDecoder().decode(input);
  }

  // Buffer handling (for Node.js)
  if (
    typeof globalThis.Buffer !== "undefined" &&
    globalThis.Buffer.isBuffer(input)
  ) {
    return input.toString("utf-8");
  }

  // ReadableStream handling
  if (input instanceof ReadableStream) {
    const reader = input.getReader();
    const chunks: Uint8Array[] = [];

    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      chunks.push(value);
    }

    const concatenated = new Uint8Array(
      chunks.reduce((acc, chunk) => acc + chunk.length, 0),
    );
    let offset = 0;
    for (const chunk of chunks) {
      concatenated.set(chunk, offset);
      offset += chunk.length;
    }

    return new TextDecoder().decode(concatenated);
  }

  throw new Error(`Unsupported input type: ${typeof input}`);
}

function autoDetectAndParseSops(data: string): SOPS {
  // Try JSON first
  try {
    return parseSopsJson(data);
  } catch {
    // Not JSON, try YAML
    try {
      return parseSopsYaml(data);
    } catch {
      // Try ENV
      try {
        return parseSopsEnv(data);
      } catch {
        throw new Error(
          "Could not auto-detect file type. Please specify: env, json, or yaml",
        );
      }
    }
  }
}

export async function parseSops(input: SopsInput, sopsFileType?: SopsFileType) {
  try {
    const data = await inputToString(input);

    if (sopsFileType) {
      switch (sopsFileType) {
        case "env":
          return parseSopsEnv(data);
        case "json":
          return parseSopsJson(data);
        case "yaml":
          return parseSopsYaml(data);
        default:
          throw new Error(`Unknown SOPS file type: ${String(sopsFileType)}`);
      }
    }

    return autoDetectAndParseSops(data);
  } catch (err) {
    throw new Error(`Failed to load SOPS file: ${(err as Error).message}`, {
      cause: err,
    });
  }
}

export async function loadSopsFile(
  path: string,
  sopsFileType?: SopsFileType,
): Promise<SOPS> {
  try {
    const content = await loadFromFile(path);
    return await parseSops(content, sopsFileType);
  } catch (err) {
    throw new Error(
      `Failed to load SOPS file '${path}': ${(err as Error).message}`,
      {
        cause: err,
      },
    );
  }
}

function parseSopsYaml(yamlString: string) {
  return SopsSchema.parse(parseYaml(yamlString));
}

function parseSopsJson(json: any | string) {
  return SopsSchema.parse(typeof json === "string" ? JSON.parse(json) : json);
}

function rebuildAgeArray(
  sops: Record<string, any>,
): { enc: string; recipient: string }[] {
  return Object.keys(sops)
    .filter((key) => key.startsWith("age__list_"))
    .reduce<{ enc: string; recipient: string }[]>((acc, key) => {
      const match = key.match(/^age__list_(\d+)__(map_enc|map_recipient)$/);
      if (match) {
        const index = parseInt(match[1], 10);
        const type = match[2];
        acc[index] = acc[index] || {};
        acc[index][type === "map_enc" ? "enc" : "recipient"] = sops[key];
      }

      return acc;
    }, [])
    .map(({ enc, recipient }) => ({
      enc: enc.replaceAll("\\n", "\n"),
      recipient,
    }));
}

function constructSopsObject(
  base: Record<string, any>,
  sops: Record<string, any>,
) {
  return SopsSchema.parse({
    ...base,
    sops: {
      age: rebuildAgeArray(sops),
      lastmodified: sops.lastmodified,
      mac: sops.mac,
      unencrypted_suffix: sops.unencrypted_suffix,
      version: sops.version,
    },
  });
}

function parseSopsEnv(envString: string) {
  const parsedEnv = dotenv.parse(envString);
  const sopsKeys = Object.keys(parsedEnv).filter((key) =>
    key.startsWith("sops_"),
  );

  if (sopsKeys.length === 0) {
    throw new Error("Missing sops data in .env");
  }

  // Initialize an object to hold the sops data
  const sops: any = {};
  sopsKeys.forEach((key) => {
    // Remove 'sops_' prefix
    const newKey = key.replace(/^sops_/, "");
    sops[newKey] = parsedEnv[key];
  });

  // Exclude sopsKeys from parsedEnv to create a new object for non-sops pairs
  const nonSopsEnv = Object.keys(parsedEnv).reduce<Record<string, string>>(
    (acc, key) => {
      if (!sopsKeys.includes(key)) {
        acc[key] = parsedEnv[key];
      }

      return acc;
    },
    {},
  );

  return constructSopsObject(nonSopsEnv, sops);
}
