// TODO: sort out the various TypeScript/ESLint rules I've disabled...

/* eslint-disable eslint-comments/disable-enable-pair */
/* eslint-disable eslint-comments/no-duplicate-disable */
/* eslint-disable eslint-comments/disable-enable-pair */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable eslint-comments/disable-enable-pair */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import dotenv from "dotenv";
import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

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

export async function loadSopsFile(
  path: string,
  sopsFileType?: "env" | "json" | "yaml",
) {
  const data = await readFile(path, "utf-8");

  // Parse the data using the given explicit type, if present.
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

  // Otherwise, infer type from extension, if possible
  const ext = extname(path);
  switch (ext) {
    case ".env":
      return parseSopsEnv(data);
    case ".json":
      return parseSopsJson(data);
    case ".yaml":
    case ".yml":
      return parseSopsYaml(data);
    default:
      throw new Error(
        `Unable to pick SOPS parser for extension ${ext}. Use: .env, .json, .yaml`,
      );
  }
}

export function parseSopsYaml(yamlString: string) {
  return SopsSchema.parse(parseYaml(yamlString));
}

// eslint-disable-next-line @typescript-eslint/no-redundant-type-constituents
export function parseSopsJson(json: any | string) {
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
        // eslint-disable-next-line logical-assignment-operators
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

export function parseSopsEnv(envString: string) {
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

  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  return constructSopsObject(nonSopsEnv, sops);
}
