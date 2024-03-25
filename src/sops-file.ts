import ini from "ini";
import { readFile } from "node:fs/promises";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

const AgeRecipientSchema = z.object({
  enc: z.string(),
  recipient: z.string(),
});

const SopsSchema = z
  .object({
    sops: z.object({
      // We only care about age recipients for now
      age: z.array(AgeRecipientSchema),
      lastmodified: z.string(),
      mac: z.string().optional(),
      unencrypted_suffix: z.string().optional(),
      version: z.string(),
    }),
  })
  .passthrough();

export type SOPS = z.infer<typeof SopsSchema>;

export async function loadYamlSopsFile(path: string) {
  const data = await readFile(path, "utf-8");
  return parseSopsYaml(data);
}

export function parseSopsYaml(yamlString: string) {
  return SopsSchema.parse(parseYaml(yamlString));
}

export async function loadJsonSopsFile(path: string) {
  const data = await readFile(path, "utf-8");
  return parseSopsJson(JSON.parse(data));
}

export function parseSopsJson(json: any | string) {
  return SopsSchema.parse(typeof json === "string" ? JSON.parse(json) : json);
}

export async function loadIniSopsFile(path: string) {
  const data = await readFile(path, "utf-8");
  const parsedIni = ini.parse(data);
  // Adapt `parsedIni` to fit the SOPS structure as needed
  // This is a placeholder and needs to be adjusted based on the actual INI structure
  const adaptedForSops = {
    sops: {
      // Example adaptation, replace with actual logic
      age: [],
      lastmodified: "",
      version: "",
      // Populate with actual data from `parsedIni`
    },
  };
  return SopsSchema.parse(adaptedForSops);
}

export async function loadEnvSopsFile(path: string) {
  const data = await readFile(path, "utf-8");
  const lines = data.split("\n");
  const parsedEnv = lines.reduce<Record<string, string>>((acc, line) => {
    const [key, value] = line.split("=");
    if (key && value) {
      acc[key.trim()] = value.trim();
    }

    return acc;
  }, {});
  // Adapt `parsedEnv` to fit the SOPS structure as needed
  // This is a placeholder and needs to be adjusted based on the actual .env structure
  const adaptedForSops = {
    sops: {
      // Example adaptation, replace with actual logic
      age: [],
      lastmodified: "",
      version: "",
      // Populate with actual data from `parsedEnv`
    },
  };
  return SopsSchema.parse(adaptedForSops);
}
