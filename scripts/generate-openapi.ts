import { OpenApiGeneratorV3 } from "@asteasolutions/zod-to-openapi";
import { registry } from "../src/schemas.js";
import { writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, "..");

const generator = new OpenApiGeneratorV3(registry.definitions);

const document = generator.generateDocument({
  openapi: "3.0.0",
  info: {
    title: "Key Service",
    description:
      "Manages API keys and BYOK (Bring Your Own Key) credentials for organizations. Handles key generation, validation, encryption, and secure storage.",
    version: "1.0.0",
  },
  servers: [
    {
      url: process.env.SERVICE_URL || "http://localhost:3001",
    },
  ],
});

const outputFile = join(projectRoot, "openapi.json");
writeFileSync(outputFile, JSON.stringify(document, null, 2));
console.log("openapi.json generated");
