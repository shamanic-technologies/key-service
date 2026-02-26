import { beforeAll, afterAll } from "vitest";

process.env.KEY_SERVICE_DATABASE_URL = process.env.KEY_SERVICE_DATABASE_URL || "postgresql://test:test@localhost/test";
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

beforeAll(() => console.log("Test suite starting..."));
afterAll(() => console.log("Test suite complete."));
