import { z } from "zod";
import {
  OpenAPIRegistry,
  extendZodWithOpenApi,
} from "@asteasolutions/zod-to-openapi";

extendZodWithOpenApi(z);
export const registry = new OpenAPIRegistry();

// ==================== Shared ====================

const ErrorResponseSchema = z
  .object({
    error: z.string(),
  })
  .openapi("ErrorResponse");

// ==================== Health ====================

const HealthResponseSchema = z
  .object({
    status: z.string(),
    timestamp: z.string(),
    service: z.string(),
  })
  .openapi("HealthResponse");

registry.registerPath({
  method: "get",
  path: "/health",
  summary: "Health check",
  responses: {
    200: {
      description: "Service is healthy",
      content: { "application/json": { schema: HealthResponseSchema } },
    },
  },
});

// ==================== Validate ====================

export const ValidateResponseSchema = z
  .object({
    valid: z.literal(true),
    type: z.literal("user"),
    orgId: z.string(),
    userId: z.string(),
    configuredProviders: z.array(z.string()),
  })
  .openapi("ValidateResponse");

const ValidateKeyQuerySchema = z
  .object({
    key: z.string().min(1).openapi({ description: "The API key to validate (distrib.usr_*)", example: "distrib.usr_abc123" }),
  })
  .openapi("ValidateKeyQuery");

const ValidateKeyResponseSchema = z
  .object({
    provider: z.string(),
    key: z.string(),
  })
  .openapi("ValidateKeyResponse");

registry.registerPath({
  method: "get",
  path: "/validate",
  summary: "Validate API key — returns user identity",
  description: "Pass the API key to validate as ?key= query parameter. Authenticated via X-API-Key (service key).",
  security: [{ serviceKeyAuth: [] }],
  request: {
    query: ValidateKeyQuerySchema,
  },
  responses: {
    200: {
      description: "API key is valid",
      content: {
        "application/json": { schema: ValidateResponseSchema },
      },
    },
    400: { description: "Missing key parameter" },
    401: { description: "Unauthorized" },
  },
});

registry.registerPath({
  method: "get",
  path: "/validate/keys/{provider}",
  summary: "Get decrypted org key for a provider",
  description:
    "Pass the user's API key as ?key= query parameter. Requires X-Caller-Service, X-Caller-Method, and X-Caller-Path headers to identify the calling endpoint. These are used to build the provider requirements registry.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({
      provider: z.string(),
    }),
    query: ValidateKeyQuerySchema,
    headers: z.object({
      "x-caller-service": z.string().min(1).openapi({ description: "Name of the calling service", example: "apollo" }),
      "x-caller-method": z.string().min(1).openapi({ description: "HTTP method of the caller's endpoint", example: "POST" }),
      "x-caller-path": z.string().min(1).openapi({ description: "Path of the caller's endpoint", example: "/leads/search" }),
    }),
  },
  responses: {
    200: {
      description: "Decrypted key",
      content: { "application/json": { schema: ValidateKeyResponseSchema } },
    },
    400: { description: "Missing key parameter or required caller headers" },
    401: { description: "Unauthorized" },
    404: { description: "Key not configured" },
  },
});

// ==================== Internal: Shared ====================

const OrgIdQuerySchema = z
  .object({
    orgId: z.string().min(1),
  })
  .openapi("OrgIdQuery");

// ==================== Internal: User Auth Keys ====================

const ListUserAuthKeysQuerySchema = z
  .object({
    orgId: z.string().min(1),
    userId: z.string().optional(),
  })
  .openapi("ListUserAuthKeysQuery");

const UserAuthKeyItemSchema = z
  .object({
    id: z.string().uuid(),
    keyPrefix: z.string(),
    name: z.string().nullable(),
    orgId: z.string(),
    userId: z.string(),
    createdBy: z.string(),
    createdAt: z.coerce.date(),
    lastUsedAt: z.coerce.date().nullable(),
  })
  .openapi("UserAuthKeyItem");

const ListUserAuthKeysResponseSchema = z
  .object({
    keys: z.array(UserAuthKeyItemSchema),
  })
  .openapi("ListUserAuthKeysResponse");

registry.registerPath({
  method: "get",
  path: "/internal/api-keys",
  summary: "List user auth keys for an org",
  security: [{ serviceKeyAuth: [] }],
  request: {
    query: ListUserAuthKeysQuerySchema,
  },
  responses: {
    200: {
      description: "List of user auth keys",
      content: { "application/json": { schema: ListUserAuthKeysResponseSchema } },
    },
    400: { description: "Missing orgId" },
  },
});

export const CreateUserAuthKeyRequestSchema = z
  .object({
    orgId: z.string().min(1),
    userId: z.string().min(1),
    createdBy: z.string().min(1),
    name: z.string().min(1),
  })
  .openapi("CreateUserAuthKeyRequest");

const CreateUserAuthKeyResponseSchema = z
  .object({
    id: z.string().uuid(),
    key: z.string(),
    name: z.string(),
    orgId: z.string(),
    userId: z.string(),
    createdBy: z.string(),
    createdAt: z.coerce.date(),
  })
  .openapi("CreateUserAuthKeyResponse");

registry.registerPath({
  method: "post",
  path: "/internal/api-keys",
  summary: "Create a new user auth key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: { "application/json": { schema: CreateUserAuthKeyRequestSchema } },
    },
  },
  responses: {
    200: {
      description: "User auth key created",
      content: { "application/json": { schema: CreateUserAuthKeyResponseSchema } },
    },
    400: { description: "Invalid request" },
  },
});

export const DeleteUserAuthKeyRequestSchema = z
  .object({
    orgId: z.string().min(1),
  })
  .openapi("DeleteUserAuthKeyRequest");

const MessageResponseSchema = z
  .object({
    message: z.string(),
  })
  .openapi("MessageResponse");

registry.registerPath({
  method: "delete",
  path: "/internal/api-keys/{id}",
  summary: "Delete a user auth key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ id: z.string().uuid() }),
    body: {
      content: { "application/json": { schema: DeleteUserAuthKeyRequestSchema } },
    },
  },
  responses: {
    200: {
      description: "User auth key deleted",
      content: { "application/json": { schema: MessageResponseSchema } },
    },
    400: { description: "Missing orgId" },
    404: { description: "Key not found" },
  },
});

export const SessionKeyRequestSchema = z
  .object({
    orgId: z.string().min(1),
    userId: z.string().min(1),
  })
  .openapi("SessionKeyRequest");

const SessionKeyResponseSchema = z
  .object({
    id: z.string().uuid(),
    key: z.string(),
    keyPrefix: z.string(),
    name: z.string().nullable(),
  })
  .openapi("SessionKeyResponse");

registry.registerPath({
  method: "post",
  path: "/internal/api-keys/session",
  summary: "Get or create a default user auth key for the org+user",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: {
        "application/json": { schema: SessionKeyRequestSchema },
      },
    },
  },
  responses: {
    200: {
      description: "Session key",
      content: { "application/json": { schema: SessionKeyResponseSchema } },
    },
    400: { description: "Missing orgId or userId" },
  },
});

// ==================== Internal: Org Keys ====================

const OrgKeyItemSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    createdAt: z.coerce.date(),
    updatedAt: z.coerce.date(),
  })
  .openapi("OrgKeyItem");

const ListOrgKeysResponseSchema = z
  .object({
    keys: z.array(OrgKeyItemSchema),
  })
  .openapi("ListOrgKeysResponse");

registry.registerPath({
  method: "get",
  path: "/internal/keys",
  summary: "List org keys for an org",
  security: [{ serviceKeyAuth: [] }],
  request: {
    query: OrgIdQuerySchema,
  },
  responses: {
    200: {
      description: "List of org keys",
      content: { "application/json": { schema: ListOrgKeysResponseSchema } },
    },
    400: { description: "Missing orgId" },
  },
});

export const CreateOrgKeyRequestSchema = z
  .object({
    orgId: z.string().min(1),
    provider: z.string().min(1),
    apiKey: z.string().min(1),
  })
  .openapi("CreateOrgKeyRequest");

const CreateOrgKeyResponseSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    message: z.string(),
  })
  .openapi("CreateOrgKeyResponse");

registry.registerPath({
  method: "post",
  path: "/internal/keys",
  summary: "Add or update an org key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: {
        "application/json": { schema: CreateOrgKeyRequestSchema },
      },
    },
  },
  responses: {
    200: {
      description: "Org key saved",
      content: {
        "application/json": { schema: CreateOrgKeyResponseSchema },
      },
    },
    400: { description: "Invalid request" },
  },
});

export const DeleteOrgKeyQuerySchema = z
  .object({
    orgId: z.string().min(1),
  })
  .openapi("DeleteOrgKeyQuery");

const DeleteOrgKeyResponseSchema = z
  .object({
    provider: z.string(),
    message: z.string(),
  })
  .openapi("DeleteOrgKeyResponse");

registry.registerPath({
  method: "delete",
  path: "/internal/keys/{provider}",
  summary: "Delete an org key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({
      provider: z.string(),
    }),
    query: DeleteOrgKeyQuerySchema,
  },
  responses: {
    200: {
      description: "Org key deleted",
      content: {
        "application/json": { schema: DeleteOrgKeyResponseSchema },
      },
    },
    400: { description: "Invalid request" },
  },
});

const DecryptOrgKeyResponseSchema = z
  .object({
    provider: z.string(),
    key: z.string(),
  })
  .openapi("DecryptOrgKeyResponse");

registry.registerPath({
  method: "get",
  path: "/internal/keys/{provider}/decrypt",
  summary: "Get decrypted org key (internal service use)",
  description:
    "Requires X-Caller-Service, X-Caller-Method, and X-Caller-Path headers to identify the calling endpoint. These are used to build the provider requirements registry.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    query: OrgIdQuerySchema,
    headers: z.object({
      "x-caller-service": z.string().min(1).openapi({ description: "Name of the calling service", example: "apollo" }),
      "x-caller-method": z.string().min(1).openapi({ description: "HTTP method of the caller's endpoint", example: "POST" }),
      "x-caller-path": z.string().min(1).openapi({ description: "Path of the caller's endpoint", example: "/leads/search" }),
    }),
  },
  responses: {
    200: {
      description: "Decrypted key",
      content: {
        "application/json": { schema: DecryptOrgKeyResponseSchema },
      },
    },
    400: { description: "Missing orgId or required caller headers" },
    404: { description: "Key not configured" },
  },
});

// ==================== Internal: Platform Keys ====================

export const CreatePlatformKeyRequestSchema = z
  .object({
    provider: z.string().min(1),
    apiKey: z.string().min(1),
  })
  .openapi("CreatePlatformKeyRequest");

const CreatePlatformKeyResponseSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    message: z.string(),
  })
  .openapi("CreatePlatformKeyResponse");

registry.registerPath({
  method: "post",
  path: "/internal/platform-keys",
  summary: "Add or update a platform key",
  description:
    "Upsert a platform-level API key. Platform keys are global — not tied to any org. Typically registered once at deployment.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: {
        "application/json": { schema: CreatePlatformKeyRequestSchema },
      },
    },
  },
  responses: {
    200: {
      description: "Platform key saved",
      content: {
        "application/json": { schema: CreatePlatformKeyResponseSchema },
      },
    },
    400: { description: "Invalid request" },
  },
});

const PlatformKeyItemSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    createdAt: z.coerce.date(),
    updatedAt: z.coerce.date(),
  })
  .openapi("PlatformKeyItem");

const ListPlatformKeysResponseSchema = z
  .object({
    keys: z.array(PlatformKeyItemSchema),
  })
  .openapi("ListPlatformKeysResponse");

registry.registerPath({
  method: "get",
  path: "/internal/platform-keys",
  summary: "List all platform keys",
  security: [{ serviceKeyAuth: [] }],
  responses: {
    200: {
      description: "List of platform keys",
      content: { "application/json": { schema: ListPlatformKeysResponseSchema } },
    },
  },
});

const DecryptPlatformKeyResponseSchema = z
  .object({
    provider: z.string(),
    key: z.string(),
  })
  .openapi("DecryptPlatformKeyResponse");

registry.registerPath({
  method: "get",
  path: "/internal/platform-keys/{provider}/decrypt",
  summary: "Get decrypted platform key (internal service use)",
  description:
    "Returns the decrypted platform-level key for the given provider. No orgId needed — platform keys are global. Requires X-Caller-* headers for provider requirements tracking.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    headers: z.object({
      "x-caller-service": z.string().min(1).openapi({ description: "Name of the calling service", example: "apollo" }),
      "x-caller-method": z.string().min(1).openapi({ description: "HTTP method of the caller's endpoint", example: "POST" }),
      "x-caller-path": z.string().min(1).openapi({ description: "Path of the caller's endpoint", example: "/leads/search" }),
    }),
  },
  responses: {
    200: {
      description: "Decrypted key",
      content: {
        "application/json": { schema: DecryptPlatformKeyResponseSchema },
      },
    },
    400: { description: "Missing required caller headers" },
    404: { description: "Key not configured" },
  },
});

export const DeletePlatformKeyQuerySchema = z
  .object({
    provider: z.string().min(1),
  })
  .openapi("DeletePlatformKeyQuery");

const DeletePlatformKeyResponseSchema = z
  .object({
    provider: z.string(),
    message: z.string(),
  })
  .openapi("DeletePlatformKeyResponse");

registry.registerPath({
  method: "delete",
  path: "/internal/platform-keys/{provider}",
  summary: "Delete a platform key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({
      provider: z.string(),
    }),
  },
  responses: {
    200: {
      description: "Platform key deleted",
      content: {
        "application/json": { schema: DeletePlatformKeyResponseSchema },
      },
    },
  },
});

// ==================== Provider Requirements ====================

const EndpointSchema = z
  .object({
    service: z.string().min(1),
    method: z.string().min(1),
    path: z.string().min(1),
  })
  .openapi("Endpoint");

export const ProviderRequirementsRequestSchema = z
  .object({
    endpoints: z.array(EndpointSchema).min(1),
  })
  .openapi("ProviderRequirementsRequest");

const ProviderRequirementItemSchema = z
  .object({
    service: z.string(),
    method: z.string(),
    path: z.string(),
    provider: z.string(),
  })
  .openapi("ProviderRequirementItem");

const ProviderRequirementsResponseSchema = z
  .object({
    requirements: z.array(ProviderRequirementItemSchema),
    providers: z.array(z.string()),
  })
  .openapi("ProviderRequirementsResponse");

registry.registerPath({
  method: "post",
  path: "/internal/provider-requirements",
  summary: "Query which providers are needed for a set of endpoints",
  description:
    "Given a list of service endpoints (service + method + path), returns which third-party providers each endpoint has been observed requesting. Used by workflow-service to determine which keys are needed before execution.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: {
        "application/json": { schema: ProviderRequirementsRequestSchema },
      },
    },
  },
  responses: {
    200: {
      description: "Provider requirements for the given endpoints",
      content: {
        "application/json": { schema: ProviderRequirementsResponseSchema },
      },
    },
    400: { description: "Invalid request" },
  },
});

// ==================== Security schemes ====================

registry.registerComponent("securitySchemes", "serviceKeyAuth", {
  type: "apiKey",
  in: "header",
  name: "x-api-key",
  description: "Service-to-service key (KEY_SERVICE_API_KEY)",
});

// ==================== Unified Key Endpoints (/keys) ====================

export const KeySourceSchema = z.enum(["org", "platform", "byok"]);

export const ListKeysQuerySchema = z
  .object({
    keySource: KeySourceSchema,
    orgId: z.string().min(1).optional(),
  })
  .openapi("ListKeysQuery");

const UnifiedKeyItemSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    createdAt: z.coerce.date(),
    updatedAt: z.coerce.date(),
  })
  .openapi("UnifiedKeyItem");

const ListKeysResponseSchema = z
  .object({
    keys: z.array(UnifiedKeyItemSchema),
  })
  .openapi("ListKeysResponse");

registry.registerPath({
  method: "get",
  path: "/keys",
  summary: "List keys by source",
  description:
    "List stored keys filtered by keySource. Use keySource=org (requires orgId) or keySource=platform (no scope).",
  security: [{ serviceKeyAuth: [] }],
  request: {
    query: ListKeysQuerySchema,
  },
  responses: {
    200: {
      description: "List of keys",
      content: { "application/json": { schema: ListKeysResponseSchema } },
    },
    400: { description: "Missing required parameters" },
  },
});

export const UpsertKeyRequestSchema = z
  .object({
    keySource: KeySourceSchema,
    provider: z.string().min(1),
    apiKey: z.string().min(1),
    orgId: z.string().min(1).optional(),
  })
  .refine(
    (data) => {
      const source = data.keySource === "byok" ? "org" : data.keySource;
      if (source === "org") return !!data.orgId;
      return true;
    },
    { message: "orgId required for keySource 'org'" }
  )
  .openapi("UpsertKeyRequest");

const UpsertKeyResponseSchema = z
  .object({
    provider: z.string(),
    maskedKey: z.string(),
    message: z.string(),
  })
  .openapi("UpsertKeyResponse");

registry.registerPath({
  method: "post",
  path: "/keys",
  summary: "Add or update a key",
  description:
    "Upsert a key. keySource determines scope: org (requires orgId), platform (no scope). 'byok' is accepted as alias for 'org'.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    body: {
      content: { "application/json": { schema: UpsertKeyRequestSchema } },
    },
  },
  responses: {
    200: {
      description: "Key saved",
      content: { "application/json": { schema: UpsertKeyResponseSchema } },
    },
    400: { description: "Invalid request" },
  },
});

export const DeleteKeyQuerySchema = z
  .object({
    keySource: KeySourceSchema,
    orgId: z.string().min(1).optional(),
  })
  .openapi("DeleteKeyQuery");

const DeleteKeyResponseSchema = z
  .object({
    provider: z.string(),
    message: z.string(),
  })
  .openapi("DeleteKeyResponse");

registry.registerPath({
  method: "delete",
  path: "/keys/{provider}",
  summary: "Delete a key",
  description:
    "Delete a key by provider. keySource determines scope: org (requires orgId), platform (no scope).",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    query: DeleteKeyQuerySchema,
  },
  responses: {
    200: {
      description: "Key deleted",
      content: { "application/json": { schema: DeleteKeyResponseSchema } },
    },
    400: { description: "Invalid request" },
  },
});

// Decrypt — auto-resolves key source via org_provider_key_sources preference
export const DecryptKeyQuerySchema = z
  .object({
    orgId: z.string().min(1),
  })
  .openapi("DecryptKeyQuery");

const DecryptKeyResponseSchema = z
  .object({
    provider: z.string(),
    key: z.string(),
    keySource: z.enum(["org", "platform"]),
  })
  .openapi("DecryptKeyResponse");

registry.registerPath({
  method: "get",
  path: "/keys/{provider}/decrypt",
  summary: "Get decrypted key (auto-resolves source)",
  description:
    "Returns the decrypted key for a provider. Automatically resolves whether to use org or platform key based on the org's preference (default: platform). Response includes keySource indicating which was used. Requires X-Caller-* headers for provider requirements tracking.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    query: DecryptKeyQuerySchema,
    headers: z.object({
      "x-caller-service": z.string().min(1).openapi({ description: "Name of the calling service", example: "apollo" }),
      "x-caller-method": z.string().min(1).openapi({ description: "HTTP method of the caller's endpoint", example: "POST" }),
      "x-caller-path": z.string().min(1).openapi({ description: "Path of the caller's endpoint", example: "/leads/search" }),
    }),
  },
  responses: {
    200: {
      description: "Decrypted key",
      content: { "application/json": { schema: DecryptKeyResponseSchema } },
    },
    400: { description: "Missing required parameters or caller headers" },
    404: { description: "Key not configured" },
  },
});

// ==================== Key Source Preferences ====================

export const SetKeySourceRequestSchema = z
  .object({
    orgId: z.string().min(1),
    keySource: z.enum(["org", "platform"]),
  })
  .openapi("SetKeySourceRequest");

const SetKeySourceResponseSchema = z
  .object({
    provider: z.string(),
    orgId: z.string(),
    keySource: z.enum(["org", "platform"]),
    message: z.string(),
  })
  .openapi("SetKeySourceResponse");

registry.registerPath({
  method: "put",
  path: "/keys/{provider}/source",
  summary: "Set key source preference for an org+provider",
  description:
    "Set whether an org uses its own key ('org') or the platform key ('platform') for a given provider. If switching to 'org', an org key must already be stored — otherwise returns 400.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    body: {
      content: { "application/json": { schema: SetKeySourceRequestSchema } },
    },
  },
  responses: {
    200: {
      description: "Key source preference saved",
      content: { "application/json": { schema: SetKeySourceResponseSchema } },
    },
    400: { description: "Invalid request or no org key stored" },
  },
});

const GetKeySourceQuerySchema = z
  .object({
    orgId: z.string().min(1),
  })
  .openapi("GetKeySourceQuery");

const GetKeySourceResponseSchema = z
  .object({
    provider: z.string(),
    orgId: z.string(),
    keySource: z.enum(["org", "platform"]),
    isDefault: z.boolean(),
  })
  .openapi("GetKeySourceResponse");

registry.registerPath({
  method: "get",
  path: "/keys/{provider}/source",
  summary: "Get key source preference for an org+provider",
  description:
    "Returns the current key source preference for an org+provider. If no explicit preference is set, returns 'platform' with isDefault=true.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    query: GetKeySourceQuerySchema,
  },
  responses: {
    200: {
      description: "Key source preference",
      content: { "application/json": { schema: GetKeySourceResponseSchema } },
    },
    400: { description: "Missing orgId" },
  },
});

// List all key source preferences for an org
const ListKeySourcesQuerySchema = z
  .object({
    orgId: z.string().min(1),
  })
  .openapi("ListKeySourcesQuery");

const KeySourceItemSchema = z
  .object({
    provider: z.string(),
    keySource: z.enum(["org", "platform"]),
  })
  .openapi("KeySourceItem");

const ListKeySourcesResponseSchema = z
  .object({
    sources: z.array(KeySourceItemSchema),
  })
  .openapi("ListKeySourcesResponse");

registry.registerPath({
  method: "get",
  path: "/keys/sources",
  summary: "List all key source preferences for an org",
  description:
    "Returns all explicit key source preferences for an org. Providers not listed default to 'platform'.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    query: ListKeySourcesQuerySchema,
  },
  responses: {
    200: {
      description: "Key source preferences",
      content: { "application/json": { schema: ListKeySourcesResponseSchema } },
    },
    400: { description: "Missing orgId" },
  },
});
