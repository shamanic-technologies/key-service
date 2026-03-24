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

/** Required on all protected endpoints (except /validate, /health, /openapi.json) */
const IdentityHeadersSchema = z.object({
  "x-org-id": z.string().min(1).openapi({ description: "Internal org UUID from client-service", example: "org-uuid-123" }),
  "x-user-id": z.string().min(1).openapi({ description: "Internal user UUID from client-service", example: "user-uuid-456" }),
});

/** Optional workflow tracking headers — injected by workflow-service on all workflow HTTP calls */
const TrackingHeadersSchema = z.object({
  "x-campaign-id": z.string().optional().openapi({ description: "Campaign identifier (injected by workflow-service)", example: "campaign-uuid-789" }),
  "x-brand-id": z.string().optional().openapi({ description: "Brand identifier (injected by workflow-service)", example: "brand-uuid-012" }),
  "x-workflow-name": z.string().optional().openapi({ description: "Workflow name (injected by workflow-service)", example: "lead-enrichment" }),
  "x-feature-slug": z.string().optional().openapi({ description: "Feature slug for tracking (injected by workflow-service)", example: "press-outreach" }),
});

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
    headers: TrackingHeadersSchema,
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
    headers: TrackingHeadersSchema.extend({
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

// ==================== User Auth Keys (/api-keys) ====================

const ListUserAuthKeysQuerySchema = z
  .object({
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
  path: "/api-keys",
  summary: "List user auth keys for an org",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
    query: ListUserAuthKeysQuerySchema,
  },
  responses: {
    200: {
      description: "List of user auth keys",
      content: { "application/json": { schema: ListUserAuthKeysResponseSchema } },
    },
  },
});

export const CreateUserAuthKeyRequestSchema = z
  .object({
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
  path: "/api-keys",
  summary: "Create a new user auth key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
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

const MessageResponseSchema = z
  .object({
    message: z.string(),
  })
  .openapi("MessageResponse");

registry.registerPath({
  method: "delete",
  path: "/api-keys/{id}",
  summary: "Delete a user auth key",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
    params: z.object({ id: z.string().uuid() }),
  },
  responses: {
    200: {
      description: "User auth key deleted",
      content: { "application/json": { schema: MessageResponseSchema } },
    },
    404: { description: "Key not found" },
  },
});

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
  path: "/api-keys/session",
  summary: "Get or create a default user auth key for the org+user",
  description: "Uses orgId and userId from identity headers (x-org-id, x-user-id). No request body needed.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
  },
  responses: {
    200: {
      description: "Session key",
      content: { "application/json": { schema: SessionKeyResponseSchema } },
    },
  },
});

// ==================== Org Keys (/keys) ====================

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
  path: "/keys",
  summary: "List org keys for an org",
  description: "Uses orgId from identity header (x-org-id).",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
  },
  responses: {
    200: {
      description: "List of org keys",
      content: { "application/json": { schema: ListOrgKeysResponseSchema } },
    },
  },
});

export const CreateOrgKeyRequestSchema = z
  .object({
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
  path: "/keys",
  summary: "Add or update an org key",
  description: "Uses orgId from identity header (x-org-id).",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
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

const DeleteOrgKeyResponseSchema = z
  .object({
    provider: z.string(),
    message: z.string(),
  })
  .openapi("DeleteOrgKeyResponse");

registry.registerPath({
  method: "delete",
  path: "/keys/{provider}",
  summary: "Delete an org key",
  description: "Uses orgId from identity header (x-org-id).",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
    params: z.object({
      provider: z.string(),
    }),
  },
  responses: {
    200: {
      description: "Org key deleted",
      content: {
        "application/json": { schema: DeleteOrgKeyResponseSchema },
      },
    },
  },
});

// ==================== Platform Keys (/platform-keys) ====================

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
  path: "/platform-keys",
  summary: "Add or update a platform key",
  description:
    "Upsert a platform-level API key. Platform keys are global — not tied to any org. Typically registered once at deployment. No identity headers needed.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: TrackingHeadersSchema,
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
  path: "/platform-keys",
  summary: "List all platform keys",
  description: "No identity headers needed.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: TrackingHeadersSchema,
  },
  responses: {
    200: {
      description: "List of platform keys",
      content: { "application/json": { schema: ListPlatformKeysResponseSchema } },
    },
  },
});

const DeletePlatformKeyResponseSchema = z
  .object({
    provider: z.string(),
    message: z.string(),
  })
  .openapi("DeletePlatformKeyResponse");

registry.registerPath({
  method: "delete",
  path: "/platform-keys/{provider}",
  summary: "Delete a platform key",
  description: "No identity headers needed.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: TrackingHeadersSchema,
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

// ==================== Provider Requirements (/provider-requirements) ====================

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
  path: "/provider-requirements",
  summary: "Query which providers are needed for a set of endpoints",
  description:
    "Given a list of service endpoints (service + method + path), returns which third-party providers each endpoint has been observed requesting. Used by workflow-service to determine which keys are needed before execution. No identity headers needed.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: TrackingHeadersSchema,
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

// ==================== Key Resolve Endpoints (/keys) ====================

// Platform key decrypt — explicit, no auto-resolve
const DecryptPlatformKeyDirectResponseSchema = z
  .object({
    provider: z.string(),
    key: z.string(),
  })
  .openapi("DecryptPlatformKeyDirectResponse");

registry.registerPath({
  method: "get",
  path: "/keys/platform/{provider}/decrypt",
  summary: "Get decrypted platform key (direct)",
  description:
    "Returns the decrypted platform-level key for the given provider. No orgId/userId needed — platform keys are global. Requires X-Caller-* headers for provider requirements tracking.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    headers: TrackingHeadersSchema.extend({
      "x-caller-service": z.string().min(1).openapi({ description: "Name of the calling service", example: "billing" }),
      "x-caller-method": z.string().min(1).openapi({ description: "HTTP method of the caller's endpoint", example: "POST" }),
      "x-caller-path": z.string().min(1).openapi({ description: "Path of the caller's endpoint", example: "/billing/charge" }),
    }),
  },
  responses: {
    200: {
      description: "Decrypted platform key",
      content: { "application/json": { schema: DecryptPlatformKeyDirectResponseSchema } },
    },
    400: { description: "Missing required caller headers" },
    404: { description: "Platform key not configured" },
  },
});

// Decrypt — auto-resolves key source via org_provider_key_sources preference
const DecryptKeyResponseSchema = z
  .object({
    provider: z.string(),
    key: z.string(),
    keySource: z.enum(["org", "platform"]),
    userId: z.string(),
  })
  .openapi("DecryptKeyResponse");

registry.registerPath({
  method: "get",
  path: "/keys/{provider}/decrypt",
  summary: "Get decrypted key (auto-resolves source)",
  description:
    "Returns the decrypted key for a provider. Automatically resolves whether to use org or platform key based on the org's preference (default: platform). Response includes keySource indicating which was used. Requires X-Caller-* headers for provider requirements tracking. Uses orgId and userId from identity headers.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    params: z.object({ provider: z.string() }),
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema).extend({
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
    400: { description: "Missing required caller headers" },
    404: { description: "Key not configured" },
  },
});

// ==================== Key Source Preferences ====================

export const SetKeySourceRequestSchema = z
  .object({
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
    "Set whether an org uses its own key ('org') or the platform key ('platform') for a given provider. If switching to 'org', an org key must already be stored — otherwise returns 400. Uses orgId from identity header.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
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
    "Returns the current key source preference for an org+provider. If no explicit preference is set, returns 'platform' with isDefault=true. Uses orgId from identity header.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
    params: z.object({ provider: z.string() }),
  },
  responses: {
    200: {
      description: "Key source preference",
      content: { "application/json": { schema: GetKeySourceResponseSchema } },
    },
  },
});

// List all key source preferences for an org
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
    "Returns all explicit key source preferences for an org. Providers not listed default to 'platform'. Uses orgId from identity header.",
  security: [{ serviceKeyAuth: [] }],
  request: {
    headers: IdentityHeadersSchema.merge(TrackingHeadersSchema),
  },
  responses: {
    200: {
      description: "Key source preferences",
      content: { "application/json": { schema: ListKeySourcesResponseSchema } },
    },
  },
});
