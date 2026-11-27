/**
 * Secret audit trail (SECURITY-ALERTS-1128).
 *
 * Every decrypt / create / update / delete of a platform, org or brand key, and
 * every request refused for a wrong service key, writes ONE append-only row in
 * `secret_audit_events` BEFORE the response leaves. A decrypt whose row cannot
 * be written fails (500): no secret is handed out without its trace.
 *
 * The row never holds a key value: provider name, who asked (X-Caller-*
 * headers, as declared), where from (socket address + X-Forwarded-For), outcome.
 * After the write, the security checks run in the background
 * (`lib/security-alerts.ts`).
 */

import { Request } from "express";
import { timingSafeEqual } from "crypto";
import { db } from "../db/index.js";
import { secretAuditEvents } from "../db/schema.js";
import { extractCallerHeaders } from "./caller-headers.js";
import { scheduleSecurityChecks } from "./security-alerts.js";

export type AuditAction = "decrypt" | "create" | "update" | "delete" | "auth_rejected";
export type AuditGrain = "platform" | "org" | "brand";
export type AuditOutcome = "success" | "not_found" | "refused";

export interface AuditEvent {
  action: AuditAction;
  grain: AuditGrain | null;
  provider: string | null;
  orgId: string | null;
  brandId: string | null;
  callerService: string | null;
  callerMethod: string | null;
  callerPath: string | null;
  requestMethod: string;
  requestPath: string;
  sourceIp: string;
  forwardedFor: string | null;
  outcome: AuditOutcome;
}

/** Caller-controlled strings are capped: a header is evidence, not storage. */
const cap = (v: string | null | undefined, n = 200): string | null =>
  v == null ? null : v.length > n ? v.slice(0, n) : v;

/** The peer that opened the socket (a container on the box network), IPv4-mapped prefix stripped. */
export function sourceIpOf(req: Request): string {
  const raw = req.socket?.remoteAddress;
  if (!raw) return "unknown";
  return raw.startsWith("::ffff:") ? raw.slice(7) : raw;
}

function forwardedForOf(req: Request): string | null {
  const xff = req.headers["x-forwarded-for"];
  const real = req.headers["x-real-ip"];
  const v = typeof xff === "string" ? xff : Array.isArray(xff) ? xff.join(", ") : typeof real === "string" ? real : null;
  return cap(v);
}

/** The request path as received (mount prefix included), query string dropped. */
function requestPathOf(req: Request): string {
  return (req.originalUrl || req.url || "").split("?")[0];
}

export interface AuditFacts {
  action: AuditAction;
  grain: AuditGrain | null;
  provider: string | null;
  outcome: AuditOutcome;
  orgId?: string | null;
  brandId?: string | null;
}

export function buildAuditEvent(req: Request, facts: AuditFacts): AuditEvent {
  const caller = extractCallerHeaders(req);
  return {
    action: facts.action,
    grain: facts.grain,
    provider: cap(facts.provider),
    orgId: cap(facts.orgId ?? null),
    brandId: cap(facts.brandId ?? null),
    callerService: cap(caller?.service ?? null),
    callerMethod: cap(caller?.method ?? null, 20),
    callerPath: cap(caller?.path ?? null),
    requestMethod: req.method,
    requestPath: cap(requestPathOf(req), 500) as string,
    sourceIp: cap(sourceIpOf(req), 100) as string,
    forwardedFor: forwardedForOf(req),
    outcome: facts.outcome,
  };
}

/**
 * Append the audit row (awaited: throws if it cannot be written), then queue
 * the security checks. Returns the stored event.
 */
export async function recordSecretEvent(req: Request, facts: AuditFacts): Promise<AuditEvent> {
  const event = buildAuditEvent(req, facts);
  await db.insert(secretAuditEvents).values(event);
  scheduleSecurityChecks(event, isSecurityAlertTest(req));
  return event;
}

/**
 * A staff proof-of-fire: header `x-security-alert-test` equal to the box-only
 * SECURITY_ALERT_TEST_TOKEN. Its incident is mailed with a [TEST] subject and
 * never turns Monitoring red. Keyed on a secret that lives only in the env file,
 * never on a caller name: anyone holding the service key could pick a name and
 * dress a real dump up as a test.
 */
export function isSecurityAlertTest(req: Request): boolean {
  const token = process.env.SECURITY_ALERT_TEST_TOKEN?.trim();
  const given = req.headers["x-security-alert-test"];
  if (!token || typeof given !== "string") return false;
  const a = Buffer.from(given.trim());
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}
