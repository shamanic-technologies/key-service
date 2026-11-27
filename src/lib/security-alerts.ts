/**
 * Security alerts on secret reads and writes (SECURITY-ALERTS-1128).
 *
 * Evidence (2026-11-20): with a leaked KEY_SERVICE_API_KEY an attacker created
 * platform key `probe26210` and decrypted ~57 platform keys under caller names
 * `probe26235` / `auto-collect`; nothing alerted. Each audit row now runs four
 * checks, and a hit opens (or joins) a security incident that mails staff ONCE
 * through transactional-email-service `POST /platform-staff-alert`
 * (`security_alert`, eventId `key-service:<kind>:<incidentId>`):
 *
 * - key_write              a platform/org/brand key was created, changed or deleted.
 *                          Boot-time registrations re-send the SAME value and write
 *                          nothing, so they never reach this check.
 * - unknown_caller_decrypt a decrypt from a caller service not seen in 30 days.
 * - provider_sweep         one caller service decrypted > SWEEP_PER_CALLER distinct
 *                          providers in 10 min, or one source address > SWEEP_PER_SOURCE.
 * - auth_failure_burst     >= AUTH_BURST requests with a wrong service key from one
 *                          source address in 10 min.
 *
 * Incident = (kind, subject); a new hit within INCIDENT_QUIET_MS of the last one
 * joins it (count + last seen) and mails nothing. An undelivered alert stays
 * `failed`/`pending` and the retry sweep resends it under the SAME eventId
 * (transactional-email-service dedups by eventId, so a retry never mails twice).
 */

import { and, eq, gt, lt, sql as dsql, inArray, desc } from "drizzle-orm";
import { db } from "../db/index.js";
import { knownCallers, securityIncidents, secretAuditEvents } from "../db/schema.js";
import type { AuditEvent } from "./audit.js";

export const WINDOW_MS = 10 * 60 * 1000;
export const KNOWN_CALLER_DAYS = 30;
export const SWEEP_PER_CALLER = 20; // busiest legit service ever decrypted 15 distinct providers (chat, prod 2026-11-27)
export const SWEEP_PER_SOURCE = 40; // one container may carry 2 caller names (chat + chat-service: 24)
export const AUTH_BURST = 5; // prod baseline: 1 rejected request in 12 h (2026-11-27)
export const INCIDENT_QUIET_MS = 60 * 60 * 1000;
export const AUDIT_RETENTION_DAYS = 90;

export type IncidentKind = "key_write" | "unknown_caller_decrypt" | "provider_sweep" | "auth_failure_burst";

const pending = new Set<Promise<void>>();

/** Run the checks for one audit row in the background. Failures are logged loudly, never thrown at the request. */
export function scheduleSecurityChecks(event: AuditEvent, test = false): void {
  const p = runSecurityChecks(event, test)
    .catch((err) => {
      console.error(`[key-service] security checks FAILED for ${event.action} ${event.provider ?? ""} from ${event.sourceIp}:`, err);
    })
    .finally(() => {
      pending.delete(p);
    });
  pending.add(p);
}

/** Await every queued check (tests, graceful shutdown). */
export async function flushSecurityChecks(): Promise<void> {
  while (pending.size > 0) await Promise.all([...pending]);
}

function who(e: AuditEvent): string {
  const caller = e.callerService ? `caller service '${e.callerService}' (${e.callerMethod} ${e.callerPath})` : "a caller sending no X-Caller headers";
  const xff = e.forwardedFor ? `, forwarded for ${e.forwardedFor}` : "";
  return `${caller} from ${e.sourceIp}${xff}`;
}

function keyLabel(e: AuditEvent): string {
  const owner = e.grain === "brand" ? ` of org ${e.orgId} brand ${e.brandId}` : e.grain === "org" ? ` of org ${e.orgId}` : "";
  return `${e.grain} key '${e.provider}'${owner}`;
}

function eventLine(e: AuditEvent): string {
  return [
    `action=${e.action}`,
    `outcome=${e.outcome}`,
    e.grain ? `grain=${e.grain}` : null,
    e.provider ? `provider=${e.provider}` : null,
    e.orgId ? `org=${e.orgId}` : null,
    e.brandId ? `brand=${e.brandId}` : null,
    `caller=${e.callerService ?? "-"} ${e.callerMethod ?? ""} ${e.callerPath ?? ""}`.trim(),
    `request=${e.requestMethod} ${e.requestPath}`,
    `source=${e.sourceIp}`,
    e.forwardedFor ? `forwardedFor=${e.forwardedFor}` : null,
  ].filter(Boolean).join(" | ");
}

export async function runSecurityChecks(e: AuditEvent, test = false): Promise<void> {
  const raise = (input: IncidentInput) => raiseIncident({ ...input, test });
  if ((e.action === "create" || e.action === "update" || e.action === "delete") && e.outcome === "success") {
    await raise({
      kind: "key_write",
      subject: `${e.callerService ?? "no-caller-headers"}@${e.sourceIp}`,
      summary: `Secret ${e.action === "create" ? "created" : e.action === "update" ? "changed" : "deleted"}: ${keyLabel(e)}, by ${e.callerService ?? "an unnamed caller"}`,
      evidence: `By ${who(e)}.\nIf this was not you or a deploy you made, the service key is in someone else's hands: rotate KEY_SERVICE_API_KEY.\n${eventLine(e)}`,
    });
  }

  if (e.action === "decrypt" && e.callerService) {
    const cutoff = new Date(Date.now() - KNOWN_CALLER_DAYS * 86_400_000);
    const known = await db.query.knownCallers.findFirst({
      where: and(eq(knownCallers.service, e.callerService), gt(knownCallers.lastSeenAt, cutoff)),
    });
    await db
      .insert(knownCallers)
      .values({ service: e.callerService })
      .onConflictDoUpdate({ target: knownCallers.service, set: { lastSeenAt: new Date() } });
    if (!known) {
      await raise({
        kind: "unknown_caller_decrypt",
        subject: e.callerService,
        summary: `Unknown caller '${e.callerService}' read ${keyLabel(e)}`,
        evidence: `By ${who(e)}, a caller service not seen in the last ${KNOWN_CALLER_DAYS} days (outcome: ${e.outcome}).\nIf no service named '${e.callerService}' was just deployed, rotate KEY_SERVICE_API_KEY and every key it read.\n${eventLine(e)}`,
      });
    }
  }

  if (e.action === "decrypt") {
    const since = new Date(Date.now() - WINDOW_MS);
    if (e.callerService) {
      const providers = await distinctProviders(eq(secretAuditEvents.callerService, e.callerService), since);
      if (providers.length > SWEEP_PER_CALLER) {
        await raise({
          kind: "provider_sweep",
          subject: `caller:${e.callerService}`,
          summary: `'${e.callerService}' read ${providers.length} different secrets in 10 minutes`,
          evidence: `Normal: at most ${SWEEP_PER_CALLER}. Looks like a bulk secret dump.\nLast request: ${eventLine(e)}\nProviders read: ${providers.join(", ")}`,
        });
      }
    }
    const fromSource = await distinctProviders(eq(secretAuditEvents.sourceIp, e.sourceIp), since);
    if (fromSource.length > SWEEP_PER_SOURCE) {
      await raise({
        kind: "provider_sweep",
        subject: `source:${e.sourceIp}`,
        summary: `Address ${e.sourceIp} read ${fromSource.length} different secrets in 10 minutes`,
        evidence: `Normal: at most ${SWEEP_PER_SOURCE}. Looks like a bulk secret dump under several caller names.\nLast request: ${eventLine(e)}\nProviders read: ${fromSource.join(", ")}`,
      });
    }
  }

  if (e.action === "auth_rejected") {
    const since = new Date(Date.now() - WINDOW_MS);
    const [{ n }] = await db
      .select({ n: dsql<number>`count(*)::int` })
      .from(secretAuditEvents)
      .where(and(eq(secretAuditEvents.action, "auth_rejected"), eq(secretAuditEvents.sourceIp, e.sourceIp), gt(secretAuditEvents.createdAt, since)));
    if (n >= AUTH_BURST) {
      await raise({
        kind: "auth_failure_burst",
        subject: `source:${e.sourceIp}`,
        summary: `${n} wrong key-service keys from ${e.sourceIp} in 10 minutes`,
        evidence: `Someone is guessing the key, or a service runs with a stale KEY_SERVICE_API_KEY.\nLast request: ${eventLine(e)}`,
      });
    }
  }
}

async function distinctProviders(scope: ReturnType<typeof eq>, since: Date): Promise<string[]> {
  const rows = await db
    .selectDistinct({ provider: secretAuditEvents.provider })
    .from(secretAuditEvents)
    .where(and(scope, eq(secretAuditEvents.action, "decrypt"), gt(secretAuditEvents.createdAt, since)));
  return rows.map((r) => r.provider).filter((p): p is string => !!p).sort();
}

interface IncidentInput {
  kind: IncidentKind;
  subject: string;
  summary: string;
  evidence: string;
  /** Staff proof-of-fire: [TEST] subject, never joins a real incident, never red. */
  test?: boolean;
}

/**
 * Open a new incident (and mail it) or join the open one. Serialized per
 * (kind, subject) with a transaction-scoped advisory lock, so two concurrent
 * hits never open two incidents.
 */
export async function raiseIncident(input: IncidentInput): Promise<{ id: string; opened: boolean }> {
  const test = input.test === true;
  input = { ...input, subject: `${test ? "test:" : ""}${input.subject}`.slice(0, 300) };
  const result = await db.transaction(async (tx) => {
    await tx.execute(dsql`select pg_advisory_xact_lock(hashtext(${`security-incident:${input.kind}:${input.subject}`}))`);
    const quietSince = new Date(Date.now() - INCIDENT_QUIET_MS);
    const open = await tx
      .select({ id: securityIncidents.id })
      .from(securityIncidents)
      .where(and(eq(securityIncidents.kind, input.kind), eq(securityIncidents.subject, input.subject), gt(securityIncidents.lastSeenAt, quietSince)))
      .orderBy(desc(securityIncidents.lastSeenAt))
      .limit(1);
    if (open.length > 0) {
      await tx
        .update(securityIncidents)
        .set({ lastSeenAt: new Date(), eventCount: dsql`${securityIncidents.eventCount} + 1` })
        .where(eq(securityIncidents.id, open[0].id));
      return { id: open[0].id, opened: false };
    }
    const [row] = await tx
      .insert(securityIncidents)
      .values({
        kind: input.kind,
        subject: input.subject,
        summary: input.summary.slice(0, 1000),
        evidence: input.evidence.slice(0, 4000),
        test,
        alertStatus: "pending",
      })
      .returning({ id: securityIncidents.id });
    return { id: row.id, opened: true };
  });
  if (result.opened) {
    console.warn(`[key-service] SECURITY incident opened: ${input.kind} ${input.subject} (${result.id}): ${input.summary}`);
    await deliverIncidentAlert(result.id);
  }
  return result;
}

export function incidentEventId(kind: string, id: string): string {
  return `key-service:${kind}:${id}`;
}

/** Send (or resend) one incident's staff alert. Records the outcome on the row; never throws. */
export async function deliverIncidentAlert(id: string): Promise<boolean> {
  const incident = await db.query.securityIncidents.findFirst({ where: eq(securityIncidents.id, id) });
  if (!incident) throw new Error(`security incident ${id} not found`);
  if (incident.alertStatus === "sent") return true;
  try {
    await sendSecurityAlert({
      eventId: incidentEventId(incident.kind, incident.id),
      kind: incident.kind,
      summary: incident.summary,
      evidence: `${incident.evidence}\nIncident ${incident.id}, opened ${incident.openedAt.toISOString()}.`,
      firstSeenAt: incident.openedAt.toISOString(),
      test: incident.test,
    });
    await db
      .update(securityIncidents)
      .set({ alertStatus: "sent", alertedAt: new Date(), alertAttempts: incident.alertAttempts + 1, alertError: null })
      .where(eq(securityIncidents.id, id));
    console.warn(`[key-service] SECURITY alert sent to staff: ${incident.kind} ${incident.subject} (${id})`);
    return true;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await db
      .update(securityIncidents)
      .set({ alertStatus: "failed", alertAttempts: incident.alertAttempts + 1, alertError: message.slice(0, 500) })
      .where(eq(securityIncidents.id, id));
    console.error(`[key-service] SECURITY alert NOT delivered for ${incident.kind} ${incident.subject} (${id}), retry sweep will resend: ${message}`);
    return false;
  }
}

export interface SecurityAlertPayload {
  eventId: string;
  kind: string;
  summary: string;
  evidence: string;
  firstSeenAt: string;
  test: boolean;
}

/** transactional-email-service POST /platform-staff-alert, eventType `security_alert`: staff list only, once per eventId. */
export async function sendSecurityAlert(payload: SecurityAlertPayload): Promise<void> {
  const url = process.env.TRANSACTIONAL_EMAIL_SERVICE_URL?.trim();
  const apiKey = process.env.TRANSACTIONAL_EMAIL_SERVICE_API_KEY?.trim();
  if (!url || !apiKey) throw new Error("TRANSACTIONAL_EMAIL_SERVICE_URL or TRANSACTIONAL_EMAIL_SERVICE_API_KEY not set");
  const res = await fetch(`${url}/platform-staff-alert`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": apiKey },
    body: JSON.stringify({
      eventType: "security_alert",
      eventId: payload.eventId,
      metadata: {
        kind: payload.kind,
        summary: payload.summary,
        evidence: payload.evidence,
        firstSeenAt: payload.firstSeenAt,
        ...(payload.test ? { test: "true" } : {}),
      },
    }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`transactional-email platform-staff-alert ${res.status}: ${body.slice(0, 300)}`);
  }
}

/** Resend every undelivered alert of the last 24 h. */
export async function retryUndeliveredAlerts(): Promise<number> {
  const since = new Date(Date.now() - 86_400_000);
  const rows = await db
    .select({ id: securityIncidents.id })
    .from(securityIncidents)
    .where(and(inArray(securityIncidents.alertStatus, ["pending", "failed"]), gt(securityIncidents.openedAt, since)))
    .orderBy(desc(securityIncidents.openedAt));
  let sent = 0;
  for (const r of rows) if (await deliverIncidentAlert(r.id)) sent++;
  return sent;
}

/** Delete audit rows older than the 90-day retention (the table trigger refuses younger ones). */
export async function pruneAuditEvents(): Promise<number> {
  const cutoff = new Date(Date.now() - AUDIT_RETENTION_DAYS * 86_400_000);
  const deleted = await db.delete(secretAuditEvents).where(lt(secretAuditEvents.createdAt, cutoff)).returning({ id: secretAuditEvents.id });
  return deleted.length;
}

let sweepRunning = false;

/** Minute sweep: resend undelivered alerts; hourly: prune the audit log. First tick ~60 s after boot. */
export function startSecuritySweeps(): void {
  if (!process.env.TRANSACTIONAL_EMAIL_SERVICE_URL?.trim() || !process.env.TRANSACTIONAL_EMAIL_SERVICE_API_KEY?.trim()) {
    console.error("[key-service] TRANSACTIONAL_EMAIL_SERVICE_URL / TRANSACTIONAL_EMAIL_SERVICE_API_KEY missing: security incidents are recorded but staff will NOT be mailed");
  }
  let tick = 0;
  const run = async () => {
    if (sweepRunning) return;
    sweepRunning = true;
    try {
      const resent = await retryUndeliveredAlerts();
      if (resent > 0) console.log(`[key-service] security sweep resent ${resent} alert(s)`);
      if (tick % 60 === 0) {
        const pruned = await pruneAuditEvents();
        if (pruned > 0) console.log(`[key-service] audit retention pruned ${pruned} row(s) older than ${AUDIT_RETENTION_DAYS} days`);
      }
      tick++;
    } catch (err) {
      console.error("[key-service] security sweep failed:", err);
    } finally {
      sweepRunning = false;
    }
  };
  setTimeout(() => {
    void run();
    setInterval(() => void run(), 60_000).unref();
  }, 60_000).unref();
}
