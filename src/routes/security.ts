/**
 * Security series for dashboard v2 Monitoring (SECURITY-ALERTS-1128).
 * Mounted at /internal/security — service-key auth only, no identity.
 *
 * GET /internal/security/daily?days=30 — one row per UTC day (oldest first,
 * every day present, zeros included): secret reads, writes, wrong-key
 * requests, incidents opened, and incidents whose staff alert is still
 * undelivered. `red` is true while an incident opened in the last 24 h exists
 * or an alert failed to deliver (staff [TEST] incidents and our own jobs'
 * incidents excluded from both).
 * Plus the 20 most recent incidents.
 */

import { Router, Request, Response } from "express";
import { desc, sql as dsql } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/index.js";
import { securityIncidents } from "../db/schema.js";
import { OWN_CALLERS, isOwnCaller } from "../lib/own-callers.js";

const OWN_CALLER_NAMES = `{${Object.keys(OWN_CALLERS).join(",")}}`;

const router = Router();

const DaysSchema = z.coerce.number().int().min(1).max(90);

router.get("/daily", async (req: Request, res: Response) => {
  try {
    const parsedDays = DaysSchema.safeParse(req.query.days ?? 30);
    if (!parsedDays.success) {
      return res.status(400).json({ error: "days must be an integer between 1 and 90" });
    }
    const days = parsedDays.data;

    const rows = await db.execute<{
      day: string;
      decrypts: number;
      decrypts_refused: number;
      writes: number;
      auth_rejected: number;
      incidents: number;
    }>(dsql`
      with d as (
        select generate_series((now() at time zone 'utc')::date - (${days}::int - 1), (now() at time zone 'utc')::date, interval '1 day')::date as day
      ),
      a as (
        select (created_at at time zone 'utc')::date as day,
          count(*) filter (where action = 'decrypt' and outcome = 'success')::int as decrypts,
          count(*) filter (where action = 'decrypt' and outcome <> 'success')::int as decrypts_refused,
          count(*) filter (where action in ('create','update','delete'))::int as writes,
          count(*) filter (where action = 'auth_rejected')::int as auth_rejected
        from secret_audit_events
        where created_at >= (now() at time zone 'utc')::date - (${days}::int - 1)
        group by 1
      ),
      i as (
        select (opened_at at time zone 'utc')::date as day, count(*)::int as incidents
        from security_incidents
        where not test
          and ours_reason is null
          and not (kind = 'unknown_caller_decrypt' and subject = any(${OWN_CALLER_NAMES}::text[]))
          and opened_at >= (now() at time zone 'utc')::date - (${days}::int - 1)
        group by 1
      )
      select to_char(d.day, 'YYYY-MM-DD') as day,
        coalesce(a.decrypts, 0) as decrypts,
        coalesce(a.decrypts_refused, 0) as decrypts_refused,
        coalesce(a.writes, 0) as writes,
        coalesce(a.auth_rejected, 0) as auth_rejected,
        coalesce(i.incidents, 0) as incidents
      from d left join a on a.day = d.day left join i on i.day = d.day
      order by d.day`);

    const incidents = await db
      .select()
      .from(securityIncidents)
      .orderBy(desc(securityIncidents.openedAt))
      .limit(20);

    const dayAgo = Date.now() - 86_400_000;
    // An incident opened on one of our own jobs' bare name (2026-11-27, before lib/own-callers.ts) was us:
    // listed, never red. Since the fix such an incident can only open under `<job>:off-list:<key>`, which stays red.
    // Since SECURITY-ALERTS-OURS-1128 transactional-email-service judges every alert (staff IP, box-internal while one
    // of us is logged in): its reason is stored on the incident, listed as ours, never red.
    const ourOwn = (i: { kind: string; subject: string; oursReason: string | null }) =>
      i.oursReason !== null || (i.kind === "unknown_caller_decrypt" && isOwnCaller(i.subject));
    const real = incidents.filter((i) => !i.test && !ourOwn(i));
    const recentIncidents = real.filter((i) => i.openedAt.getTime() > dayAgo).length;
    const undelivered = real.filter((i) => i.alertStatus !== "sent").length;

    res.json({
      red: recentIncidents > 0 || undelivered > 0,
      incidentsLast24h: recentIncidents,
      undeliveredAlerts: undelivered,
      days: [...rows].map((r) => ({
        day: r.day,
        secretReads: r.decrypts,
        secretReadsRefused: r.decrypts_refused,
        keyWrites: r.writes,
        wrongKeyRequests: r.auth_rejected,
        incidentsOpened: r.incidents,
      })),
      incidents: incidents.map((i) => ({
        id: i.id,
        kind: i.kind,
        subject: i.subject,
        summary: i.summary,
        openedAt: i.openedAt.toISOString(),
        lastSeenAt: i.lastSeenAt.toISOString(),
        eventCount: i.eventCount,
        alertStatus: i.alertStatus,
        alertError: i.alertError,
        test: i.test,
        ourOwn: ourOwn(i),
        oursReason: i.oursReason,
      })),
    });
  } catch (error) {
    console.error("[key-service] GET /internal/security/daily failed:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
