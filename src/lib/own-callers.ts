/**
 * Our own box jobs that read keys (SECURITY-OWN-ACTORS-1128).
 *
 * 2026-11-27 19:37-19:38 UTC: the box's own security jobs (`security-watch.py
 * vendor-keys`, `security-watch.py ship` -> security-ship.mjs) decrypted keys
 * for the first time and each raised an "Unknown caller" email to staff. The
 * actor was us. A recorded positive fact replaces the guess: this list, kept in
 * the repo and changed only by a reviewed PR, names each of our jobs AND the
 * exact platform keys it reads.
 *
 * - A decrypt by a listed job of a key on its list is us: no incident, no email,
 *   never red, and it never ages out (a daily or rarely-run job stays us).
 * - The same caller name reading ANY other key is not its job: it still raises
 *   `unknown_caller_decrypt`, even once the name is in `known_callers`. Anyone
 *   holding the service key can pick a caller name; borrowing ours buys them
 *   nothing beyond the keys that job already reads.
 * - The source address is NOT a proof here: every caller of key-service is a
 *   container on our box, and the 2026-11-20 dump came through our own
 *   containers too.
 *
 * Adding a job (or a key a job reads) = one line here in the same ship as the job.
 */

export const OWN_CALLERS: Readonly<Record<string, readonly string[]>> = {
  // /root/distribute/security-watch.py vendor-keys (hourly, in distribute-apollo-service-1)
  "security-watch": ["anthropic", "postmark", "stripe"],
  // /root/distribute/security-ship.mjs (daily, throwaway cloudflare-service container)
  "security-ship": [
    "cloudflare-r2-access-key-id",
    "cloudflare-r2-secret-access-key",
    "cloudflare-r2-account-id",
    "cloudflare-r2-private-bucket-name",
    "cloudflare-r2-bucket-name",
  ],
};

export function isOwnCaller(service: string | null | undefined): boolean {
  return !!service && Object.prototype.hasOwnProperty.call(OWN_CALLERS, service);
}

/** A platform-key decrypt by one of our jobs, of a key that job reads. */
export function isOwnRead(e: { callerService: string | null; grain: string | null; provider: string | null }): boolean {
  if (!isOwnCaller(e.callerService) || e.grain !== "platform" || !e.provider) return false;
  return OWN_CALLERS[e.callerService as string].includes(e.provider);
}
