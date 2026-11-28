/** What the dashboard can say about the core from the last health answer. */
export type HealthState = "running" | "stopped" | "unknown";

/** Stable reasons behind a state; `unknown` covers a reason we cannot name. */
export type HealthReason = "running" | "stopped" | "no_inbounds" | "core_error" | "unknown";

export interface HealthStatus {
  state: HealthState;
  reason: HealthReason;
}

const knownReasons: HealthReason[] = ["running", "stopped", "no_inbounds", "core_error", "unknown"];

const asRecord = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};

const asText = (value: unknown): string | null => (typeof value === "string" && value.trim() ? value.trim() : null);

/**
 * Read a `/health` answer for display. An answer we cannot read is `unknown`,
 * never `stopped`: the dashboard must not report a down core on the strength
 * of a malformed reply.
 */
export function parseHealthStatus(value: unknown): HealthStatus {
  const core = asRecord(asRecord(value).core);
  if (typeof core.running !== "boolean") return { state: "unknown", reason: "unknown" };
  if (core.running) return { state: "running", reason: "running" };

  const health = asRecord(value);
  const reported = asText(core.reason) ?? asText(health.reason);
  if (reported) {
    // "running" contradicts what the answer says, so it cannot explain it.
    if (reported === "running") return { state: "stopped", reason: "unknown" };
    if (knownReasons.includes(reported as HealthReason)) return { state: "stopped", reason: reported as HealthReason };
    return { state: "stopped", reason: "unknown" };
  }
  // The node stops the core when there is nothing to listen on; that is a
  // different thing from a core that stopped while it had inbounds.
  const inbounds = Array.isArray(core.inbounds) ? core.inbounds : [];
  return { state: "stopped", reason: inbounds.length === 0 ? "no_inbounds" : "stopped" };
}
