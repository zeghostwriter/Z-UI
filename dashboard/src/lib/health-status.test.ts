import { describe, expect, it } from "vitest";
import { parseHealthStatus } from "./health-status";

describe("the health answer as the dashboard reads it", () => {
  it("calls a running core running", () => {
    expect(parseHealthStatus({ core: { running: true, inbounds: ["vless-1"] } })).toEqual({
      state: "running",
      reason: "running",
    });
  });

  it("tells an empty core from one that stopped with inbounds", () => {
    expect(parseHealthStatus({ core: { running: false, inbounds: [] } })).toEqual({
      state: "stopped",
      reason: "no_inbounds",
    });
    expect(parseHealthStatus({ core: { running: false, inbounds: ["vless-1"] } })).toEqual({
      state: "stopped",
      reason: "stopped",
    });
  });

  it("keeps a reason the panel reported", () => {
    expect(parseHealthStatus({ core: { running: false, inbounds: [], reason: "core_error" } })).toEqual({
      state: "stopped",
      reason: "core_error",
    });
    expect(parseHealthStatus({ reason: "core_error", core: { running: false } })).toEqual({
      state: "stopped",
      reason: "core_error",
    });
  });

  it("falls back to an unknown reason for one it cannot explain", () => {
    expect(parseHealthStatus({ core: { running: false, reason: "a new reason" } })).toEqual({
      state: "stopped",
      reason: "unknown",
    });
    expect(parseHealthStatus({ core: { running: false, reason: "running" } })).toEqual({
      state: "stopped",
      reason: "unknown",
    });
  });

  it("does not call an unreadable answer a stopped core", () => {
    for (const value of [undefined, null, "down", [], {}, { core: [] }, { core: { running: "false" } }]) {
      expect(parseHealthStatus(value)).toEqual({ state: "unknown", reason: "unknown" });
    }
  });
});
