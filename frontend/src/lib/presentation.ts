import type { RiskLevel } from "@/domain/sentinel";

export const severityClass: Record<RiskLevel, string> = {
  Low: "text-[var(--low)] border-[color:var(--low)]/35 bg-[color:var(--low)]/8",
  Medium: "text-[var(--medium)] border-[color:var(--medium)]/35 bg-[color:var(--medium)]/8",
  High: "text-[var(--high)] border-[color:var(--high)]/35 bg-[color:var(--high)]/8",
  Critical: "text-[var(--critical)] border-[color:var(--critical)]/35 bg-[color:var(--critical)]/8",
};

export const severityTextClass: Record<RiskLevel, string> = {
  Low: "text-[var(--low)]",
  Medium: "text-[var(--medium)]",
  High: "text-[var(--high)]",
  Critical: "text-[var(--critical)]",
};

const threatTimestamp = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
  timeZone: "Asia/Kolkata",
});

export function formatThreatTimestamp(value: string) {
  const formatted = threatTimestamp.format(new Date(value));
  const [date, time] = formatted.split(", ");
  return { date, time, full: `${date}, ${time} IST` };
}
