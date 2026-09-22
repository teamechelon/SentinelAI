import type { AlertStatus, RiskLevel } from "@/domain/sentinel";

export const riskFilters = ["All", "Critical", "High", "Medium", "Low"] as const satisfies readonly (RiskLevel | "All")[];
export const statusFilters = ["All", "New", "Investigating", "Resolved", "False Positive"] as const satisfies readonly (AlertStatus | "All")[];

export function parseRiskFilter(value: string | undefined): RiskLevel | "All" {
  return riskFilters.includes(value as (typeof riskFilters)[number]) ? value as RiskLevel | "All" : "All";
}

export function parseStatusFilter(value: string | undefined): AlertStatus | "All" {
  return statusFilters.includes(value as (typeof statusFilters)[number]) ? value as AlertStatus | "All" : "All";
}
