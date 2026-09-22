import type { RiskLevel } from "@/domain/sentinel";

export function RiskValue({ level, score }: { level: RiskLevel; score: number }) {
  return <span aria-label={`${level} risk score ${score.toFixed(1)} out of 100`} className="tabular font-mono text-[15px] font-semibold" style={{ color: `var(--${level.toLowerCase()})` }}>{score.toFixed(1)}</span>;
}
