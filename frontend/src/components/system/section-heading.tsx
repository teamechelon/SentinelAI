export function SectionHeading({ eyebrow, title, description, action, id }: { eyebrow: string; title: string; description?: string; action?: React.ReactNode; id?: string }) {
  return <div className="flex items-end justify-between gap-4"><div><div className="tech-label">{eyebrow}</div><h2 id={id} className="mt-1 text-[14px] font-semibold">{title}</h2>{description && <p className="mt-1 text-[11px] text-[var(--text-muted)]">{description}</p>}</div>{action}</div>;
}
