"use client";

import { useFormStatus } from "react-dom";

export function AttackLabSubmitButton({ disabled }: { disabled: boolean }) {
  const { pending } = useFormStatus();
  return <button type="submit" disabled={disabled || pending} className="control border-[var(--accent-dim)] bg-[var(--accent-dim)] px-4 font-semibold text-[var(--accent-strong)] hover:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-40">{pending ? "Executing…" : "Execute sequence"}</button>;
}
