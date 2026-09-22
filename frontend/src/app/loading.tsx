import { Skeleton } from "@/components/ui/skeleton";

export default function Loading() {
  return <div className="mx-auto max-w-[1600px] space-y-4"><Skeleton className="h-20 w-full bg-[var(--surface)]" /><Skeleton className="h-[520px] w-full bg-[var(--surface)]" /></div>;
}
