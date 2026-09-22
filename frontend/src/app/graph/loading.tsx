import { Skeleton } from "@/components/ui/skeleton";

export default function GraphLoading() {
  return (
    <div className="mx-auto max-w-[1600px] space-y-6">
      {/* Header Skeleton */}
      <div className="space-y-2">
        <Skeleton className="h-4 w-36 bg-[var(--surface-subtle)]" />
        <Skeleton className="h-8 w-56 bg-[var(--surface-subtle)]" />
        <Skeleton className="h-4 w-96 bg-[var(--surface-subtle)]" />
      </div>

      {/* 6 Summary Cards Skeleton */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }, (_, index) => (
          <div
            key={index}
            className="panel p-3.5 space-y-2 bg-[var(--surface)] border border-[var(--border)] rounded-lg"
          >
            <Skeleton className="h-3 w-20 bg-[var(--surface-subtle)]" />
            <Skeleton className="h-7 w-14 bg-[var(--surface-subtle)]" />
            <Skeleton className="h-3 w-24 bg-[var(--surface-subtle)]" />
          </div>
        ))}
      </div>

      {/* Toolbar Skeleton */}
      <div className="panel p-3 bg-[var(--surface)] border border-[var(--border)] rounded-lg">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Skeleton className="h-8 w-64 bg-[var(--surface-subtle)]" />
          <div className="flex items-center gap-2">
            <Skeleton className="h-8 w-32 bg-[var(--surface-subtle)]" />
            <Skeleton className="h-8 w-32 bg-[var(--surface-subtle)]" />
            <Skeleton className="h-8 w-24 bg-[var(--surface-subtle)]" />
          </div>
        </div>
      </div>

      {/* Graph Canvas Skeleton */}
      <div className="panel p-4 bg-[var(--surface)] border border-[var(--border)] rounded-lg">
        <div className="flex items-center justify-between border-b border-[var(--border)] pb-2.5 mb-3">
          <Skeleton className="h-4 w-48 bg-[var(--surface-subtle)]" />
          <Skeleton className="h-4 w-36 bg-[var(--surface-subtle)]" />
        </div>
        <Skeleton className="h-[600px] w-full rounded bg-[var(--surface-subtle)]" />
      </div>

      {/* Findings Table Skeleton */}
      <div className="panel p-4 bg-[var(--surface)] border border-[var(--border)] rounded-lg space-y-3">
        <Skeleton className="h-5 w-44 bg-[var(--surface-subtle)]" />
        <Skeleton className="h-32 w-full bg-[var(--surface-subtle)]" />
      </div>
    </div>
  );
}
