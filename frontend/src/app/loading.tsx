import { Skeleton } from "@/components/ui/skeleton";

export default function Loading() {
  return <div className="mx-auto max-w-[1560px] space-y-5"><Skeleton className="h-20 w-full bg-white" /><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">{Array.from({ length: 5 }, (_, index) => <Skeleton key={index} className="h-32 bg-white" />)}</div><div className="grid gap-4 xl:grid-cols-[1.7fr_.75fr]"><Skeleton className="h-[360px] bg-white" /><Skeleton className="h-[360px] bg-white" /></div></div>;
}
