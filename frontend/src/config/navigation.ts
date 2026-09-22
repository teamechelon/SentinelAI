export interface PlannedModule { slug: string; label: string }
export const plannedModules: readonly PlannedModule[] = [];
export type PlannedModuleSlug = string;

export function getPlannedModule(slug: string) {
  return plannedModules.find((module) => module.slug === slug);
}
