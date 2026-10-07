import type { HttpMethod, OperationDef, ProviderAdapter } from "./types.js";

/**
 * Explicit route registry: (provider, method, path) → operation, and
 * callback slug → provider. Built once at startup from code + env; nothing
 * at request time can add a destination.
 */
export class ProviderRegistry {
  private readonly byId = new Map<string, ProviderAdapter>();
  private readonly bySlug = new Map<string, ProviderAdapter>();
  private readonly ops = new Map<string, OperationDef>();
  private readonly disabled: ReadonlySet<string>;

  constructor(adapters: readonly ProviderAdapter[], disabledIds: readonly string[] = []) {
    this.disabled = new Set(disabledIds);
    for (const a of adapters) {
      if (this.byId.has(a.id)) throw new Error(`provider "${a.id}" registered twice`);
      this.byId.set(a.id, a);
      if (a.callback) {
        if (this.bySlug.has(a.callback.slug)) throw new Error(`callback slug "${a.callback.slug}" used by two providers`);
        this.bySlug.set(a.callback.slug, a);
      }
      for (const op of a.operations) {
        const key = ProviderRegistry.key(a.id, op.route.method, op.route.path);
        if (this.ops.has(key)) throw new Error(`route ${key} registered twice`);
        this.ops.set(key, op);
      }
    }
  }

  private static key(provider: string, method: string, path: string): string {
    return `${provider} ${method.toUpperCase()} ${path}`;
  }

  get(id: string): ProviderAdapter | undefined {
    return this.byId.get(id);
  }

  isDisabled(id: string): boolean {
    return this.disabled.has(id) && !this.byId.has(id);
  }

  byCallbackSlug(slug: string): ProviderAdapter | undefined {
    return this.bySlug.get(slug);
  }

  operation(providerId: string, method: string, path: string): OperationDef | undefined {
    return this.ops.get(ProviderRegistry.key(providerId, method as HttpMethod, path));
  }

  /** Whether any operation of this provider lives at `path` (for 405 vs 404). */
  hasPath(providerId: string, path: string): boolean {
    const a = this.byId.get(providerId);
    return Boolean(a?.operations.some((o) => o.route.path === path));
  }

  list(): ProviderAdapter[] {
    return [...this.byId.values()];
  }

  disabledIds(): string[] {
    return [...this.disabled].filter((id) => !this.byId.has(id));
  }
}
