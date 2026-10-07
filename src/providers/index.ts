import { parscoinFactory } from "./parscoin/index.js";
import type { ProviderFactory } from "./types.js";

/**
 * Every provider the proxy knows. A provider is reachable only when it is
 * listed here AND switched on with `<PREFIX>ENABLED=true`.
 */
export const PROVIDER_FACTORIES: readonly ProviderFactory[] = [parscoinFactory];
