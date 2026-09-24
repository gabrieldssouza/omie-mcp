/**
 * Which Omie account a request talks to. The HTTP bridge serves one connector
 * per company (Ecovalor on /mcp, ESG Now on /esgnow/mcp), all sharing the same
 * tool handlers, so the credentials ride along with the request instead of
 * being read once from the environment.
 */

import { AsyncLocalStorage } from "node:async_hooks";

export interface OmieCredentials {
  appKey: string;
  appSecret: string;
}

const current = new AsyncLocalStorage<OmieCredentials>();

export function withOmieCredentials<T>(credentials: OmieCredentials, fn: () => T): T {
  return current.run(credentials, fn);
}

/** Credentials of the connector handling this request; stdio falls back to
 *  OMIE_APP_KEY / OMIE_APP_SECRET. */
export function omieCredentials(): OmieCredentials {
  return (
    current.getStore() ?? {
      appKey: process.env.OMIE_APP_KEY || "",
      appSecret: process.env.OMIE_APP_SECRET || "",
    }
  );
}
