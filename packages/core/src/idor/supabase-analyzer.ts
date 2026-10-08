import { IndexedRepository, IndexedSupabaseQuery } from "./types.js";
import { UnresolvedStep } from "../types.js";

export interface SupabaseTableSecurityStatus {
  tableName: string;
  rlsEnabled: boolean;
  hasPermissivePolicy: boolean;
  hasUserScopedPolicy: boolean;
  ownerColumns: string[];
  isSecureByRls: boolean;
  unresolvedSteps: UnresolvedStep[];
}

/**
 * Analyzes Supabase usage, table definitions, RLS policies, and ownership constraints deterministically.
 */
export class SupabaseAnalyzer {
  constructor(private indexedRepo: IndexedRepository) {}

  /**
   * Retrieves security status for a database table from indexed SQL migrations.
   */
  getTableSecurityStatus(tableName: string): SupabaseTableSecurityStatus {
    const table = this.indexedRepo.tables.get(tableName);

    if (!table) {
      // Table schema not found in indexed migrations -> table lacks RLS by default
      return {
        tableName,
        rlsEnabled: false,
        hasPermissivePolicy: false,
        hasUserScopedPolicy: false,
        ownerColumns: [],
        isSecureByRls: false,
        unresolvedSteps: [],
      };
    }

    const hasPermissivePolicy = table.policies.some((p) => p.isPermissive);
    const hasUserScopedPolicy = table.policies.some((p) => p.hasAuthUid);

    // RLS protects table if RLS is enabled, user-scoped policy exists, and NO permissive USING(true) policy overrides it
    const isSecureByRls = table.hasRlsEnabled && hasUserScopedPolicy && !hasPermissivePolicy;

    return {
      tableName,
      rlsEnabled: table.hasRlsEnabled,
      hasPermissivePolicy,
      hasUserScopedPolicy,
      ownerColumns: table.ownerColumns,
      isSecureByRls,
      unresolvedSteps: [],
    };
  }

  /**
   * Validates whether a Supabase query is constrained by an ownership filter or valid RLS policy.
   */
  evaluateQuerySecurity(query: IndexedSupabaseQuery): {
    isOwnerConstrained: boolean;
    isRlsProtected: boolean;
    unresolvedSteps: UnresolvedStep[];
  } {
    const tableStatus = this.getTableSecurityStatus(query.table);

    // Query is directly owner-constrained if it includes a filter on an ownership column matched to authenticated user
    const hasDirectOwnerFilter = query.filters.some((f) => f.isOwnerCheck && (f.isAuthUidCheck || f.isUserControlled));

    const isOwnerConstrained = hasDirectOwnerFilter || query.hasAuthUidFilter;
    const isRlsProtected = tableStatus.isSecureByRls;

    return {
      isOwnerConstrained,
      isRlsProtected,
      unresolvedSteps: tableStatus.unresolvedSteps,
    };
  }
}
