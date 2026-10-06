/**
 * Purge any installation tokens or embedded authentication credentials from
 * `.git/config` and temporary credential files inside the target repository workspace.
 * Ensures the token is strictly available ONLY during the initial git clone step.
 */
export declare function purgeTokenFromWorkspace(targetDir: string): void;
//# sourceMappingURL=token-purge.d.ts.map
