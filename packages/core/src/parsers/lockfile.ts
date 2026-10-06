export interface ExactDependency {
  name: string;
  version: string;
}

export function parsePackageLockJson(content: string): ExactDependency[] {
  const deps: ExactDependency[] = [];
  try {
    const parsed = JSON.parse(content);

    // v2/v3 packages object format
    if (parsed.packages && typeof parsed.packages === "object") {
      for (const [pkgPath, pkgMeta] of Object.entries(parsed.packages)) {
        if (!pkgPath || pkgPath === "") continue; // root package
        const name = pkgPath.startsWith("node_modules/")
          ? pkgPath.substring("node_modules/".length)
          : (pkgMeta as { name?: string }).name;

        const version = (pkgMeta as { version?: string }).version;
        if (name && version) {
          deps.push({ name, version });
        }
      }
      return deps;
    }

    // v1 dependencies object format
    if (parsed.dependencies && typeof parsed.dependencies === "object") {
      for (const [name, pkgMeta] of Object.entries(parsed.dependencies)) {
        const version = (pkgMeta as { version?: string }).version;
        if (name && version) {
          deps.push({ name, version });
        }
      }
    }
  } catch {
    // Return empty on JSON parse error
  }
  return deps;
}

export function parsePnpmLockYaml(content: string): ExactDependency[] {
  const deps: ExactDependency[] = [];
  const lines = content.split(/\r?\n/);

  // Parse lines matching package specs like  /express@4.17.1: or express@4.17.1:
  for (const line of lines) {
    const trimmed = line.trim();
    // Match pnpm lock format: '/express@4.17.1:' or 'express@4.17.1:'
    const match =
      /^(?:\/|['"])?(@?[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)?)@([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9._-]*)(?:['"])?:/.exec(
        trimmed
      );
    if (match) {
      const name = match[1];
      const version = match[2];
      deps.push({ name, version });
    }
  }

  return deps;
}

export function parseYarnLock(content: string): ExactDependency[] {
  const deps: ExactDependency[] = [];
  const lines = content.split(/\r?\n/);

  let currentPkgName = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (line.endsWith(":") && line.includes("@")) {
      const nameMatch = /^"?(@?[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)?)@/.exec(line);
      if (nameMatch) {
        currentPkgName = nameMatch[1];
      }
    } else if (line.startsWith("version ")) {
      const verMatch = /^version\s+["']?([^"']+)["']?/.exec(line);
      if (verMatch && currentPkgName) {
        deps.push({ name: currentPkgName, version: verMatch[1] });
        currentPkgName = "";
      }
    }
  }

  return deps;
}

export function isLooseVersionRange(versionSpec: string): boolean {
  const v = versionSpec.trim();
  if (v === "*" || v === "latest" || v.startsWith(">=") || v.startsWith(">") || v.includes("||")) {
    return true;
  }
  return false;
}
