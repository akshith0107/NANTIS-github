import fs from "fs";
import path from "path";

export interface ScannedFile {
  relativePath: string;
  absolutePath: string;
  content: string;
}

const DEFAULT_IGNORED_DIRS = new Set([
  "node_modules",
  ".next",
  "dist",
  "build",
  ".git",
  ".turbo",
  "coverage",
  ".vercel",
]);

const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".svg",
  ".webp",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".7z",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".bin",
  ".wasm",
  ".ttf",
  ".woff",
  ".woff2",
  ".eot",
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
]);

export function isBinaryFile(filePath: string, buffer?: Buffer): boolean {
  const ext = path.extname(filePath).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) {
    return true;
  }

  if (buffer) {
    // Check first 512 bytes for null byte
    const checkLength = Math.min(buffer.length, 512);
    for (let i = 0; i < checkLength; i++) {
      if (buffer[i] === 0) {
        return true;
      }
    }
  }

  return false;
}

function parseGitignore(rootDir: string): string[] {
  const gitignorePath = path.join(rootDir, ".gitignore");
  if (!fs.existsSync(gitignorePath)) {
    return [];
  }

  try {
    const content = fs.readFileSync(gitignorePath, "utf-8");
    return content
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#"));
  } catch {
    return [];
  }
}

function isPathIgnored(relPath: string, gitignorePatterns: string[]): boolean {
  const normalizedRel = relPath.replace(/\\/g, "/");
  const segments = normalizedRel.split("/");

  // Check default ignored directories
  for (const segment of segments) {
    if (DEFAULT_IGNORED_DIRS.has(segment)) {
      return true;
    }
  }

  // Check simple gitignore pattern rules
  for (const pattern of gitignorePatterns) {
    const cleanPattern = pattern.replace(/^\//, "").replace(/\/$/, "");
    if (normalizedRel === cleanPattern || normalizedRel.startsWith(cleanPattern + "/")) {
      return true;
    }
    if (segments.includes(cleanPattern)) {
      return true;
    }
  }

  return false;
}

export function walkDirectory(rootDir: string): ScannedFile[] {
  const normalizedRoot = path.resolve(rootDir);
  if (!fs.existsSync(normalizedRoot)) {
    throw new Error(`Directory does not exist: ${rootDir}`);
  }

  const rootReal = fs.realpathSync(normalizedRoot);
  const gitignorePatterns = parseGitignore(normalizedRoot);
  const results: ScannedFile[] = [];

  function traverse(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      // Symlink escape prevention
      let realFullPath: string;
      try {
        realFullPath = fs.realpathSync(fullPath);
      } catch {
        // Skip broken symlinks or unreadable paths
        continue;
      }

      // Ensure target real path is strictly within the root real path
      const relativeToRoot = path.relative(rootReal, realFullPath);
      if (relativeToRoot.startsWith("..") || path.isAbsolute(relativeToRoot)) {
        // Symlink points outside root or traversal attempt - ignore for safety
        continue;
      }

      const relPath = path.relative(rootReal, realFullPath).replace(/\\/g, "/");

      if (isPathIgnored(relPath, gitignorePatterns)) {
        continue;
      }

      const stat = fs.statSync(realFullPath);
      if (stat.isDirectory()) {
        traverse(realFullPath);
      } else if (stat.isFile()) {
        const buffer = fs.readFileSync(realFullPath);
        if (!isBinaryFile(realFullPath, buffer)) {
          results.push({
            relativePath: relPath,
            absolutePath: realFullPath,
            content: buffer.toString("utf-8"),
          });
        }
      }
    }
  }

  traverse(rootReal);
  return results;
}
