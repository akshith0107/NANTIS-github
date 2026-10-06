import fs from "fs";
import path from "path";
import { OSVQueryResult, PackageQuery } from "./client.js";

export interface CacheEntry {
  timestamp: number;
  data: OSVQueryResult;
}

export class DiskOSVCache {
  private cacheFilePath: string;
  private ttlMs: number;
  private memoryCache: Map<string, CacheEntry> = new Map();

  constructor(cacheFilePath: string, ttlMs = 24 * 60 * 60 * 1000) {
    this.cacheFilePath = cacheFilePath;
    this.ttlMs = ttlMs;
    this.loadFromDisk();
  }

  private getKey(pkg: PackageQuery): string {
    return `${pkg.ecosystem || "npm"}:${pkg.name}@${pkg.version}`;
  }

  private loadFromDisk(): void {
    if (!fs.existsSync(this.cacheFilePath)) return;
    try {
      const raw = fs.readFileSync(this.cacheFilePath, "utf-8");
      const parsed = JSON.parse(raw) as Record<string, CacheEntry>;
      const now = Date.now();
      for (const [key, entry] of Object.entries(parsed)) {
        if (now - entry.timestamp < this.ttlMs) {
          this.memoryCache.set(key, entry);
        }
      }
    } catch {
      // Ignore cache load failure
    }
  }

  private saveToDisk(): void {
    try {
      const dir = path.dirname(this.cacheFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const obj: Record<string, CacheEntry> = {};
      for (const [key, entry] of this.memoryCache.entries()) {
        obj[key] = entry;
      }
      fs.writeFileSync(this.cacheFilePath, JSON.stringify(obj, null, 2), "utf-8");
    } catch {
      // Ignore cache save failure
    }
  }

  public get(pkg: PackageQuery): OSVQueryResult | null {
    const key = this.getKey(pkg);
    const entry = this.memoryCache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp >= this.ttlMs) {
      this.memoryCache.delete(key);
      return null;
    }
    return entry.data;
  }

  public set(pkg: PackageQuery, data: OSVQueryResult): void {
    const key = this.getKey(pkg);
    this.memoryCache.set(key, {
      timestamp: Date.now(),
      data,
    });
    this.saveToDisk();
  }
}
