import fs from "fs";
import path from "path";

export interface ExpectedFindingLocation {
  ruleId: string;
  file: string;
  lineRange: {
    startLine: number;
    endLine: number;
  };
}

export interface ExpectedFixtureData {
  vulnerable: ExpectedFindingLocation[];
  mutated: ExpectedFindingLocation[];
  clean: ExpectedFindingLocation[];
}

export interface LoadedFixtureSet {
  checkId: string;
  vulnerableFiles: Map<string, string>;
  cleanFiles: Map<string, string>;
  mutatedFiles: Map<string, string>;
  expected: ExpectedFixtureData;
}

function readFilesRecursively(dir: string, baseDir = dir): Map<string, string> {
  const fileMap = new Map<string, string>();
  if (!fs.existsSync(dir)) {
    return fileMap;
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const subMap = readFilesRecursively(fullPath, baseDir);
      for (const [relPath, content] of subMap.entries()) {
        fileMap.set(relPath, content);
      }
    } else if (entry.isFile()) {
      const relPath = path.relative(baseDir, fullPath).replace(/\\/g, "/");
      const content = fs.readFileSync(fullPath, "utf-8");
      fileMap.set(relPath, content);
    }
  }

  return fileMap;
}

export function loadFixture(fixturesRootDir: string, checkId: string): LoadedFixtureSet {
  const checkDir = path.join(fixturesRootDir, checkId);
  if (!fs.existsSync(checkDir)) {
    throw new Error(`Fixture directory not found for checkId: ${checkId} at ${checkDir}`);
  }

  const expectedPath = path.join(checkDir, "expected.json");
  if (!fs.existsSync(expectedPath)) {
    throw new Error(`expected.json missing for checkId: ${checkId}`);
  }

  const expectedRaw = fs.readFileSync(expectedPath, "utf-8");
  const expected = JSON.parse(expectedRaw) as ExpectedFixtureData;

  const vulnerableFiles = readFilesRecursively(path.join(checkDir, "vulnerable"));
  const cleanFiles = readFilesRecursively(path.join(checkDir, "clean"));
  const mutatedFiles = readFilesRecursively(path.join(checkDir, "mutated"));

  return {
    checkId,
    vulnerableFiles,
    cleanFiles,
    mutatedFiles,
    expected,
  };
}

export function loadAllFixtures(fixturesRootDir: string): LoadedFixtureSet[] {
  if (!fs.existsSync(fixturesRootDir)) {
    return [];
  }

  const entries = fs.readdirSync(fixturesRootDir, { withFileTypes: true });
  const fixtureSets: LoadedFixtureSet[] = [];

  for (const entry of entries) {
    if (entry.isDirectory()) {
      const expectedPath = path.join(fixturesRootDir, entry.name, "expected.json");
      if (fs.existsSync(expectedPath)) {
        fixtureSets.push(loadFixture(fixturesRootDir, entry.name));
      }
    }
  }

  return fixtureSets;
}
