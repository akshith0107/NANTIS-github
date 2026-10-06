import fs from "fs";
import path from "path";
function readFilesRecursively(dir, baseDir = dir) {
    const fileMap = new Map();
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
        }
        else if (entry.isFile()) {
            const relPath = path.relative(baseDir, fullPath).replace(/\\/g, "/");
            const content = fs.readFileSync(fullPath, "utf-8");
            fileMap.set(relPath, content);
        }
    }
    return fileMap;
}
export function loadFixture(fixturesRootDir, checkId) {
    const checkDir = path.join(fixturesRootDir, checkId);
    if (!fs.existsSync(checkDir)) {
        throw new Error(`Fixture directory not found for checkId: ${checkId} at ${checkDir}`);
    }
    const expectedPath = path.join(checkDir, "expected.json");
    if (!fs.existsSync(expectedPath)) {
        throw new Error(`expected.json missing for checkId: ${checkId}`);
    }
    const expectedRaw = fs.readFileSync(expectedPath, "utf-8");
    const expected = JSON.parse(expectedRaw);
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
export function loadAllFixtures(fixturesRootDir) {
    if (!fs.existsSync(fixturesRootDir)) {
        return [];
    }
    const entries = fs.readdirSync(fixturesRootDir, { withFileTypes: true });
    const fixtureSets = [];
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
//# sourceMappingURL=index.js.map