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
export declare function loadFixture(fixturesRootDir: string, checkId: string): LoadedFixtureSet;
export declare function loadAllFixtures(fixturesRootDir: string): LoadedFixtureSet[];
//# sourceMappingURL=index.d.ts.map