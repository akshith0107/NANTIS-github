import { Project, SourceFile } from "ts-morph";

export interface ImportInfo {
  moduleSpecifier: string;
  defaultImport?: string;
  namedImports: string[];
}

export interface ExportInfo {
  name: string;
  isDefault: boolean;
}

export interface SymbolLocation {
  filePath: string;
  line: number;
  kind: string;
}

export class ProjectModel {
  private project: Project;
  private sourceFilesMap: Map<string, SourceFile> = new Map();

  constructor(files: Map<string, string>) {
    this.project = new Project({
      useInMemoryFileSystem: true,
      skipAddingFilesFromTsConfig: true,
    });

    for (const [relPath, content] of files.entries()) {
      const normalizedPath = relPath.replace(/\\/g, "/");
      if (
        normalizedPath.endsWith(".ts") ||
        normalizedPath.endsWith(".tsx") ||
        normalizedPath.endsWith(".js") ||
        normalizedPath.endsWith(".jsx")
      ) {
        const sourceFile = this.project.createSourceFile(normalizedPath, content, {
          overwrite: true,
        });
        this.sourceFilesMap.set(normalizedPath, sourceFile);
      }
    }
  }

  public getSourceFile(relativePath: string): SourceFile | undefined {
    return this.sourceFilesMap.get(relativePath.replace(/\\/g, "/"));
  }

  public getImports(relativePath: string): ImportInfo[] {
    const sourceFile = this.getSourceFile(relativePath);
    if (!sourceFile) return [];

    return sourceFile.getImportDeclarations().map((imp) => ({
      moduleSpecifier: imp.getModuleSpecifierValue(),
      defaultImport: imp.getDefaultImport()?.getText(),
      namedImports: imp.getNamedImports().map((ni) => ni.getName()),
    }));
  }

  public getExports(relativePath: string): ExportInfo[] {
    const sourceFile = this.getSourceFile(relativePath);
    if (!sourceFile) return [];

    const exportsList: ExportInfo[] = [];

    // Check export functions/declarations
    for (const fn of sourceFile.getFunctions()) {
      if (fn.isExported()) {
        exportsList.push({
          name: fn.getName() ?? "default",
          isDefault: fn.isDefaultExport(),
        });
      }
    }

    for (const exp of sourceFile.getExportDeclarations()) {
      for (const spec of exp.getNamedExports()) {
        exportsList.push({
          name: spec.getName(),
          isDefault: false,
        });
      }
    }

    return exportsList;
  }

  public findSymbols(symbolName: string): SymbolLocation[] {
    const locations: SymbolLocation[] = [];

    for (const [filePath, sourceFile] of this.sourceFilesMap.entries()) {
      sourceFile.forEachDescendant((node) => {
        if (node.getText() === symbolName) {
          const startPos = node.getStart();
          const { line } = sourceFile.getLineAndColumnAtPos(startPos);
          locations.push({
            filePath,
            line,
            kind: node.getKindName(),
          });
        }
      });
    }

    return locations;
  }
}
