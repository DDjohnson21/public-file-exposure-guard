import { setTimeout as delay } from "node:timers/promises";

export type SurfaceKind = "asset-url" | "bucket-object" | "document-endpoint" | "upload-workflow";
export type ExposureVerdict = "public" | "protected" | "unknown" | "error";

export interface ScanTarget {
  id: string;
  kind: SurfaceKind;
  url: string;
  method?: "GET" | "HEAD";
  notes?: string;
  expectedProtection?: "public" | "private";
}

export interface IndexabilitySignals {
  robotsTag?: string | null;
  xRobotsTag?: string | null;
  cacheControl?: string | null;
  contentType?: string | null;
}

export interface MetadataLeakSignals {
  exposesFilename: boolean;
  exposesStorageProviderHint: boolean;
  exposesInternalPath: boolean;
}

export interface ExposureFinding {
  targetId: string;
  url: string;
  verdict: ExposureVerdict;
  statusCode?: number;
  reachable: boolean;
  indexable: boolean;
  signals: IndexabilitySignals;
  metadata: MetadataLeakSignals;
  summary: string;
}

export interface GuardConfig {
  userAgent: string;
  concurrency: number;
  timeoutMs: number;
  targets: ScanTarget[];
}

const DEFAULT_CONFIG: GuardConfig = {
  userAgent: "public-file-exposure-guard/0.1.0",
  concurrency: 4,
  timeoutMs: 10_000,
  targets: [
    {
      id: "example-doc",
      kind: "document-endpoint",
      url: "https://example.com/documents/sample.pdf",
      method: "HEAD",
      expectedProtection: "private",
      notes: "Replace with real app/document URLs"
    }
  ]
};

export async function probeTarget(target: ScanTarget, config: GuardConfig): Promise<ExposureFinding> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

  try {
    const response = await fetch(target.url, {
      method: target.method ?? "HEAD",
      headers: {
        "user-agent": config.userAgent
      },
      signal: controller.signal,
      redirect: "follow"
    });

    const headers = response.headers;
    const signals: IndexabilitySignals = {
      robotsTag: null,
      xRobotsTag: headers.get("x-robots-tag"),
      cacheControl: headers.get("cache-control"),
      contentType: headers.get("content-type")
    };

    const metadata: MetadataLeakSignals = {
      exposesFilename: /filename=|content-disposition/i.test(headers.get("content-disposition") ?? ""),
      exposesStorageProviderHint: /amazonaws|storage.googleapis|blob.core.windows/i.test(target.url),
      exposesInternalPath: /\/internal\/|\/private\//i.test(target.url)
    };

    const reachable = response.ok || response.status === 403;
    const indexable = !((signals.xRobotsTag ?? "").toLowerCase().includes("noindex"));

    let verdict: ExposureVerdict = "unknown";
    if (response.ok && target.expectedProtection === "private") {
      verdict = "public";
    } else if ((response.status === 401 || response.status === 403) && target.expectedProtection === "private") {
      verdict = "protected";
    } else if (response.ok && target.expectedProtection === "public") {
      verdict = "protected";
    }

    return {
      targetId: target.id,
      url: target.url,
      verdict,
      statusCode: response.status,
      reachable,
      indexable,
      signals,
      metadata,
      summary: buildSummary(target, response.status, verdict, indexable, metadata)
    };
  } catch (error) {
    return {
      targetId: target.id,
      url: target.url,
      verdict: "error",
      reachable: false,
      indexable: false,
      metadata: {
        exposesFilename: false,
        exposesStorageProviderHint: false,
        exposesInternalPath: false
      },
      signals: {
        robotsTag: null,
        xRobotsTag: null,
        cacheControl: null,
        contentType: null
      },
      summary: `Probe failed: ${error instanceof Error ? error.message : "unknown error"}`
    };
  } finally {
    clearTimeout(timeout);
  }
}

export async function scanTargets(config: GuardConfig): Promise<ExposureFinding[]> {
  const findings: ExposureFinding[] = [];

  // TODO: Replace naive sequential batching with a small concurrency pool.
  for (const target of config.targets) {
    findings.push(await probeTarget(target, config));
    await delay(25);
  }

  return findings;
}

export function buildSummary(
  target: ScanTarget,
  statusCode: number | undefined,
  verdict: ExposureVerdict,
  indexable: boolean,
  metadata: MetadataLeakSignals
): string {
  const parts = [
    `target=${target.id}`,
    `kind=${target.kind}`,
    `status=${statusCode ?? "n/a"}`,
    `verdict=${verdict}`,
    `indexable=${indexable}`
  ];

  if (metadata.exposesFilename) parts.push("filename-exposed=true");
  if (metadata.exposesStorageProviderHint) parts.push("provider-hint=true");
  if (metadata.exposesInternalPath) parts.push("internal-path=true");

  return parts.join(" ");
}

export function printReport(findings: ExposureFinding[]): void {
  const highRisk = findings.filter((item) => item.verdict === "public" || item.indexable);

  console.log("public-file-exposure-guard report");
  console.log(`findings=${findings.length} highRisk=${highRisk.length}`);

  for (const finding of findings) {
    console.log(`- ${finding.summary}`);
  }

  // TODO: Add JSON, SARIF, and webhook reporters.
}

export async function main(config: GuardConfig = DEFAULT_CONFIG): Promise<void> {
  // TODO: Load config from file/env/CLI flags.
  // TODO: Add workflow-aware discovery to generate targets from app routes and storage manifests.
  const findings = await scanTargets(config);
  printReport(findings);

  const hasUnexpectedPublicExposure = findings.some(
    (finding) => finding.verdict === "public"
  );

  if (hasUnexpectedPublicExposure) {
    process.exitCode = 1;
  }
}

if (import.meta.main) {
  void main();
}
