// High-level aggregate tools: answer the questions users actually ask without
// forcing an LLM to walk thousands of REST pages itself.
import { DependencyTrackClient, type Finding, type Project } from './client.js';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNASSIGNED';

const SEV_RANK: Record<string, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNASSIGNED: 0,
};

// DT analysis states that mean a finding is already handled.
const RESOLVED_STATES = new Set([
  'RESOLVED', 'FALSE_POSITIVE', 'NOT_AFFECTED',
]);

export function isOpenFinding(f: Finding): boolean {
  if (f.analysis?.isSuppressed) return false;
  const state = f.analysis?.state;
  if (state && RESOLVED_STATES.has(state)) return false;
  return true;
}

export function severityAtLeast(sev: string | undefined, min: Severity): boolean {
  const a = SEV_RANK[(sev || 'UNASSIGNED').toUpperCase()] ?? 0;
  return a >= SEV_RANK[min];
}

export interface VulnSummary {
  totalOpen: number;
  bySeverity: Record<string, number>;
  suppressedOrResolved: number;
}

export function summarizeFindings(findings: Finding[], minSeverity: Severity = 'LOW'): VulnSummary {
  const bySeverity: Record<string, number> = {};
  let totalOpen = 0;
  let handled = 0;
  for (const f of findings) {
    if (!isOpenFinding(f)) {
      handled += 1;
      continue;
    }
    if (!severityAtLeast(f.vulnerability?.severity, minSeverity)) continue;
    const sev = (f.vulnerability?.severity || 'UNASSIGNED').toUpperCase();
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    totalOpen += 1;
  }
  return { totalOpen, bySeverity, suppressedOrResolved: handled };
}

export interface ProjectRisk {
  projectUuid: string;
  projectName: string;
  version?: string;
  open: VulnSummary;
  criticalFindings: Finding[];
}

// Portfolio-wide rollup. Projects are fetched in pages by the client and
// findings are DT-side aggregated per project (no manual vuln pagination),
// so this scales where a 1:1 REST proxy would not.
export async function portfolioRiskOverview(
  client: DependencyTrackClient,
  opts: { minSeverity?: Severity; limit?: number; activeOnly?: boolean } = {},
): Promise<{ projectsScanned: number; projects: ProjectRisk[]; portfolio: VulnSummary }> {
  const minSeverity = opts.minSeverity ?? 'HIGH';
  const projects: Project[] = await client.listProjects({ activeOnly: opts.activeOnly });
  const selected = opts.limit ? projects.slice(0, opts.limit) : projects;

  const portfolio: VulnSummary = { totalOpen: 0, bySeverity: {}, suppressedOrResolved: 0 };
  const risks: ProjectRisk[] = [];

  for (const p of selected) {
    const findings = await client.getProjectFindings(p.uuid);
    const open = summarizeFindings(findings, minSeverity);
    if (open.totalOpen === 0) continue;
    const criticalFindings = findings.filter(
      (f) => isOpenFinding(f) && severityAtLeast(f.vulnerability?.severity, minSeverity),
    );
    risks.push({
      projectUuid: p.uuid, projectName: p.name, version: p.version,
      open, criticalFindings,
    });
    portfolio.totalOpen += open.totalOpen;
    portfolio.suppressedOrResolved += open.suppressedOrResolved;
    for (const [sev, n] of Object.entries(open.bySeverity)) {
      portfolio.bySeverity[sev] = (portfolio.bySeverity[sev] ?? 0) + n;
    }
  }

  risks.sort(
    (a, b) =>
      (b.open.bySeverity.CRITICAL ?? 0) - (a.open.bySeverity.CRITICAL ?? 0) ||
      (b.open.bySeverity.HIGH ?? 0) - (a.open.bySeverity.HIGH ?? 0),
  );

  return { projectsScanned: selected.length, projects: risks, portfolio };
}
