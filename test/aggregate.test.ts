import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isOpenFinding, severityAtLeast, summarizeFindings, portfolioRiskOverview,
} from '../src/aggregate.js';
import { DependencyTrackClient, type Finding, type Project } from '../src/client.js';

function f(sev: string, state?: string, suppressed = false): Finding {
  return {
    vulnerability: { vulnId: 'CVE-X', severity: sev },
    analysis: state ? { state, isSuppressed: suppressed } : { isSuppressed: suppressed },
  };
}

test('isOpenFinding excludes suppressed and resolved states', () => {
  assert.equal(isOpenFinding(f('HIGH')), true);
  assert.equal(isOpenFinding(f('HIGH', 'RESOLVED')), false);
  assert.equal(isOpenFinding(f('HIGH', 'FALSE_POSITIVE')), false);
  assert.equal(isOpenFinding(f('HIGH', 'NOT_AFFECTED')), false);
  assert.equal(isOpenFinding(f('HIGH', 'EXPLOITABLE')), true);
  assert.equal(isOpenFinding(f('HIGH', undefined, true)), false);
});

test('severityAtLeast compares ranks', () => {
  assert.equal(severityAtLeast('CRITICAL', 'HIGH'), true);
  assert.equal(severityAtLeast('LOW', 'HIGH'), false);
  assert.equal(severityAtLeast(undefined, 'LOW'), false);
});

test('summarizeFindings buckets open findings and counts handled', () => {
  const s = summarizeFindings([
    f('CRITICAL'), f('CRITICAL'), f('HIGH'), f('MEDIUM'),
    f('HIGH', 'RESOLVED'), f('LOW', undefined, true),
  ], 'HIGH');
  assert.equal(s.totalOpen, 3); // 2 critical + 1 high
  assert.equal(s.bySeverity.CRITICAL, 2);
  assert.equal(s.bySeverity.HIGH, 1);
  assert.equal(s.suppressedOrResolved, 2);
});

// Fake client to prove the portfolio rollup without any network.
class FakeClient extends DependencyTrackClient {
  constructor(private projects: Project[], private findingsByProject: Record<string, Finding[]>) {
    super({ baseUrl: 'http://dt', apiKey: 'k' });
  }
  override async listProjects() { return this.projects; }
  override async getProjectFindings(uuid: string) { return this.findingsByProject[uuid] ?? []; }
}

test('portfolioRiskOverview aggregates and sorts projects', async () => {
  const projects: Project[] = [
    { uuid: 'a', name: 'alpha' },
    { uuid: 'b', name: 'beta' },
  ];
  const findings = {
    a: [f('HIGH')],
    b: [f('CRITICAL'), f('CRITICAL'), f('LOW', 'RESOLVED')],
  };
  const r = await portfolioRiskOverview(new FakeClient(projects, findings), { minSeverity: 'HIGH' });
  assert.equal(r.projectsScanned, 2);
  assert.equal(r.portfolio.totalOpen, 3);
  assert.equal(r.projects[0].projectName, 'beta'); // more critical first
  assert.equal(r.projects[0].open.bySeverity.CRITICAL, 2);
});
