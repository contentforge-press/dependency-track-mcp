// Minimal Dependency-Track API client with efficient, bounded pagination.
export interface DTClientOptions {
  baseUrl: string;
  apiKey: string;
  // Cap on how many pages a single aggregation may walk. Protects against
  // accidental runaway scans over huge portfolios.
  maxPages?: number;
  pageSize?: number;
  concurrency?: number;
  fetchImpl?: typeof fetch;
}

export interface Finding {
  project?: { uuid?: string; name?: string; version?: string };
  component?: { uuid?: string; name?: string; version?: string };
  vulnerability?: {
    uuid?: string; vulnId?: string; severity?: string;
    source?: string; description?: string;
  };
  analysis?: { state?: string; isSuppressed?: boolean };
  matrix?: string;
}

export interface Project {
  uuid: string;
  name: string;
  version?: string;
  active?: boolean;
  tags?: { name: string }[];
  lastBomImport?: string;
  metrics?: { critical?: number; high?: number };
}

export class DTError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'DTError';
  }
}

export class DependencyTrackClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly maxPages: number;
  private readonly pageSize: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: DTClientOptions) {
    if (!opts.baseUrl) throw new Error('baseUrl is required');
    if (!opts.apiKey) throw new Error('apiKey is required');
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.apiKey = opts.apiKey;
    this.maxPages = opts.maxPages ?? 100;
    this.pageSize = opts.pageSize ?? 100;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await this.fetchImpl(this.baseUrl + path, {
      headers: { Accept: 'application/json', 'X-API-Key': this.apiKey },
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new DTError(res.status, `DT API ${res.status} on ${path}: ${text.slice(0, 200)}`);
    }
    return res.json() as Promise<T>;
  }

  // List projects using the paginated /v1/project endpoint.
  async listProjects(opts: { name?: string; activeOnly?: boolean } = {}): Promise<Project[]> {
    const out: Project[] = [];
    for (let page = 1; page <= this.maxPages; page++) {
      const params = new URLSearchParams({ page: String(page), limit: String(this.pageSize) });
      if (opts.name) params.set('name', opts.name);
      const batch = await this.get<Project[]>(`/v1/project?${params}`);
      if (!Array.isArray(batch) || batch.length === 0) break;
      for (const p of batch) {
        if (opts.activeOnly && p.active === false) continue;
        out.push(p);
      }
      if (batch.length < this.pageSize) break;
    }
    return out;
  }

  // Findings are returned in one call per project, already aggregated by DT.
  async getProjectFindings(projectUuid: string): Promise<Finding[]> {
    return this.get<Finding[]>(
      `/v1/finding/project/${encodeURIComponent(projectUuid)}?suppressed=false`,
    );
  }
}
