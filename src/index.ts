#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema, ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { DependencyTrackClient } from './client.js';
import { portfolioRiskOverview, type Severity } from './aggregate.js';

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required environment variable: ${name}`);
  return v;
}

const client = new DependencyTrackClient({
  baseUrl: process.env.DEPENDENCY_TRACK_URL ?? '',
  apiKey: process.env.DEPENDENCY_TRACK_API_KEY ?? '',
});

const server = new Server(
  { name: 'dependency-track-mcp', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'portfolio_risk_overview',
      description:
        'Portfolio-wide open vulnerability rollup across projects. Efficiently aggregates Dependency-Track findings (no client-side pagination), sorted by critical/high exposure. Returns per-project severity buckets and a portfolio total.',
      inputSchema: {
        type: 'object',
        properties: {
          minSeverity: {
            type: 'string',
            enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            description: 'Only include open findings at or above this severity.',
            default: 'HIGH',
          },
          activeOnly: { type: 'boolean', default: true },
          limit: { type: 'number', description: 'Optional cap on number of projects scanned.' },
        },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  if (name !== 'portfolio_risk_overview') {
    throw new Error(`Unknown tool: ${name}`);
  }
  const a = (args ?? {}) as { minSeverity?: Severity; activeOnly?: boolean; limit?: number };
  const result = await portfolioRiskOverview(client, {
    minSeverity: a.minSeverity ?? 'HIGH',
    activeOnly: a.activeOnly ?? true,
    limit: a.limit,
  });
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            projectsScanned: result.projectsScanned,
            portfolio: result.portfolio,
            topProjects: result.projects.slice(0, 25).map((p) => ({
              name: p.projectName,
              version: p.version,
              open: p.open,
            })),
          },
          null,
          2,
        ),
      },
    ],
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
