import { createMcpHandler } from "agents/mcp/server";
import { McpServer } from "@modelcontextprotocol/server";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";

const REQUIRED = [
  "FEISHU_APP_ID",
  "FEISHU_APP_SECRET",
  "FEISHU_APP_TOKEN",
  "FEISHU_TABLE_ID",
  "MCP_URL",
  "AUTH0_ISSUER",
  "AUTH0_JWKS_URL",
  "ALLOWED_AUTH0_SUB",
];
const READ_SCOPE = "bitable.read";
const MAX_SCAN = 1000;
const MAX_RESULTS = 50;
const HOSTNAME = "feishu-bitable-mcp.zhihuishi33.workers.dev";
let feishuTokenCache;
let jwksCache;

function configurationError(env) {
  const missing = REQUIRED.filter((key) => !env[key]);
  if (missing.length) return `Missing configuration: ${missing.join(", ")}`;
  const resource = new URL(env.MCP_URL);
  const issuer = new URL(env.AUTH0_ISSUER);
  const jwks = new URL(env.AUTH0_JWKS_URL);
  if (
    resource.protocol !== "https:" ||
    resource.hostname !== HOSTNAME ||
    resource.pathname !== "/mcp" ||
    issuer.protocol !== "https:" ||
    jwks.protocol !== "https:" ||
    jwks.origin !== issuer.origin
  ) {
    return "Invalid MCP or Auth0 URL configuration";
  }
  return null;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

function challenge(env, description = "Authentication required") {
  const metadata = `${new URL(env.MCP_URL).origin}/.well-known/oauth-protected-resource`;
  return json(
    { error: "unauthorized", error_description: description },
    401,
    {
      "WWW-Authenticate": `Bearer resource_metadata="${metadata}", scope="${READ_SCOPE}"`,
      "Cache-Control": "no-store",
    },
  );
}

async function authorize(request, env) {
  const match = /^Bearer (\S+)$/i.exec(request.headers.get("Authorization") || "");
  if (!match) return false;
  try {
    const jwksUrl = env.AUTH0_JWKS_URL;
    if (!jwksCache || jwksCache.url !== jwksUrl) {
      jwksCache = { url: jwksUrl, keys: createRemoteJWKSet(new URL(jwksUrl)) };
    }
    const { payload } = await jwtVerify(match[1], jwksCache.keys, {
      issuer: env.AUTH0_ISSUER,
      audience: env.MCP_URL,
      algorithms: ["RS256"],
    });
    const scopes = new Set(String(payload.scope || "").split(/\s+/));
    return payload.sub === env.ALLOWED_AUTH0_SUB && scopes.has(READ_SCOPE);
  } catch {
    return false;
  }
}

async function tenantToken(env) {
  if (feishuTokenCache && feishuTokenCache.until > Date.now()) {
    return feishuTokenCache.value;
  }
  const response = await fetch(
    "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ app_id: env.FEISHU_APP_ID, app_secret: env.FEISHU_APP_SECRET }),
    },
  );
  const body = await response.json();
  if (!response.ok || body.code !== 0 || !body.tenant_access_token) {
    throw new Error(`Feishu token request failed (code ${body.code ?? response.status})`);
  }
  feishuTokenCache = {
    value: body.tenant_access_token,
    until: Date.now() + Math.max(30, Number(body.expire || 7200) - 120) * 1000,
  };
  return feishuTokenCache.value;
}

async function feishuGet(env, path, params = {}) {
  const url = new URL(`https://open.feishu.cn/open-apis/bitable/v1/${path}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") url.searchParams.set(key, String(value));
  }
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${await tenantToken(env)}` },
  });
  const body = await response.json();
  if (!response.ok || body.code !== 0) {
    throw new Error(`Feishu API request failed (code ${body.code ?? response.status})`);
  }
  return body.data || {};
}

function toolResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value) }] };
}

function safeTool(callback) {
  return async (args) => {
    try {
      return toolResult(await callback(args));
    } catch (error) {
      return {
        content: [{ type: "text", text: error instanceof Error ? error.message : "Request failed" }],
        isError: true,
      };
    }
  };
}

function createServer(env) {
  const server = new McpServer({ name: "feishu-bitable-readonly", version: "1.0.0" });
  const securitySchemes = [{ type: "oauth2", scopes: [READ_SCOPE] }];
  const appPath = `apps/${encodeURIComponent(env.FEISHU_APP_TOKEN)}`;
  const recordPath = `${appPath}/tables/${encodeURIComponent(env.FEISHU_TABLE_ID)}/records`;

  server.registerTool(
    "list_bitable_tables",
    {
      description: "List the one Feishu Bitable table authorized for this MCP server.",
      inputSchema: {},
      securitySchemes,
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => {
      let pageToken;
      do {
        const data = await feishuGet(env, `${appPath}/tables`, {
          page_size: 100,
          page_token: pageToken,
        });
        const table = (data.items || []).find((item) => item.table_id === env.FEISHU_TABLE_ID);
        if (table) return { tables: [table] };
        pageToken = data.has_more ? data.page_token : undefined;
      } while (pageToken);
      return { tables: [] };
    }),
  );

  server.registerTool(
    "get_bitable_records",
    {
      description: "Read one page of records from the designated Feishu Bitable table.",
      inputSchema: {
        page_size: z.number().int().min(1).max(100).optional(),
        page_token: z.string().max(1000).optional(),
      },
      securitySchemes,
      annotations: { readOnlyHint: true },
    },
    safeTool(async ({ page_size = 100, page_token }) => {
      const data = await feishuGet(env, recordPath, { page_size, page_token });
      return {
        records: data.items || [],
        has_more: Boolean(data.has_more),
        next_page_token: data.page_token || null,
        total: data.total ?? null,
      };
    }),
  );

  server.registerTool(
    "search_bitable_records",
    {
      description: `Case-insensitive text search in the designated table. Scans at most ${MAX_SCAN} records and returns at most ${MAX_RESULTS} matches; incomplete indicates more records may exist.`,
      inputSchema: { query: z.string().trim().min(1).max(200) },
      securitySchemes,
      annotations: { readOnlyHint: true },
    },
    safeTool(async ({ query }) => {
      const needle = query.toLocaleLowerCase();
      const records = [];
      let scanned = 0;
      let pageToken;
      let hasMore = false;
      do {
        const data = await feishuGet(env, recordPath, {
          page_size: Math.min(100, MAX_SCAN - scanned),
          page_token: pageToken,
        });
        const items = data.items || [];
        scanned += items.length;
        for (const item of items) {
          if (JSON.stringify(item.fields || {}).toLocaleLowerCase().includes(needle)) {
            records.push(item);
            if (records.length >= MAX_RESULTS) break;
          }
        }
        hasMore = Boolean(data.has_more);
        pageToken = hasMore ? data.page_token : undefined;
      } while (pageToken && scanned < MAX_SCAN && records.length < MAX_RESULTS);
      return {
        records,
        scanned,
        incomplete: hasMore || scanned >= MAX_SCAN || records.length >= MAX_RESULTS,
      };
    }),
  );

  return server;
}

export default {
  async fetch(request, env, ctx) {
    let error;
    try {
      error = configurationError(env);
    } catch {
      error = "Invalid configuration";
    }
    if (error) {
  console.error("Worker configuration:", error);
  return json({ error: "service_not_configured" }, 503);
}

    const url = new URL(request.url);
    if (url.hostname !== HOSTNAME) return json({ error: "invalid_host" }, 400);
    if (url.pathname === "/.well-known/oauth-protected-resource" && request.method === "GET") {
      return json({
        resource: env.MCP_URL,
        authorization_servers: [env.AUTH0_ISSUER],
        scopes_supported: [READ_SCOPE],
      });
    }
    if (url.pathname !== "/mcp") return json({ error: "not_found" }, 404);
    if (!(await authorize(request, env))) return challenge(env);
    return createMcpHandler(() => createServer(env), {
      route: "/mcp",
      allowedHostnames: [HOSTNAME],
      responseMode: "json",
    })(request, env, ctx);
  },
};
