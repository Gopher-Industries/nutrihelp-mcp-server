import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { validateSupabaseToken } from "./auth/validateSupabaseToken.js";
import "dotenv/config";
const server = new McpServer({
  name: "nutrihelp-mcp-server",
  version: "0.1.0",
});

server.registerTool(
  "ping",
  {
    title: "Ping",
    description: "Simple test tool to confirm the MCP server is working",
    inputSchema: {},
  },
  async () => {
    return {
      content: [{ type: "text", text: "pong from NutriHelp MCP server" }],
    };
  }
);

const app = express();
app.use(express.json());

app.post("/mcp", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Bearer token is required." });
    return;
  }

  try {
    const token = authHeader.slice(7).trim();
    await validateSupabaseToken(token);
  } catch {
    res.status(401).json({ error: "Invalid or expired token." });
    return;
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  res.on("close", () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`NutriHelp MCP server listening on http://localhost:${PORT}/mcp`);
});
