import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import "dotenv/config";
import { getMealPlan } from "./services/backend.js";

let currentUserToken: string | undefined;

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
      content: [
        {
          type: "text",
          text: "pong from NutriHelp MCP server",
        },
      ],
    };
  }
);

server.registerTool(
  "get_meal_plan",
  {
    title: "Get Meal Plan",
    description: "Retrieve the authenticated user's meal plan",
    inputSchema: {},
  },
  async () => {
    try {
      const mealPlan = await getMealPlan(currentUserToken);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(mealPlan, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text:
              error instanceof Error
                ? error.message
                : "Unknown error",
          },
        ],
      };
    }
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

  const token = authHeader.slice(7).trim();
  if (!token) {
    res.status(401).json({ error: "Bearer token is required." });
    return;
  }

  // The NutriHelp backend remains responsible for validating this token.
  // MCP-specific token verification will be implemented separately.
  currentUserToken = token;

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
