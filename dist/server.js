"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const streamableHttp_js_1 = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const validateSupabaseToken_js_1 = require("./auth/validateSupabaseToken.js");
require("dotenv/config");
const server = new mcp_js_1.McpServer({
    name: "nutrihelp-mcp-server",
    version: "0.1.0",
});
server.registerTool("ping", {
    title: "Ping",
    description: "Simple test tool to confirm the MCP server is working",
    inputSchema: {},
}, async () => {
    return {
        content: [{ type: "text", text: "pong from NutriHelp MCP server" }],
    };
});
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.post("/mcp", async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
        res.status(401).json({ error: "Bearer token is required." });
        return;
    }
    try {
        const token = authHeader.slice(7).trim();
        await (0, validateSupabaseToken_js_1.validateSupabaseToken)(token);
    }
    catch {
        res.status(401).json({ error: "Invalid or expired token." });
        return;
    }
    const transport = new streamableHttp_js_1.StreamableHTTPServerTransport({
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
