#!/usr/bin/env node
/**
 * TypeScript MCP Client for AI Security Server
 * Supports: stdio (local) and SSE (remote) transports
 * Requires: npm install @modelcontextprotocol/sdk
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { CallToolResult, ListToolsResult, TextContent } from "@modelcontextprotocol/sdk/types.js";

interface ToolInfo {
  name: string;
  description: string;
  schema: Record<string, unknown>;
}

interface ToolCallResult {
  tool: string;
  arguments: Record<string, unknown>;
  output: string;
  isError: boolean;
}

export class SecurityMCPClient {
  private client: Client;
  private transport: StdioClientTransport | SSEClientTransport | null = null;
  public tools: ToolInfo[] = [];

  constructor() {
    this.client = new Client(
      { name: "security-client", version: "1.0.0" },
      { capabilities: {} } as any
    );
  }

  /**
   * Connect via stdio (spawns local server process)
   * Best for: Desktop apps, local development
   */
  async connectStdio(scriptPath: string = "./mcp_security_server.ts"): Promise<void> {
    this.transport = new StdioClientTransport({
      command: "npx",
      args: ["tsx", scriptPath],
      env: { ...process.env, MCP_TRANSPORT: "stdio" }
    });

    await this.client.connect(this.transport);
    console.log("✅ Connected via stdio");
    await this.discoverCapabilities();
  }

  /**
   * Connect via SSE (HTTP Server-Sent Events)
   * Best for: Remote servers, microservices
   */
  async connectSSE(url: string = "http://localhost:3000/sse"): Promise<void> {
    this.transport = new SSEClientTransport(new URL(url));
    await this.client.connect(this.transport);
    console.log(`✅ Connected via SSE to ${url}`);
    await this.discoverCapabilities();
  }

  /**
   * Discover available tools and resources
   */
  private async discoverCapabilities(): Promise<void> {
    const toolsResponse: ListToolsResult = await this.client.listTools();
    this.tools = toolsResponse.tools.map((tool) => ({
      name: tool.name,
      description: tool.description || "",
      schema: tool.inputSchema as Record<string, unknown>
    }));
    console.log(`📦 Discovered ${this.tools.length} tools`);
  }

  /**
   * Call a tool with arguments
   */
  async callTool(toolName: string, args: Record<string, unknown>): Promise<ToolCallResult> {
    console.log(`\n🔧 Calling tool: ${toolName}`);
    console.log(`   Args:`, JSON.stringify(args, null, 2));

    const result = await this.client.callTool({
      name: toolName,
      arguments: args
    }) as any;

    const contentList = result.content || [];
    const texts = contentList
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text || "");

    return {
      tool: toolName,
      arguments: args,
      output: texts.join("\n"),
      isError: result.isError || false
    };
  }

  /**
   * Read a resource by URI
   */
  async readResource(uri: string): Promise<string> {
    const result = await this.client.readResource({ uri }) as any;
    const contents = result.contents || [];
    const texts = contents
      .map((c: any) => c.text || "")
      .filter(Boolean);
    return texts.join("\n");
  }

  /**
   * Get security policies resource
   */
  async getSecurityPolicies(): Promise<Record<string, unknown>> {
    const text = await this.readResource("security://policies");
    return JSON.parse(text);
  }

  /**
   * Get injection detection patterns resource
   */
  async getInjectionPatterns(): Promise<Record<string, unknown>> {
    const text = await this.readResource("security://injection-patterns");
    return JSON.parse(text);
  }

  /**
   * Close connection
   */
  async close(): Promise<void> {
    await this.client.close();
    console.log("\n🔌 Connection closed");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE USAGE
// ═══════════════════════════════════════════════════════════════════════════════

async function exampleBasicUsage(): Promise<void> {
  const client = new SecurityMCPClient();

  try {
    await client.connectStdio("./mcp_security_server.ts");

    console.log("\n📋 Available Tools:");
    client.tools.forEach((tool) => {
      console.log(`   • ${tool.name}: ${tool.description.slice(0, 60)}...`);
    });

    // Test read_file
    console.log("\n" + "-".repeat(50));
    console.log("📄 TEST 1: read_file");
    const readResult = await client.callTool("read_file", {
      path: "/tmp/test.txt",
      max_size: 1000
    });
    console.log("Result:", readResult.output.slice(0, 500));

    // Test scan_security
    console.log("\n" + "-".repeat(50));
    console.log("🔍 TEST 2: scan_security");
    const scanResult = await client.callTool("scan_security", {
      target: "web-app-1",
      scan_type: "quick"
    });
    console.log("Result:", scanResult.output.slice(0, 500));

    // Read security policies resource
    console.log("\n" + "-".repeat(50));
    console.log("📚 TEST 3: Read security policies");
    const policies = await client.getSecurityPolicies();
    console.log("Policies:", JSON.stringify(policies, null, 2).slice(0, 500));

  } finally {
    await client.close();
  }
}

async function main(): Promise<void> {
  console.log("=".repeat(70));
  console.log("🔒 TypeScript MCP Security Client");
  console.log("=".repeat(70));

  await exampleBasicUsage();
}

main().catch(console.error);
