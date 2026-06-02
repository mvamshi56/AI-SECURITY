# AI Security MCP Server Integration Guide

This guide explains how to integrate and use the **AI Security MCP Server** inside external AI assistants and client applications such as **Claude Desktop**, **Cursor**, **Cline (VS Code)**, or your own custom applications.

---

## 🚀 Architectural Overview
The AI Security MCP Server functions as a security middleware gateway. When an LLM client requests a tool execution (like executing a shell command or reading sensitive files), the command goes through our security layers:

```
[ LLM Client ] ──(Calls Tool)──> [ MCP Server Pipeline ]
                                        │
                                        ▼
                             1. Input Schema Check (Zod)
                                        │
                                        ▼
                             2. Prompt Injection Shield
                                        │
                                        ▼
                             3. Role-Based Auth Checking
                                        │
                                        ▼
                             4. Human-In-The-Loop Approval
                                        │
                                        ▼
                             5. Audit Logging Append
                                        │
                                        ▼
                              [ Physical Execution ]
```

---

## 🛠️ Prerequisites
Ensure you have the following installed on your machine:
* **Node.js** (v18 or higher)
* **npm** (v9 or higher)

Before connecting clients, install dependencies in your local project directory:
```bash
npm install
```

---

## 🖥️ 1. Connecting to Claude Desktop
Claude Desktop supports local MCP servers connected over **standard I/O (stdio)**. You configure them via a central JSON file.

### Configuration Path
Open your Claude Desktop configuration file:
* **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
* **Linux:** `~/.config/Claude/claude_desktop_config.json`

### JSON Snippet
Add the security server inside the `mcpServers` object. *Replace `/absolute/path/to/your/project` with your real workspace directory.*

```json
{
  "mcpServers": {
    "security-gateway": {
      "command": "npx",
      "args": [
        "tsx",
        "/absolute/path/to/your/project/mcp_security_server.ts"
      ],
      "env": {
        "NODE_ENV": "development",
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
      }
    }
  }
}
```

### Testing step:
1. Save the file.
2. Restart Claude Desktop completely (Quit the app and reopen).
3. Click the **plug icon** 🔌 in the Claude prompt field to verify `read_file`, `execute_command`, `send_email`, and `scan_security` are listed and protected!

---

## 🚀 2. Connecting to Cursor
Cursor includes native support for stdio-based MCP Servers.

### How to configure:
1. Open **Cursor Settings** (`Cmd + ,` or click gear icon in top right).
2. Go to **Features** in the sidebar.
3. Scroll down to the **Model Context Protocol (MCP)** section.
4. Click **+ Add New MCP Server**.
5. Fill out the dialog with:
   * **Name:** `Security Gateway`
   * **Type:** `command`
   * **Command:** `npx tsx "/absolute/path/to/your/project/mcp_security_server.ts"`
6. Click **Save**.
7. Cursor will spawn the server process instantly. Look for the green **Active** status bullet indicator next to the server name.

---

## 🧩 3. Connecting to Cline (VS Code Extension)
If you use Cline in VS Code, you can register the MCP Server dynamically.

### How to configure:
Cline maintains its configuration inside a local extension settings file:
* **Path:** `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`

Add the following to your settings file:
```json
{
  "mcpServers": {
    "security-gateway": {
      "command": "npx",
      "args": [
        "tsx",
        "/absolute/path/to/your/project/mcp_security_server.ts"
      ]
    }
  }
}
```

---

## 📟 4. Programming Custom Clients
If you want to build a custom application that pulls data from this security gateway, you can import our pre-built `SecurityMCPClient` class.

### TypeScript / JavaScript Integration:
```typescript
import { SecurityMCPClient } from "./typescript_mcp_client";

async function run() {
  const client = new SecurityMCPClient();
  
  // Connect over local processes
  await client.connectStdio("./mcp_security_server.ts");
  
  // Call read_file (this will trigger schema and path checks)
  const result = await client.callTool("read_file", {
    path: "./package.json",
    max_size: 1000
  });
  
  console.log("Response:", result.output);
  await client.close();
}

run().catch(console.error);
```

### Python Integration:
You can also connect to this server from Python using the official `mcp` library:

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="npx",
        args=["tsx", "/absolute/path/to/mcp_security_server.ts"]
    )
    
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize connection
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print("Tools:", [t.name for t in tools.tools])
            
            # Call tool
            response = await session.call_tool("read_file", {
                "path": "test.txt",
                "max_size": 2048
            })
            print("Result:", response.content)

asyncio.run(main())
```

---

## 🔒 Security Middleware Customization
When utilizing this server, you can pass custom token credentials to authenticate different user levels:

* **Low/Medium clearance user:** Access is restricted. Attempting dangerous commands (like `execute_command`) is immediately rejected before physical subprocess calls are issued.
* **Admin clearance user:** Full command execution clearances, but prompts containing **jailbreaks** or **prompt injections** are blocked immediately.
* **Human-In-The-Loop Approval:** For high-stakes tools, request approvals are logged and can be interactive.

You can modify these policies inside `mcp_security_server.ts` by editing the `POLICIES` map in `AuthorizationManager`.

---

## 🔍 Troubleshooting Connection Issues
1. **Server fails with `tsx: not found`**
   Ensure dependencies are fully installed locally:
   ```bash
   npm install tsx @modelcontextprotocol/sdk zod
   ```
2. **Absolute Paths require double quotes**
   In Windows configuration files, replace backward slashes with forward slashes or escape them properly (`\\\\`):
   `C:/Users/username/project/mcp_security_server.ts`
3. **Check the logs**
   The MCP Security server automatically writes security operations logs, validation denials, and command results to `mcp_audit.log` in the server root.
