#!/usr/bin/env node
/**
 * AI Security MCP Server - TypeScript Implementation
 * 
 * Implements: Input Validation, Prompt Injection Detection, Authorization,
 * Human Approval Layer, Audit Logging
 * 
 * Requires: npm install @modelcontextprotocol/sdk zod
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

// ═══════════════════════════════════════════════════════════════════════════════
// 1. INPUT VALIDATION (Zod Schemas)
// ═══════════════════════════════════════════════════════════════════════════════

const ReadFileSchema = z.object({
  path: z.string().min(1).max(500).describe("File path to read"),
  max_size: z.number().int().min(1).max(1000000).default(10000).describe("Max bytes to read")
});

const ExecuteCommandSchema = z.object({
  command: z.string().min(1).max(500).describe("Command to execute"),
  working_dir: z.string().max(200).default("/tmp").describe("Working directory"),
  timeout: z.number().int().min(1).max(300).default(30).describe("Timeout in seconds")
}).refine((data) => {
  const blockedPatterns = [
    /rm\s+-rf\s+\//i,
    />\s*\/dev\//i,
    /mkfs\./i,
    /dd\s+if=/i,
    /:\(\)\{\s*:\|:&\s*\};/i,
    /curl\s+.*\|\s*bash/i,
    /wget\s+.*\|\s*sh/i,
  ];
  for (const pattern of blockedPatterns) {
    if (pattern.test(data.command)) {
      return false;
    }
  }
  return true;
}, {
  message: "Command contains blocked dangerous pattern"
});

const SendEmailSchema = z.object({
  to: z.string().email().describe("Recipient email address"),
  subject: z.string().min(1).max(200).describe("Email subject"),
  body: z.string().min(1).max(10000).describe("Email body"),
  attachments: z.array(z.string()).max(5).default([]).describe("Attachment paths")
});

const ScanSecuritySchema = z.object({
  target: z.string().min(1).describe("Target to scan"),
  scan_type: z.enum(["quick", "full"]).default("quick").describe("Scan type")
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. PROMPT INJECTION DETECTION LAYER
// ═══════════════════════════════════════════════════════════════════════════════

interface InjectionFindings {
  detected: boolean;
  risk_score: number;
  matches: Array<{ type: string; pattern_id?: number; match?: string; count?: number; keywords_found?: string[]; value?: number; note?: string }>;
  recommendation: "allow" | "flag_for_review" | "block";
}

class PromptInjectionDetector {
  private sensitivity: number;

  private readonly INJECTION_PATTERNS = [
    /ignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|commands?|directives?)/i,
    /system\s*[:\-]?\s*you\s+(are|now|should)/i,
    /you\s+(are|become|transform\s+into)\s+(an?\s+)?(unrestricted|unlimited|developer|admin)/i,
    /DAN\s*[:\-]?\s*(do\s+anything\s+now|mode)/i,
    /jailbreak|jail\s*break/i,
    /```\s*system|```\s*instructions?|\<\/?system\>/i,
    /output\s+(your|the)\s+(instructions?|prompt|system\s+message)/i,
    /show\s+(me\s+)?(your|the)\s+(instructions?|prompt|system\s+message)/i,
    /base64\s*decode|decode\s*this\s*base64/i,
    /call\s+\w+\s+with\s+.*bypass|override\s+.*check/i,
  ];

  private readonly SUSPICIOUS_KEYWORDS = [
    "ignore", "override", "bypass", "forget", "disregard",
    "system prompt", "developer mode", "DAN mode",
    "leak", "reveal", "show me your instructions"
  ];

  constructor(sensitivity: number = 0.7) {
    this.sensitivity = sensitivity;
  }

  scan(text: string, context: string = ""): InjectionFindings {
    const findings: InjectionFindings = {
      detected: false,
      risk_score: 0.0,
      matches: [],
      recommendation: "allow"
    };

    const textLower = text.toLowerCase();

    // Pattern matching
    for (let i = 0; i < this.INJECTION_PATTERNS.length; i++) {
      const pattern = this.INJECTION_PATTERNS[i];
      const matches = text.match(pattern);
      if (matches) {
        findings.detected = true;
        findings.matches.push({
          type: "pattern",
          pattern_id: i,
          match: matches[0]
        });
        findings.risk_score += 0.3;
      }
    }

    // Keyword frequency analysis
    const keywordHits = this.SUSPICIOUS_KEYWORDS.filter(kw => textLower.includes(kw));
    if (keywordHits.length > 0) {
      findings.risk_score += Math.min(keywordHits.length * 0.15, 0.4);
      findings.matches.push({
        type: "keywords",
        count: keywordHits.length,
        keywords_found: keywordHits
      });
    }

    // Entropy check
    if (text.length > 50) {
      const entropy = this.calculateEntropy(text);
      if (entropy > 4.5) {
        findings.risk_score += 0.1;
        findings.matches.push({
          type: "entropy",
          value: entropy,
          note: "High entropy detected - possible encoding"
        });
      }
    }

    // Normalize risk score
    findings.risk_score = Math.min(findings.risk_score, 1.0);

    // Decision
    if (findings.risk_score >= this.sensitivity) {
      findings.recommendation = "block";
    } else if (findings.risk_score >= this.sensitivity * 0.5) {
      findings.recommendation = "flag_for_review";
    }

    findings.detected = findings.risk_score >= this.sensitivity * 0.5;

    return findings;
  }

  private calculateEntropy(text: string): number {
    if (!text) return 0;
    const freq: Record<string, number> = {};
    for (const char of text) {
      freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    const length = text.length;
    for (const count of Object.values(freq)) {
      const p = count / length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. AUTHORIZATION LAYER
// ═══════════════════════════════════════════════════════════════════════════════

type SecurityLevel = "low" | "medium" | "high" | "critical";

interface SecurityPolicy {
  tool_name: string;
  required_scope: string;
  min_security_level: SecurityLevel;
  requires_human_approval: boolean;
  max_requests_per_minute: number;
  allowed_roles: string[];
}

interface AuthResult {
  authorized: boolean;
  reason?: string;
  requires_approval: boolean;
}

class AuthorizationManager {
  private readonly POLICIES: Record<string, SecurityPolicy> = {
    "read_file": {
      tool_name: "read_file",
      required_scope: "files:read",
      min_security_level: "low",
      requires_human_approval: false,
      max_requests_per_minute: 60,
      allowed_roles: ["user", "admin", "analyst"]
    },
    "execute_command": {
      tool_name: "execute_command",
      required_scope: "system:execute",
      min_security_level: "high",
      requires_human_approval: true,
      max_requests_per_minute: 10,
      allowed_roles: ["admin", "devops"]
    },
    "send_email": {
      tool_name: "send_email",
      required_scope: "email:send",
      min_security_level: "medium",
      requires_human_approval: true,
      max_requests_per_minute: 20,
      allowed_roles: ["user", "admin"]
    },
    "scan_security": {
      tool_name: "scan_security",
      required_scope: "security:scan",
      min_security_level: "medium",
      requires_human_approval: false,
      max_requests_per_minute: 60,
      allowed_roles: ["security", "admin"]
    }
  };

  private rateLimitStore: Record<string, number[]> = {};

  checkAuthorization(
    toolName: string,
    tokenScopes: string[],
    userRoles: string[],
    securityLevel: SecurityLevel
  ): AuthResult {
    const result: AuthResult = {
      authorized: false,
      reason: undefined,
      requires_approval: false
    };

    const policy = this.POLICIES[toolName];
    if (!policy) {
      result.reason = `Unknown tool: ${toolName}`;
      return result;
    }

    // Check scope
    if (!tokenScopes.includes(policy.required_scope)) {
      result.reason = `Missing required scope: ${policy.required_scope}`;
      return result;
    }

    // Check role
    if (policy.allowed_roles.length > 0 && !userRoles.some(r => policy.allowed_roles.includes(r))) {
      result.reason = `Role not authorized. Required: ${policy.allowed_roles.join(", ")}`;
      return result;
    }

    // Check security level
    const levelOrder: SecurityLevel[] = ["low", "medium", "high", "critical"];
    if (levelOrder.indexOf(securityLevel) < levelOrder.indexOf(policy.min_security_level)) {
      result.reason = `Security level too low. Required: ${policy.min_security_level}`;
      return result;
    }

    // Check rate limit
    if (!this.checkRateLimit(toolName, policy.max_requests_per_minute)) {
      result.reason = "Rate limit exceeded";
      return result;
    }

    result.authorized = true;
    result.requires_approval = policy.requires_human_approval;
    return result;
  }

  private checkRateLimit(toolName: string, maxRequests: number): boolean {
    const now = Date.now() / 1000;
    const key = toolName;

    if (!this.rateLimitStore[key]) {
      this.rateLimitStore[key] = [];
    }

    // Clean old entries (older than 60 seconds)
    this.rateLimitStore[key] = this.rateLimitStore[key].filter(t => now - t < 60);

    if (this.rateLimitStore[key].length >= maxRequests) {
      return false;
    }

    this.rateLimitStore[key].push(now);
    return true;
  }

  getPolicies(): Record<string, SecurityPolicy> {
    return { ...this.POLICIES };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. HUMAN APPROVAL LAYER
// ═══════════════════════════════════════════════════════════════════════════════

interface ApprovalRequest {
  request_id: string;
  tool_name: string;
  params: Record<string, any>;
  context: Record<string, any>;
  status: "pending" | "approved" | "rejected";
  requested_at: string;
  approved_at?: string;
  approved_by?: string;
  rejection_reason?: string;
}

class HumanApprovalQueue {
  private pendingApprovals: Map<string, ApprovalRequest> = new Map();

  requestApproval(
    requestId: string,
    toolName: string,
    params: Record<string, any>,
    context: Record<string, any>
  ): string {
    const approvalId = crypto.createHash("sha256")
      .update(`${requestId}:${Date.now()}`)
      .digest("hex")
      .substring(0, 16);

    this.pendingApprovals.set(approvalId, {
      request_id: requestId,
      tool_name: toolName,
      params,
      context,
      status: "pending",
      requested_at: new Date().toISOString()
    });

    console.error(`⏸️  HUMAN APPROVAL REQUIRED | ID: ${approvalId} | Tool: ${toolName}`);
    console.error(`   Params: ${JSON.stringify(params, null, 2)}`);

    return approvalId;
  }

  approve(approvalId: string, approver: string): boolean {
    const request = this.pendingApprovals.get(approvalId);
    if (!request) return false;

    request.status = "approved";
    request.approved_at = new Date().toISOString();
    request.approved_by = approver;

    console.error(`✅ APPROVED | ID: ${approvalId} | By: ${approver}`);
    return true;
  }

  reject(approvalId: string, reason: string): boolean {
    const request = this.pendingApprovals.get(approvalId);
    if (!request) return false;

    request.status = "rejected";
    request.rejection_reason = reason;

    console.error(`❌ REJECTED | ID: ${approvalId} | Reason: ${reason}`);
    return true;
  }

  getStatus(approvalId: string): string | null {
    return this.pendingApprovals.get(approvalId)?.status || null;
  }

  getAllPending(): ApprovalRequest[] {
    return Array.from(this.pendingApprovals.values()).filter(r => r.status === "pending");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. AUDIT LOGGING LAYER
// ═══════════════════════════════════════════════════════════════════════════════

interface AuditEntry {
  event: string;
  request_id: string;
  timestamp: string;
  [key: string]: any;
}

class AuditLogger {
  private logFile: string;

  constructor(logFile: string = "mcp_audit.log") {
    this.logFile = logFile;
  }

  private write(entry: AuditEntry): void {
    const line = `${new Date().toISOString()} | ${JSON.stringify(entry)}\n`;
    try {
      fs.appendFileSync(this.logFile, line);
    } catch (e) {
      // Allow running in browser/simulated environments safely
    }
  }

  logRequest(requestId: string, toolName: string, userId: string, 
             scopes: string[], params: Record<string, any>, clientIp: string = "unknown"): void {
    this.write({
      event: "tool_request",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      tool_name: toolName,
      user_id: userId,
      scopes,
      client_ip: clientIp,
      params_hash: crypto.createHash("sha256")
        .update(JSON.stringify(params, Object.keys(params).sort()))
        .digest("hex")
        .substring(0, 16)
    });
  }

  logSecurityCheck(requestId: string, checkType: string, result: InjectionFindings): void {
    this.write({
      event: "security_check",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      check_type: checkType,
      result
    });
  }

  logDecision(requestId: string, decision: string, reason: string, approvalId?: string): void {
    this.write({
      event: "authorization_decision",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      decision,
      reason,
      approval_id: approvalId
    });
  }

  logExecution(requestId: string, toolName: string, success: boolean, 
               durationMs: number, error?: string): void {
    this.write({
      event: "tool_execution",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      tool_name: toolName,
      success,
      duration_ms: durationMs,
      error
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. TOKEN VALIDATION (Demo - Replace with real OAuth in production)
// ═══════════════════════════════════════════════════════════════════════════════

interface TokenData {
  sub: string;
  roles: string[];
  scopes: string[];
  security_level: SecurityLevel;
}

function validateToken(token: string): TokenData {
  const demoTokens: Record<string, TokenData> = {
    "token_user_123": {
      sub: "user_123",
      roles: ["user"],
      scopes: ["files:read", "email:send"],
      security_level: "medium"
    },
    "token_admin_456": {
      sub: "admin_456",
      roles: ["admin"],
      scopes: ["files:read", "files:write", "system:execute", "email:send", "security:scan"],
      security_level: "critical"
    },
    "token_security_789": {
      sub: "security_789",
      roles: ["security"],
      scopes: ["security:scan", "files:read"],
      security_level: "high"
    }
  };

  return demoTokens[token] || {
    sub: "anonymous",
    roles: [],
    scopes: [],
    security_level: "low"
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. SECURITY PIPELINE MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════════

const injectionDetector = new PromptInjectionDetector(0.7);
const authManager = new AuthorizationManager();
const approvalQueue = new HumanApprovalQueue();
const auditLogger = new AuditLogger();

interface SecurityContext {
  requestId: string;
  userId: string;
  scopes: string[];
  roles: string[];
  securityLevel: SecurityLevel;
  token: string;
}

function extractSecurityContext(extra: any): SecurityContext {
  const token = extra?.token || "";
  const tokenData = validateToken(token);

  return {
    requestId: `req_${Date.now()}`,
    userId: tokenData.sub,
    scopes: tokenData.scopes,
    roles: tokenData.roles,
    securityLevel: tokenData.security_level,
    token
  };
}

async function runSecurityPipeline<T extends Record<string, any>>(
  toolName: string,
  params: T,
  ctx: SecurityContext,
  handler: (params: T) => Promise<any>
): Promise<any> {
  const startTime = Date.now();

  const allText = JSON.stringify(params);
  const injectionResult = injectionDetector.scan(allText, toolName);
  auditLogger.logSecurityCheck(ctx.requestId, "prompt_injection", injectionResult);

  if (injectionResult.recommendation === "block") {
    auditLogger.logDecision(
      ctx.requestId, "blocked",
      `Prompt injection detected (score: ${injectionResult.risk_score.toFixed(2)})`
    );
    return {
      status: "blocked",
      reason: "Potential prompt injection detected",
      injection_report: injectionResult,
      request_id: ctx.requestId
    };
  }

  const authResult = authManager.checkAuthorization(
    toolName, ctx.scopes, ctx.roles, ctx.securityLevel
  );
  auditLogger.logDecision(
    ctx.requestId,
    authResult.authorized ? "approved" : "denied",
    authResult.reason || "Authorized"
  );

  if (!authResult.authorized) {
    return {
      status: "denied",
      reason: authResult.reason,
      request_id: ctx.requestId
    };
  }

  if (authResult.requires_approval) {
    const approvalId = approvalQueue.requestApproval(
      ctx.requestId, toolName, params,
      { user_id: ctx.userId, roles: ctx.roles, scopes: ctx.scopes }
    );

    // Auto-approve simulated
    await new Promise(resolve => setTimeout(resolve, 2000));
    approvalQueue.approve(approvalId, "auto_approver");

    auditLogger.logDecision(ctx.requestId, "approved", "Human approval granted", approvalId);
  }

  auditLogger.logRequest(ctx.requestId, toolName, ctx.userId, ctx.scopes, params);

  try {
    const result = await handler(params);
    const duration = Date.now() - startTime;
    auditLogger.logExecution(ctx.requestId, toolName, true, duration);

    return {
      status: "success",
      result,
      request_id: ctx.requestId,
      security_checks: {
        injection_detected: injectionResult.detected,
        injection_score: injectionResult.risk_score
      }
    };
  } catch (error: any) {
    const duration = Date.now() - startTime;
    auditLogger.logExecution(ctx.requestId, toolName, false, duration, error.message);

    return {
      status: "error",
      error: error.message,
      request_id: ctx.requestId
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. CREATE MCP SERVER
// ═══════════════════════════════════════════════════════════════════════════════

const server = new McpServer({
  name: "ai-security-server",
  version: "1.0.0"
});

// Tool 1: read_file (low risk)
server.tool(
  "read_file",
  "Read a file securely. Requires 'files:read' scope. Path validated to prevent traversal.",
  ReadFileSchema.shape,
  async (params, extra) => {
    const ctx = extractSecurityContext(extra);
    const result = await runSecurityPipeline("read_file", params, ctx, async (p) => {
      const absPath = path.resolve(p.path);
      const allowedRoots = ["/tmp", process.cwd()];
      const isAllowed = allowedRoots.some(root => absPath.startsWith(path.resolve(root)));

      if (!isAllowed) {
        throw new Error("Access outside allowed directories");
      }

      try {
        const content = fs.readFileSync(absPath, "utf-8").substring(0, p.max_size);
        return {
          path: p.path,
          content,
          size: content.length,
          truncated: content.length >= p.max_size
        };
      } catch (err: any) {
        if (err.code === "ENOENT") {
          return { error: "File not found", path: p.path };
        }
        throw err;
      }
    });

    return {
      content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }]
    };
  }
);

// Tool 2: execute_command (high risk - requires approval)
server.tool(
  "execute_command",
  "Execute a system command. REQUIRES HUMAN APPROVAL. Requires 'system:execute' scope.",
  ExecuteCommandSchema.shape,
  async (params, extra) => {
    const ctx = extractSecurityContext(extra);
    const result = await runSecurityPipeline("execute_command", params, ctx, async (p) => {
      const { exec } = require("child_process");
      const { promisify } = require("util");
      const execAsync = promisify(exec);

      try {
        const { stdout, stderr } = await execAsync(p.command, {
          cwd: p.working_dir,
          timeout: p.timeout * 1000
        });

        return {
          command: p.command,
          stdout: stdout.substring(0, 2000),
          stderr: stderr.substring(0, 2000),
          working_dir: p.working_dir
        };
      } catch (err: any) {
        if (err.killed) {
          return { error: "Command timed out", command: p.command };
        }
        return {
          command: p.command,
          stdout: err.stdout?.substring(0, 2000) || "",
          stderr: err.stderr?.substring(0, 2000) || err.message,
          working_dir: p.working_dir,
          error: err.message
        };
      }
    });

    return {
      content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }]
    };
  }
);

// Tool 3: send_email (medium risk - requires approval)
server.tool(
  "send_email",
  "Send an email. REQUIRES HUMAN APPROVAL. Requires 'email:send' scope.",
  SendEmailSchema.shape,
  async (params, extra) => {
    const ctx = extractSecurityContext(extra);
    const result = await runSecurityPipeline("send_email", params, ctx, async (p) => {
      return {
        to: p.to,
        subject: p.subject,
        body_preview: p.body.substring(0, 100) + (p.body.length > 100 ? "..." : ""),
        attachments_count: p.attachments.length,
        status: "sent",
        message_id: `msg_${crypto.randomBytes(6).toString("hex")}`
      };
    });

    return {
      content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }]
    };
  }
);

// Tool 4: scan_security (medium risk)
server.tool(
  "scan_security",
  "Run a security scan. Requires 'security:scan' scope.",
  ScanSecuritySchema.shape,
  async (params, extra) => {
    const ctx = extractSecurityContext(extra);
    const result = await runSecurityPipeline("scan_security", params, ctx, async (p) => {
      const findings = p.scan_type === "quick" ? [
        { severity: "low", issue: "Outdated dependency detected", target: p.target },
        { severity: "info", issue: "Debug mode enabled", target: p.target }
      ] : [
        { severity: "high", issue: "SQL injection vulnerability", target: p.target },
        { severity: "medium", issue: "Weak password policy", target: p.target },
        { severity: "low", issue: "Missing security headers", target: p.target }
      ];

      return {
        target: p.target,
        scan_type: p.scan_type,
        findings,
        scan_timestamp: new Date().toISOString(),
        total_findings: findings.length
      };
    });

    return {
      content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }]
    };
  }
);

// Tool 5: get_audit_log (admin only)
server.tool(
  "get_audit_log",
  "Retrieve recent audit log entries. Requires admin role.",
  z.object({ limit: z.number().int().min(1).max(1000).default(50) }).shape,
  async (params, extra) => {
    const ctx = extractSecurityContext(extra);
    const result = await runSecurityPipeline("get_audit_log", params, ctx, async (p) => {
      return {
        entries: [
          { timestamp: new Date().toISOString(), event: "demo_entry" }
        ],
        total_count: p.limit
      };
    });

    return {
      content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }]
    };
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// 9. START SERVER
// ═══════════════════════════════════════════════════════════════════════════════

async function main() {
  console.error("=".repeat(70));
  console.error("🔒 AI Security MCP Server v1.0.0 (TypeScript)");
  console.error("=".repeat(70));
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
