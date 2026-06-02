import React, { useState, useEffect } from "react";
import { Shield, Lock, KeyRound, Radio, RefreshCw, Layers, FileDown, ExternalLink, Copy, Check, Terminal } from "lucide-react";
import { 
  SecurityPolicy, 
  TokenDetails, 
  PipelineExecutionState, 
  AuditEntry, 
  InjectionFindings 
} from "./types";
import { 
  DEMO_TOKENS, 
  DEFAULT_POLICIES, 
  PromptInjectionDetectorClient 
} from "./utils/security";
import ToolExecutor from "./components/ToolExecutor";
import AttackerPlayground from "./components/AttackerPlayground";
import PipelineVisualizer from "./components/PipelineVisualizer";
import PolicyEditor from "./components/PolicyEditor";
import AuditLogTerminal from "./components/AuditLogTerminal";

export default function App() {
  // Session Access Token States
  const [activeToken, setActiveToken] = useState<TokenDetails>(DEMO_TOKENS[0]);
  const [policies, setPolicies] = useState<SecurityPolicy[]>(() => {
    const saved = localStorage.getItem("mcp_security_policies");
    return saved ? JSON.parse(saved) : DEFAULT_POLICIES;
  });

  // Integration wizard state
  const [repoPath, setRepoPath] = useState(
    typeof window !== "undefined" ? localStorage.getItem("mcp_repo_path") || "/absolute/path/to/your/project" : "/absolute/path/to/your/project"
  );
  const [activeIntegrationTab, setActiveIntegrationTab] = useState("claude");
  const [copied, setCopied] = useState(false);

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Telemetry Log Store
  const [logs, setLogs] = useState<AuditEntry[]>(() => {
    const saved = localStorage.getItem("mcp_audit_logs");
    return saved ? JSON.parse(saved) : [
      {
        id: "init_log",
        event: "authorization_decision",
        request_id: "system_boot",
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        decision: "allowed",
        reason: "AI Security MCP Server initialized successfully on stdio transport mode."
      }
    ];
  });

  // Current Pipeline State
  const [pipelineState, setPipelineState] = useState<PipelineExecutionState>({
    currentStep: "idle",
    steps: {
      input_validation: { status: "idle" },
      prompt_injection: { status: "idle" },
      authorization: { status: "idle" },
      human_approval: { status: "idle" },
      execution: { status: "idle" }
    }
  });

  // Temporary container for pending async pipeline states (to support hitl release)
  const [pendingExecution, setPendingExecution] = useState<{
    toolName: string;
    args: Record<string, any>;
    requestId: string;
    policy: SecurityPolicy;
    injectionScore: number;
    injectionDetected: boolean;
  } | null>(null);

  // Sync parameters locally
  useEffect(() => {
    localStorage.setItem("mcp_security_policies", JSON.stringify(policies));
  }, [policies]);

  useEffect(() => {
    localStorage.setItem("mcp_audit_logs", JSON.stringify(logs));
  }, [logs]);

  useEffect(() => {
    localStorage.setItem("mcp_repo_path", repoPath);
  }, [repoPath]);

  // Handle Policy update from configuration editor
  const handleUpdatePolicy = (updated: SecurityPolicy) => {
    setPolicies(prev => prev.map(p => p.tool_name === updated.tool_name ? updated : p));
    appendAuditLog({
      id: `sys_policy_${Date.now()}`,
      event: "authorization_decision",
      request_id: "admin_policy_update",
      timestamp: new Date().toISOString(),
      decision: "allowed",
      reason: `Access policy schema for tool "${updated.tool_name}" was administrative updated.`
    });
  };

  const handleResetPolicies = () => {
    setPolicies(DEFAULT_POLICIES);
    appendAuditLog({
      id: `sys_policy_reset_${Date.now()}`,
      event: "authorization_decision",
      request_id: "admin_policy_reset",
      timestamp: new Date().toISOString(),
      decision: "allowed",
      reason: `Restored default access control policy schemas.`
    });
  };

  // Logging helpers
  const appendAuditLog = (entry: AuditEntry) => {
    setLogs(prev => [...prev, entry]);
  };

  // CORE SECURE MIDDLEWARE PIPELINE SIMULATION
  const triggerSecurePipelineCall = async (toolName: string, args: Record<string, any>) => {
    const requestId = `req_${Date.now()}`;
    const timestamp = new Date().toISOString();

    // Reset layout for active inspect run
    setPipelineState({
      currentStep: "input_validation",
      requestId,
      payload: args,
      steps: {
        input_validation: { status: "processing", message: "Reviewing parameter formats against Zod validators..." },
        prompt_injection: { status: "idle" },
        authorization: { status: "idle" },
        human_approval: { status: "idle" },
        execution: { status: "idle" }
      }
    });

    await new Promise(resolve => setTimeout(resolve, 800));

    // 1. INPUT VALIDATION & PATTERN FILTER (Zod checks/traversals)
    let isInputOk = true;
    let inputMessage = "Zod schemas verified successfully. Path bounds cleared.";
    
    // Check path traversals on read_file
    if (toolName === "read_file" && args.path) {
      const isTraversed = args.path.includes("../") || args.path.includes("..\\") || args.path.startsWith("/");
      // Our backend has a specific allowed directory policy
      const normalizedPath = args.path.toLowerCase();
      const isAllowed = normalizedPath.startsWith("/tmp") || normalizedPath.startsWith("./") || !normalizedPath.includes("/");
      
      if (isTraversed || !isAllowed) {
        isInputOk = false;
        inputMessage = "Zod Schema Refinement check failed: Access outside allowed directories is blocked (Traversal vector detected).";
      }
    }

    // Refinement command block check
    if (toolName === "execute_command" && args.command) {
      const blockedRegexes = [
        /rm\s+-rf\s+\//i,
        />\s*\/dev\//i,
        /mkfs\./i,
        /dd\s+if=/i,
        /:\(\)\{\s*:\|:&\s*\};/i,
        /curl\s+.*\|\s*bash/i,
        /wget\s+.*\|\s*sh/i,
      ];
      for (const rx of blockedRegexes) {
        if (rx.test(args.command)) {
          isInputOk = false;
          inputMessage = `Zod Schema Pattern Restriction failed: Command matches blocked malicious sequence: "${rx.toString()}"`;
          break;
        }
      }
    }

    if (!isInputOk) {
      setPipelineState(prev => ({
        ...prev,
        currentStep: "input_validation",
        steps: {
          ...prev.steps,
          input_validation: { status: "blocked", message: inputMessage }
        }
      }));

      appendAuditLog({
        id: `audit_${requestId}_in`,
        event: "tool_execution",
        request_id: requestId,
        timestamp,
        tool_name: toolName,
        success: false,
        duration_ms: 800,
        error: `Input schema rejection: ${inputMessage}`
      });
      return;
    }

    // Input Validation Success: Transition to Step 2
    setPipelineState(prev => ({
      ...prev,
      currentStep: "prompt_injection",
      steps: {
        ...prev.steps,
        input_validation: { status: "success", message: inputMessage },
        prompt_injection: { status: "processing", message: "Scanning parameter text payloads for adversarial directives..." }
      }
    }));

    await new Promise(resolve => setTimeout(resolve, 800));

    // 2. PROMPT INJECTION DETECTION
    // Target fields that could hold user context
    const stringData = JSON.stringify(args);
    const detector = new PromptInjectionDetectorClient(0.7);
    const injectionResult = detector.scan(stringData);

    appendAuditLog({
      id: `sec_${requestId}_inj`,
      event: "security_check",
      request_id: requestId,
      timestamp,
      check_type: `prompt_injection_ratio_scan`,
      result: injectionResult
    });

    if (injectionResult.recommendation === "block") {
      setPipelineState(prev => ({
        ...prev,
        currentStep: "prompt_injection",
        steps: {
          ...prev.steps,
          prompt_injection: { 
            status: "blocked", 
            message: `PROMPT INJECTION DETECTED (Risk Score: ${injectionResult.risk_score})\nDetector triggered Block actions immediately.\nMatching Pattern: ${JSON.stringify(injectionResult.matches)}` 
          }
        }
      }));

      appendAuditLog({
        id: `dec_${requestId}_inj_block`,
        event: "authorization_decision",
        request_id: requestId,
        timestamp,
        decision: "blocked",
        reason: `Terminated request due to high Prompt Injection probability score (${injectionResult.risk_score}).`
      });
      return;
    }

    // Prompt Injection checks cleared: Transition to Step 3
    let promMessage = `Prompt inspection cleared (Risk score: ${injectionResult.risk_score}).`;
    if (injectionResult.recommendation === "flag_for_review") {
      promMessage += ` Flagged warning review activated.`;
    }

    setPipelineState(prev => ({
      ...prev,
      currentStep: "authorization",
      steps: {
        ...prev.steps,
        prompt_injection: { status: "success", message: promMessage },
        authorization: { status: "processing", message: "Matching OAuth client credentials against role policies..." }
      }
    }));

    await new Promise(resolve => setTimeout(resolve, 800));

    // 3. AUTHORIZATION check (Scopes, Roles, Security Level)
    const activePolicy = policies.find(p => p.tool_name === toolName);
    if (!activePolicy) {
      const reason = `Unknown policy registry for tool: "${toolName}"`;
      setPipelineState(prev => ({
        ...prev,
        currentStep: "authorization",
        steps: {
          ...prev.steps,
          authorization: { status: "denied", message: reason }
        }
      }));
      appendAuditLog({
        id: `dec_${requestId}_auth_fail`,
        event: "authorization_decision",
        request_id: requestId,
        timestamp,
        decision: "denied",
        reason
      });
      return;
    }

    // Required scopes check
    const hasScope = activeToken.scopes.includes(activePolicy.required_scope);
    const hasRole = activePolicy.allowed_roles.length === 0 || activeToken.roles.some(r => activePolicy.allowed_roles.includes(r));
    
    // Security hierarchy values
    const levelOrder = ["low", "medium", "high", "critical"];
    const hasSecLevel = levelOrder.indexOf(activeToken.security_level) >= levelOrder.indexOf(activePolicy.min_security_level);

    let isAuthOk = true;
    let authReason = "Authorization validated. Correct scopes, roles, and hierarchy verified.";

    if (!hasScope) {
      isAuthOk = false;
      authReason = `Missing required scope: "${activePolicy.required_scope}". Client had scope list: [${activeToken.scopes.join(", ")}]`;
    } else if (!hasRole) {
      isAuthOk = false;
      authReason = `Unauthorized credentials. Allowed Roles: [${activePolicy.allowed_roles.join(", ")}]. User Roles: [${activeToken.roles.join(", ")}]`;
    } else if (!hasSecLevel) {
      isAuthOk = false;
      authReason = `Security clearance breach. Client security level: "${activeToken.security_level}". Tool required: "${activePolicy.min_security_level}".`;
    }

    appendAuditLog({
      id: `request_${requestId}_audit`,
      event: "tool_request",
      request_id: requestId,
      timestamp,
      tool_name: toolName,
      user_id: activeToken.sub,
      scopes: activeToken.scopes,
      details: { arguments: args }
    });

    appendAuditLog({
      id: `dec_${requestId}_auth`,
      event: "authorization_decision",
      request_id: requestId,
      timestamp,
      decision: isAuthOk ? "allowed" : "denied",
      reason: authReason
    });

    if (!isAuthOk) {
      setPipelineState(prev => ({
        ...prev,
        currentStep: "authorization",
        steps: {
          ...prev.steps,
          authorization: { status: "denied", message: authReason }
        }
      }));
      return;
    }

    // Success transition. Next is Human Gateway (Step 4) or direct Execution (Step 5)
    const requiresHitl = activePolicy.requires_human_approval;

    setPipelineState(prev => ({
      ...prev,
      currentStep: requiresHitl ? "human_approval" : "execution",
      steps: {
        ...prev.steps,
        authorization: { status: "success", message: authReason },
        human_approval: requiresHitl 
          ? { status: "pending", message: "Holding subprocess locks. Awaiting administrator releasing permission..." }
          : { status: "idle" },
        execution: !requiresHitl 
          ? { status: "processing", message: "Launcing node runner within container shell..." }
          : { status: "idle" }
      }
    }));

    if (requiresHitl) {
      // Save pending context for manual action callback
      setPendingExecution({
        toolName,
        args,
        requestId,
        policy: activePolicy,
        injectionScore: injectionResult.risk_score,
        injectionDetected: injectionResult.detected
      });
      return;
    }

    // If direct execution:
    await new Promise(resolve => setTimeout(resolve, 800));
    executeTargetToolAndFinish(toolName, args, requestId, injectionResult);
  };

  // Human Gateway Callback Action
  const handleHumanApproveAction = async (approved: boolean) => {
    if (!pendingExecution) return;

    const { toolName, args, requestId, injectionScore, injectionDetected } = pendingExecution;
    const timestamp = new Date().toISOString();

    appendAuditLog({
      id: `hitl_${requestId}_gate`,
      event: "authorization_decision",
      request_id: requestId,
      timestamp,
      decision: approved ? "approved" : "rejected",
      reason: approved 
        ? "Human release permission issued: Authorized by manual administrator unlock override." 
        : "Human release permission denied: High hazard workflow command set rejected by administrator."
    });

    if (!approved) {
      setPipelineState(prev => ({
        ...prev,
        currentStep: "human_approval",
        steps: {
          ...prev.steps,
          human_approval: { status: "blocked", message: "Approval Rejected: Transaction terminated." }
        }
      }));
      setPendingExecution(null);
      return;
    }

    // Approved: Transition directly into Step 5 (Execution)
    setPipelineState(prev => ({
      ...prev,
      currentStep: "execution",
      steps: {
        ...prev.steps,
        human_approval: { status: "success", message: "Aproved by Security Admin" },
        execution: { status: "processing", message: "Launching node runner within container shell..." }
      }
    }));

    await new Promise(resolve => setTimeout(resolve, 850));
    executeTargetToolAndFinish(toolName, args, requestId, { risk_score: injectionScore, detected: injectionDetected } as any);
    setPendingExecution(null);
  };

  // Perform Final Subprocess execution logic
  const executeTargetToolAndFinish = (
    toolName: string, 
    args: Record<string, any>, 
    requestId: string,
    injectionReport: { risk_score: number; detected: boolean }
  ) => {
    let success = true;
    let details: Record<string, any> = {};
    let errorText = "";

    try {
      switch (toolName) {
        case "read_file":
          details = {
            path: args.path,
            content: `// MOCK METRICS FROM ${args.path}\n{\n  "sys_status": "green",\n  "auth_keys_loaded": 12,\n  "last_audit_epoch": 17823901\n}`,
            size: 112,
            truncated: false
          };
          break;
        case "execute_command":
          details = {
            command: args.command,
            stdout: `STDOUT REPORT:\n  Server: AI-Security-MCP-Server-v1\n  PID: 10452\n  Status: Running on stdio loop\n  Active Scopes: files:read, email:send, system:execute, security:scan`,
            stderr: "",
            working_dir: args.working_dir || "/tmp"
          };
          break;
        case "send_email":
          details = {
            to: args.to,
            subject: args.subject,
            body_preview: args.body?.substring(0, 100) + "...",
            attachments_count: args.attachments?.length || 0,
            status: "sent",
            message_id: `msg_${Math.floor(Math.random() * 900000 + 100000)}`
          };
          break;
        case "scan_security":
          details = {
            target: args.target,
            scan_type: args.scan_type,
            findings: args.scan_type === "quick" ? [
              { severity: "low", issue: "Outdated key modules", target: args.target },
              { severity: "info", issue: "Debug telemetry verbose modes enabled", target: args.target }
            ] : [
              { severity: "high", issue: "Reflected SQL Injection vulnerability", target: args.target },
              { severity: "medium", issue: "Weak credential salt hashing parameters", target: args.target },
              { severity: "low", issue: "Missing secure browser CSP policies", target: args.target }
            ],
            scan_timestamp: new Date().toISOString(),
            total_findings: args.scan_type === "quick" ? 2 : 3
          };
          break;
        case "get_audit_log":
          details = {
            entries: logs.slice(-1 * (args.limit || 5)).map(l => ({ timestamp: l.timestamp, event: l.event })),
            total_count: logs.length
          };
          break;
        default:
          throw new Error("No execution pathway associated with endpoint.");
      }
    } catch (e: any) {
      success = false;
      errorText = e.message || "Failed running subprocess stream.";
    }

    setPipelineState(prev => ({
      ...prev,
      currentStep: "execution",
      result: success ? details : { error: errorText },
      steps: {
        ...prev.steps,
        execution: { 
          status: success ? "success" : "blocked", 
          message: success 
            ? `Exit Code 0: Complete.\nResponse Output:\n${JSON.stringify(details, null, 2)}` 
            : `Exit Code 1: Execution Failed.\nStderr: ${errorText}`
        }
      }
    }));

    appendAuditLog({
      id: `exec_${requestId}_finish`,
      event: "tool_execution",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      tool_name: toolName,
      success,
      duration_ms: Math.floor(Math.random() * 150 + 100),
      error: success ? undefined : errorText,
      details: success ? details : undefined
    });
  };

  const handleClearLogs = () => {
    setLogs([]);
  };

  // Attacker interface action connection helper
  const handleRequestInjectToExecutor = (targetTool: string, emailBody: string, command: string) => {
    // Scroll view if needed, but primarily alerts user that they can verify execution
    const executorEl = document.getElementById("tool-executor-card");
    if (executorEl) {
      executorEl.scrollIntoView({ behavior: "smooth" });
    }

    // Set corresponding input fields based on injection target
    const btn = document.getElementById(`btn-tool-${targetTool}`);
    if (btn) {
      btn.click();
    }

    setTimeout(() => {
      if (emailBody) {
        const bodyInput = document.getElementById("input-email-body") as HTMLTextAreaElement;
        if (bodyInput) {
          bodyInput.value = emailBody;
          // Dispatch synthetic event to let React update
          const event = new Event('input', { bubbles: true });
          bodyInput.dispatchEvent(event);
        }
      }
      if (command) {
        const commandInput = document.getElementById("input-command") as HTMLTextAreaElement;
        if (commandInput) {
          commandInput.value = command;
          const event = new Event('input', { bubbles: true });
          commandInput.dispatchEvent(event);
        }
      }
    }, 150);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col antialiased">
      {/* Visual background lines config */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(99,102,241,0.08),rgba(255,255,255,0))] pointer-events-none" />

      {/* Header Bar */}
      <header className="border-b border-slate-900 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-emerald-500 to-indigo-600 p-[1px]">
              <div className="h-full w-full bg-slate-950 rounded-[11px] flex items-center justify-center">
                <Shield className="h-5 w-5 text-emerald-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h1 className="font-sans font-bold tracking-tight text-white leading-tight">AI Security MCP Sandbox</h1>
                <span className="text-[9px] px-1.5 py-0.2 bg-emerald-500/10 text-emerald-400 font-mono border border-emerald-500/20 rounded font-bold">
                  LOCAL v1.0.0
                </span>
              </div>
              <p className="text-xs text-slate-500 font-mono">Input validation • Injection Shield • Multi-Role Access Control</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="hidden sm:flex items-center gap-1.5 bg-slate-900 border border-slate-800 px-3 py-1 rounded-lg">
              <span className="h-1.5 w-1.5 bg-emerald-500 rounded-full animate-ping" />
              <span className="text-[10px] font-mono text-slate-400 text-slate-300 select-none">
                Security-Server Core: Stdio Active
              </span>
            </div>
            
            <a 
              href="https://ai.studio/build" 
              target="_blank" 
              referrerPolicy="no-referrer"
              className="text-xs font-mono text-slate-400 hover:text-white flex items-center gap-1 px-3 py-2 bg-slate-900/40 hover:bg-slate-900 border border-slate-800/80 rounded-lg transition-all"
            >
              Google Build <ExternalLink className="h-3 w-3 shrink-0" />
            </a>
          </div>
        </div>
      </header>

      {/* Main Container Layout */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 w-full space-y-6 relative z-10">
        
        {/* Credentials Token Selector Strip */}
        <section className="bg-slate-900/50 border border-slate-850/80 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4" id="session-credentials-jumbotron">
          <div className="space-y-1">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <KeyRound className="h-4 w-4 text-emerald-500" /> ACTIVE SESSION CREDENTIALS (DEMO TOKEN)
            </h2>
            <p className="text-xs text-slate-500 leading-normal">
              Select key credentials to authenticate commands. Scope permissions, clearances, and role hierarchies alter policy validations dynamically.
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 shrink-0 md:min-w-[480px]">
            {DEMO_TOKENS.map((token) => (
              <button
                type="button"
                key={token.id}
                id={`btn-token-select-${token.id}`}
                onClick={() => {
                  setActiveToken(token);
                  appendAuditLog({
                    id: `sys_auth_token_${Date.now()}`,
                    event: "authorization_decision",
                    request_id: "token_swap",
                    timestamp: new Date().toISOString(),
                    decision: "allowed",
                    reason: `Active credential profiles shifted dynamically to "${token.label}" (${token.sub}). Scope parameters swapped.`
                  });
                }}
                className={`p-2 rounded-lg border text-left transition-all relative ${
                  activeToken.id === token.id
                    ? "bg-emerald-500/10 border-emerald-500/60 text-emerald-400 shadow-md ring-1 ring-emerald-500/20"
                    : "bg-slate-950/60 border-slate-800/80 text-slate-500 hover:border-slate-800 hover:text-slate-350"
                }`}
              >
                <div className="flex items-center gap-1.5 mb-1.5">
                  <span className={`h-1.5 w-1.5 rounded-full ${
                    token.security_level === "critical" ? "bg-rose-500" :
                    token.security_level === "high" ? "bg-orange-500" :
                    token.security_level === "medium" ? "bg-amber-500" : "bg-emerald-500"
                  }`} />
                  <p className="text-[10px] font-mono font-semibold uppercase truncate leading-none">{token.sub}</p>
                </div>
                <div className="text-[9px] font-mono leading-tight truncate font-medium text-slate-500">
                  lvl: {token.security_level}
                </div>
              </button>
            ))}
          </div>
        </section>

        {/* Selected token details banner */}
        <div className="p-3 bg-slate-900 border border-slate-850 rounded-xl flex flex-wrap items-center justify-between gap-4 text-xs font-mono" id="token-banner-meta">
          <div className="flex items-center gap-2">
            <span className="text-slate-500">Cred Sub:</span>
            <span className="text-slate-200 font-bold">{activeToken.label}</span>
          </div>
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500">Role List:</span>
              <span className="text-slate-350 bg-slate-950 px-1.5 py-0.5 border border-slate-800/80 rounded text-[10px]">
                {activeToken.roles.join(", ") || "Guest"}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500">OAuth Scopes:</span>
              <span className="text-indigo-300 bg-indigo-500/10 px-1.5 py-0.5 border border-indigo-500/25 rounded text-[10px]">
                {activeToken.scopes.join(", ") || "None"}
              </span>
            </div>
          </div>
        </div>

        {/* Interactive Bento Grid Workspace */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6" id="bento-grid-dashboard">
          
          {/* LEFT PANELS COLUMN */}
          <div className="lg:col-span-6 space-y-6 flex flex-col justify-between">
            <ToolExecutor 
              onExecute={triggerSecurePipelineCall} 
              activeTokenScopes={activeToken.scopes} 
            />
            
            <AttackerPlayground 
              onInject={(text, findings) => {}} 
              onRequestInjectToExecutor={handleRequestInjectToExecutor}
            />
          </div>

          {/* RIGHT PANELS COLUMN */}
          <div className="lg:col-span-6 space-y-6">
            <PipelineVisualizer 
              pipeline={pipelineState} 
              onHumanApprove={handleHumanApproveAction} 
            />

            <PolicyEditor 
              policies={policies} 
              onUpdatePolicy={handleUpdatePolicy} 
              onResetPolicies={handleResetPolicies} 
            />
          </div>

          {/* AUDIT LOG TELEMETRY (Full Width bottom row) */}
          <div className="lg:col-span-12">
            <AuditLogTerminal 
              logs={logs} 
              onClear={handleClearLogs} 
            />
          </div>

        </div>

        {/* Interactive Integration Wizard & Codebase Exporter */}
        <section className="bg-slate-900 border border-slate-850 rounded-xl p-5 md:p-6" id="developer-integration-wizard">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded bg-indigo-500/10 text-indigo-400 select-none shrink-0">
                <Layers className="h-5 w-5" />
              </div>
              <div>
                <h3 className="font-sans font-medium text-slate-100 text-lg leading-tight">🔌 Local & IDE Integration Wizard</h3>
                <p className="text-xs text-slate-400 font-mono">Use this MCP security server in Claude, Cursor, Cline, or custom software</p>
              </div>
            </div>

            {/* Path Selector */}
            <div className="flex items-center gap-2 bg-slate-950 border border-slate-800/80 px-3 py-1.5 rounded-lg w-full md:max-w-md">
              <span className="text-[10px] font-mono text-slate-500 shrink-0 font-bold uppercase">Local Project Path:</span>
              <input
                type="text"
                id="input-repo-path"
                value={repoPath}
                onChange={(e) => setRepoPath(e.target.value)}
                placeholder="/absolute/path/to/your/project"
                className="bg-transparent border-none text-xs font-mono text-indigo-300 focus:outline-none w-full placeholder-slate-600 focus:ring-0 leading-tight py-0"
              />
            </div>
          </div>

          {/* Quick Integration Tabs */}
          <div className="flex items-center gap-1 border-b border-slate-800/80 pb-3 mb-4 overflow-x-auto scrollbar-none">
            {[
              { id: "claude", label: "Claude Desktop", icon: "💬" },
              { id: "cursor", label: "Cursor IDE", icon: "🚀" },
              { id: "cline", label: "Cline (VS Code)", icon: "🧩" },
              { id: "typescript", label: "Node.js (TS SDK)", icon: "📦" },
              { id: "python", label: "Python SDK", icon: "🐍" }
            ].map((tab) => (
              <button
                type="button"
                key={tab.id}
                id={`btn-integration-${tab.id}`}
                onClick={() => setActiveIntegrationTab(tab.id)}
                className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all font-medium whitespace-nowrap ${
                  activeIntegrationTab === tab.id
                    ? "bg-indigo-500/10 border border-indigo-500/30 text-indigo-300"
                    : "border border-transparent text-slate-400 hover:bg-slate-950 hover:text-slate-200"
                }`}
              >
                <span>{tab.icon}</span> {tab.label}
              </button>
            ))}
          </div>

          {/* Tab Contents */}
          <div className="bg-slate-950/80 border border-slate-850/60 rounded-xl p-4 md:p-5 relative">
            
            {activeIntegrationTab === "claude" && (
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <h4 className="text-xs font-mono font-bold text-slate-300">How to register in Claude Desktop</h4>
                  <p className="text-xs text-slate-400 leading-relaxed md:max-w-4xl">
                    Claude Desktop runs external MCP servers over <strong>stdio</strong>. Add the security shield into your global configuration file:
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mt-2 pt-1">
                    <div className="bg-slate-900 border border-slate-850 p-2 rounded text-[10px] font-mono">
                      <span className="text-slate-500 uppercase block mb-1">macOS Path</span>
                      <code className="text-slate-300 break-all select-all">~/Library/Application Support/Claude/claude_desktop_config.json</code>
                    </div>
                    <div className="bg-slate-900 border border-slate-850 p-2 rounded text-[10px] font-mono">
                      <span className="text-slate-500 uppercase block mb-1">Windows Path</span>
                      <code className="text-slate-300 break-all select-all">%APPDATA%\Claude\claude_desktop_config.json</code>
                    </div>
                    <div className="bg-slate-900 border border-slate-850 p-2 rounded text-[10px] font-mono">
                      <span className="text-slate-500 uppercase block mb-1">Linux Path</span>
                      <code className="text-slate-300 break-all select-all">~/.config/Claude/claude_desktop_config.json</code>
                    </div>
                  </div>
                </div>

                {/* Configurations Card */}
                <div className="relative">
                  <div className="absolute top-3 right-3 flex items-center gap-2">
                    <button
                      type="button"
                      id="btn-copy-claude-config"
                      onClick={() => handleCopyCode(JSON.stringify({
                        mcpServers: {
                          "security-gateway": {
                            command: "npx",
                            args: ["tsx", `${repoPath}/mcp_security_server.ts`],
                            env: {
                              NODE_ENV: "development",
                              PATH: "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
                            }
                          }
                        }
                      }, null, 2))}
                      className="px-2.5 py-1 bg-slate-900 border border-slate-800 hover:bg-slate-850 text-[10px] rounded flex items-center gap-1 hover:text-slate-200 text-slate-400 transition-colors"
                    >
                      {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      {copied ? "Copied" : "Copy "}
                    </button>

                    <button
                      type="button"
                      id="btn-download-claude-config"
                      onClick={() => {
                        const config = {
                          mcpServers: {
                            "security-gateway": {
                              command: "npx",
                              args: ["tsx", `${repoPath}/mcp_security_server.ts`],
                              env: {
                                NODE_ENV: "development",
                                PATH: "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
                              }
                            }
                          }
                        };
                        const blob = new Blob([JSON.stringify(config, null, 2)], { type: "application/json" });
                        const url = URL.createObjectURL(blob);
                        const link = document.createElement("a");
                        link.href = url;
                        link.download = "claude_desktop_config.json";
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                        URL.revokeObjectURL(url);
                      }}
                      className="px-2.5 py-1 bg-indigo-500/10 border border-indigo-550/30 hover:bg-indigo-500/20 text-[10px] rounded flex items-center gap-1 leading-none text-indigo-300 transition-colors"
                    >
                      <FileDown className="h-3 w-3" /> Download Config
                    </button>
                  </div>
                  
                  <pre className="p-3 bg-slate-900/60 border border-slate-900 rounded-lg text-[11px] font-mono text-slate-300 overflow-x-auto pt-10">
                    {`{
  "mcpServers": {
    "security-gateway": {
      "command": "npx",
      "args": [
        "tsx",
        "${repoPath}/mcp_security_server.ts"
      ],
      "env": {
        "NODE_ENV": "development",
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
      }
    }
  }
}`}
                  </pre>
                </div>
              </div>
            )}

            {activeIntegrationTab === "cursor" && (
              <div className="space-y-4">
                <div className="space-y-2">
                  <h4 className="text-xs font-mono font-bold text-slate-300">Adding Secure Gateway to Cursor</h4>
                  <div className="text-xs text-slate-400 space-y-1.5 leading-relaxed">
                    <p>1. Open Cursor and navigate to <strong>Cursor Settings ⚙️ &gt; Features &gt; MCP</strong>.</p>
                    <p>2. Select the green <strong>+ Add New MCP Server</strong> button.</p>
                    <p>3. Input the parameters below exactly:</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-3 bg-slate-900 border border-slate-850 rounded-lg">
                    <span className="text-[9px] font-mono text-slate-550 uppercase font-bold block mb-1">Server Name</span>
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-mono text-emerald-400 font-bold">AI Security Gateway</span>
                      <button
                        type="button"
                        id="btn-copy-cursor-name"
                        onClick={() => handleCopyCode("AI Security Gateway")}
                        className="text-slate-500 hover:text-slate-300"
                        title="Copy Name"
                      >
                        <Copy className="h-3 w-3" />
                      </button>
                    </div>
                  </div>

                  <div className="p-3 bg-slate-900 border border-slate-850 rounded-lg">
                    <span className="text-[9px] font-mono text-slate-550 uppercase font-bold block mb-1">Transport Type</span>
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-mono text-indigo-400 font-semibold">command</span>
                      <button
                        type="button"
                        id="btn-copy-cursor-type"
                        onClick={() => handleCopyCode("command")}
                        className="text-slate-500 hover:text-slate-300"
                        title="Copy Type"
                      >
                        <Copy className="h-3 w-3" />
                      </button>
                    </div>
                  </div>

                  <div className="p-3 bg-slate-900 border border-slate-850 rounded-lg">
                    <span className="text-[9px] font-mono text-slate-550 uppercase font-bold block mb-1">Command String</span>
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-mono text-slate-200 truncate pr-2">npx tsx {repoPath}/mcp_security_server.ts</span>
                      <button
                        type="button"
                        id="btn-copy-cursor-cmd"
                        onClick={() => {
                          const suffix = repoPath.endsWith("/") ? "" : "/";
                          handleCopyCode(`npx tsx "${repoPath}${suffix}mcp_security_server.ts"`);
                        }}
                        className="text-slate-500 hover:text-slate-300 shrink-0"
                        title="Copy Command"
                      >
                        <Copy className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                </div>

                <div className="p-3 bg-indigo-500/5 border border-indigo-500/10 rounded-lg flex items-start gap-2.5">
                  <span className="text-indigo-400 shrink-0">ℹ️</span>
                  <p className="text-[11px] text-slate-450 leading-relaxed">
                    Cursor will run the typescript executable directly in the background. If the status bullet turns green, Cursor can consult files while preserving safety barriers! Make sure to install dependencies inside the directory.
                  </p>
                </div>
              </div>
            )}

            {activeIntegrationTab === "cline" && (
              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-xs font-mono font-bold text-slate-300">How to register in Cline for VS Code</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Cline handles MCP systems through an internal config dictionary. Modify your Cline settings file:
                  </p>
                  <code className="block p-2 mt-1.5 bg-slate-900 border border-slate-850 rounded text-[10px] font-mono text-indigo-300 select-all leading-normal break-all">
                    ~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json
                  </code>
                </div>

                <div className="relative">
                  <button
                    type="button"
                    id="btn-copy-cline"
                    onClick={() => handleCopyCode(JSON.stringify({
                      mcpServers: {
                        "security-gateway": {
                          command: "npx",
                          args: ["tsx", `${repoPath}/mcp_security_server.ts`]
                        }
                      }
                    }, null, 2))}
                    className="absolute top-3 right-3 px-2.5 py-1 bg-slate-900 border border-slate-800 hover:bg-slate-850 text-[10px] rounded flex items-center gap-1 hover:text-slate-200 text-slate-400 transition-colors"
                  >
                    {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    {copied ? "Copied" : "Copy"}
                  </button>

                  <pre className="p-3 bg-slate-900/60 border border-slate-900 rounded-lg text-[11px] font-mono text-slate-300 overflow-x-auto pt-10">
                    {`{
  "mcpServers": {
    "security-gateway": {
      "command": "npx",
      "args": [
        "tsx",
        "${repoPath}/mcp_security_server.ts"
      ]
    }
  }
}`}
                  </pre>
                </div>
              </div>
            )}

            {activeIntegrationTab === "typescript" && (
              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-xs font-mono font-bold text-slate-300">Integrating in Node.js (TypeScript)</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Use our custom client <code>typescript_mcp_client.ts</code> pre-written in your repository to implement direct program interactions:
                  </p>
                </div>

                <div className="relative">
                  <button
                    type="button"
                    className="absolute top-3 right-3 px-2.5 py-1 bg-slate-900 border border-slate-800 hover:bg-slate-850 text-[10px] rounded flex items-center gap-1 hover:text-slate-200 text-slate-400 transition-colors"
                    id="btn-copy-node-snippet"
                    onClick={() => handleCopyCode(`import { SecurityMCPClient } from "./typescript_mcp_client";

async function main() {
  const client = new SecurityMCPClient();
  
  // Connect via stdio local transport
  await client.connectStdio("${repoPath}/mcp_security_server.ts");
  
  // Connect options allow executing secure checks
  const res = await client.callTool("read_file", {
    path: "./package.json",
    max_size: 1000
  });

  console.log("Safe output:", res.output);
  await client.close();
}

main().catch(console.error);`)}
                  >
                    {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    {copied ? "Copied" : "Copy Code"}
                  </button>

                  <pre className="p-3 bg-slate-900/60 border border-slate-900 rounded-lg text-[11px] font-mono text-slate-300 overflow-x-auto pt-10">
                    {`import { SecurityMCPClient } from "./typescript_mcp_client";

async function main() {
  const client = new SecurityMCPClient();
  
  // Connect via stdio local transport
  await client.connectStdio("${repoPath}/mcp_security_server.ts");
  
  // Connect options allow executing secure checks
  const res = await client.callTool("read_file", {
    path: "./package.json",
    max_size: 1000
  });

  console.log("Safe output:", res.output);
  await client.close();
}

main().catch(console.error);`}
                  </pre>
                </div>
              </div>
            )}

            {activeIntegrationTab === "python" && (
              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-xs font-mono font-bold text-slate-300">Integrating in Python Applications</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Connect Python agents to this secure server seamlessly over standard I/O channels:
                  </p>
                </div>

                <div className="relative">
                  <button
                    type="button"
                    className="absolute top-3 right-3 px-2.5 py-1 bg-slate-900 border border-slate-800 hover:bg-slate-850 text-[10px] rounded flex items-center gap-1 hover:text-slate-200 text-slate-400 transition-colors"
                    id="btn-copy-python-snippet"
                    onClick={() => handleCopyCode(`import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="npx",
        args=["tsx", "${repoPath}/mcp_security_server.ts"]
    )
    
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print("Secure Tools Discovered:", [t.name for t in tools.tools])
            
            # Execute protected tool
            response = await session.call_tool("read_file", {
                "path": "package.json",
                "max_size": 1000
            })
            print("Response:", response.content[0].text)

asyncio.run(main())`)}
                  >
                    {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    {copied ? "Copied" : "Copy Code"}
                  </button>

                  <pre className="p-3 bg-slate-900/60 border border-slate-900 rounded-lg text-[11px] font-mono text-slate-300 overflow-x-auto pt-10">
                    {`import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="npx",
        args=["tsx", "${repoPath}/mcp_security_server.ts"]
    )
    
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print("Secure Tools Discovered:", [t.name for t in tools.tools])
            
            # Execute protected tool
            response = await session.call_tool("read_file", {
                "path": "package.json",
                "max_size": 1000
            })
            print("Response:", response.content[0].text)

asyncio.run(main())`}
                  </pre>
                </div>
              </div>
            )}

          </div>

          {/* Core File Stats Bottom Bar */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
            <div className="p-3 bg-slate-950 border border-slate-850/65 rounded-lg text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-mono text-emerald-400 font-semibold truncate">mcp_security_server.ts</span>
                <span className="text-[9px] font-mono uppercase bg-slate-900 px-1.5 rounded text-slate-400">Node ESM Server</span>
              </div>
              <p className="text-[11px] text-slate-500 leading-normal">
                Implements Zod parameter checks, Prompt Injection shielding, multi-role clearances, and Human-in-the-Loop validations.
              </p>
            </div>

            <div className="p-3 bg-slate-950 border border-slate-850/65 rounded-lg text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-mono text-indigo-400 font-semibold truncate">typescript_mcp_client.ts</span>
                <span className="text-[9px] font-mono uppercase bg-slate-900 px-1.5 rounded text-slate-400">Client Tester</span>
              </div>
              <p className="text-[11px] text-slate-500 leading-normal">
                Handles discovery, Stdio streams, and automated security profiling checks with full client sdk capability.
              </p>
            </div>
          </div>
        </section>

      </main>

      {/* Footer system details */}
      <footer className="border-t border-slate-900/80 bg-slate-950 mt-12 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs font-mono text-slate-550">
          <p>© 2026 google-ai-studio:built-applet. Confidential Secure Sandbox Instance.</p>
          <div className="flex items-center gap-1.5">
            <span>Container Ingress: Port 3000</span>
            <span className="h-1.5 w-1.5 bg-emerald-500 rounded-full" />
          </div>
        </div>
      </footer>
    </div>
  );
}
