import React, { useState, useEffect } from "react";
import { FolderOpen, Terminal, Mail, ShieldAlert, FileJson, Play } from "lucide-react";

interface ToolExecutorProps {
  onExecute: (toolName: string, args: Record<string, any>) => void;
  activeTokenScopes: string[];
}

export default function ToolExecutor({ onExecute, activeTokenScopes }: ToolExecutorProps) {
  const [selectedTool, setSelectedTool] = useState("read_file");
  const [readFilePath, setReadFilePath] = useState("/tmp/health_metrics.json");
  const [readFileSize, setReadFileSize] = useState(10000);
  
  const [execCommand, setExecCommand] = useState("npx tsx mcp_security_server.ts --status");
  const [execWorkingDir, setExecWorkingDir] = useState("/tmp");
  const [execTimeout, setExecTimeout] = useState(30);

  const [emailTo, setEmailTo] = useState("secops-auditor@enterprise.com");
  const [emailSubject, setEmailSubject] = useState("ALERT: Prompt Injection Mitigation Audit");
  const [emailBody, setEmailBody] = useState("System checks suggest that an unverified actor attempted standard DAN-mode jailbreaks.\nMitigation triggered successfully.");
  const [emailAttachments, setEmailAttachments] = useState("/tmp/exploit_payload.pcap, /tmp/audit_log.json");

  const [scanTarget, setScanTarget] = useState("production-api-gateway");
  const [scanType, setScanType] = useState<"quick" | "full">("quick");

  const [logLimit, setLogLimit] = useState(50);

  // Auto select default payloads depending on scopes for helper UX
  useEffect(() => {
    // Just reactive cues
  }, [selectedTool]);

  const handleRun = (e: React.FormEvent) => {
    e.preventDefault();
    let args: Record<string, any> = {};

    switch (selectedTool) {
      case "read_file":
        args = {
          path: readFilePath,
          max_size: Number(readFileSize),
        };
        break;
      case "execute_command":
        args = {
          command: execCommand,
          working_dir: execWorkingDir,
          timeout: Number(execTimeout),
        };
        break;
      case "send_email":
        args = {
          to: emailTo,
          subject: emailSubject,
          body: emailBody,
          attachments: emailAttachments.split(",").map((s) => s.trim()).filter(Boolean),
        };
        break;
      case "scan_security":
        args = {
          target: scanTarget,
          scan_type: scanType,
        };
        break;
      case "get_audit_log":
        args = {
          limit: Number(logLimit),
        };
        break;
    }

    onExecute(selectedTool, args);
  };

  const hasRequiredScope = (tool: string) => {
    if (activeTokenScopes.length === 0) return false;
    switch (tool) {
      case "read_file":
        return activeTokenScopes.includes("files:read");
      case "execute_command":
        return activeTokenScopes.includes("system:execute");
      case "send_email":
        return activeTokenScopes.includes("email:send");
      case "scan_security":
      case "get_audit_log":
        return activeTokenScopes.includes("security:scan");
      default:
        return false;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-2xl relative overflow-hidden" id="tool-executor-card">
      <div className="flex items-center gap-3 mb-4">
        <div className="p-2 rounded bg-emerald-500/10 text-emerald-400">
          <Play className="h-5 w-5" />
        </div>
        <div>
          <h3 className="font-sans font-medium text-slate-100 text-lg leading-tight">Tool Call Orchestrator</h3>
          <p className="text-xs text-slate-400 font-mono">MCP client call simulation</p>
        </div>
      </div>

      <form onSubmit={handleRun} className="space-y-4">
        <div>
          <label className="block text-xs font-mono font-medium text-slate-400 uppercase tracking-wider mb-2">
            Select Tool Endpoint
          </label>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-2 lg:grid-cols-3">
            {[
              { id: "read_file", label: "read_file", icon: FolderOpen },
              { id: "execute_command", label: "execute_command", icon: Terminal },
              { id: "send_email", label: "send_email", icon: Mail },
              { id: "scan_security", label: "scan_security", icon: ShieldAlert },
              { id: "get_audit_log", label: "get_audit_log", icon: FileJson },
            ].map((tool) => {
              const IconComp = tool.icon;
              const hasScope = hasRequiredScope(tool.id);
              return (
                <button
                  type="button"
                  key={tool.id}
                  id={`btn-tool-${tool.id}`}
                  onClick={() => setSelectedTool(tool.id)}
                  className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border text-left transition-all ${
                    selectedTool === tool.id
                      ? "bg-emerald-500/10 border-emerald-500/50 text-emerald-400 shadow-md"
                      : "bg-slate-950/60 border-slate-800/80 text-slate-400 hover:border-slate-700/60 hover:text-slate-200"
                  }`}
                >
                  <IconComp className="h-4 w-4 shrink-0" />
                  <div className="min-w-0">
                    <p className="text-xs font-mono font-semibold truncate leading-none mb-1">{tool.label}</p>
                    <span className={`text-[9px] px-1 py-0.2 rounded-sm font-mono block ${
                      hasScope ? "bg-emerald-500/20 text-emerald-300 font-medium" : "bg-red-500/15 text-red-300"
                    }`}>
                      {hasScope ? "AUTHORIZED" : "NO SCOPE"}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Dynamic Tool Parameters Render */}
        <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800/80 space-y-3.5" id="tool-params-panel">
          <p className="text-xs font-mono font-semibold text-slate-400 border-b border-slate-800 pb-2">
            PARAMETERS SCHEMA & VALUE OVERRIDES
          </p>

          {selectedTool === "read_file" && (
            <div className="space-y-3 animate-fade-in">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">path (string, max_size: 500)</label>
                <input
                  type="text"
                  id="input-path"
                  value={readFilePath}
                  onChange={(e) => setReadFilePath(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                />
                <span className="text-[10px] text-slate-500 font-mono mt-1 block">✔ validated to prevent system directory traversall</span>
              </div>
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">max_size (int, max: 1000000)</label>
                <input
                  type="number"
                  id="input-max-size"
                  value={readFileSize}
                  onChange={(e) => setReadFileSize(Number(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>
          )}

          {selectedTool === "execute_command" && (
            <div className="space-y-3 animate-fade-in">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">command (string, dangerous pattern guard)</label>
                <textarea
                  rows={2}
                  id="input-command"
                  value={execCommand}
                  onChange={(e) => setExecCommand(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-300 text-xs focus:outline-none focus:border-emerald-500"
                />
                <span className="text-[10px] text-amber-500 font-mono flex items-start gap-1 leading-normal mt-1">
                  ⚠ Refined pattern shield cuts execution if match found for "rm -rf", "curl | bash", redirection bypass, etc.
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[11px] font-mono text-slate-400 mb-1">working_dir</label>
                  <input
                    type="text"
                    id="input-working-dir"
                    value={execWorkingDir}
                    onChange={(e) => setExecWorkingDir(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-mono text-slate-400 mb-1">timeout (sec)</label>
                  <input
                    type="number"
                    id="input-timeout"
                    value={execTimeout}
                    onChange={(e) => setExecTimeout(Number(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>
            </div>
          )}

          {selectedTool === "send_email" && (
            <div className="space-y-3 animate-fade-in">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">to (validated email schema)</label>
                <input
                  type="email"
                  id="input-email-to"
                  value={emailTo}
                  onChange={(e) => setEmailTo(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">subject (max_size: 200)</label>
                <input
                  type="text"
                  id="input-email-subject"
                  value={emailSubject}
                  onChange={(e) => setEmailSubject(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">body content (payload injection scan target)</label>
                <textarea
                  rows={2}
                  id="input-email-body"
                  value={emailBody}
                  onChange={(e) => setEmailBody(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-300 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">attachments (comma-separated pathways)</label>
                <input
                  type="text"
                  id="input-email-attachments"
                  value={emailAttachments}
                  onChange={(e) => setEmailAttachments(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-300 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>
          )}

          {selectedTool === "scan_security" && (
            <div className="space-y-3 animate-fade-in">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">target host/identity</label>
                <input
                  type="text"
                  id="input-scan-target"
                  value={scanTarget}
                  onChange={(e) => setScanTarget(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">scan depth level</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    id="btn-scan-quick"
                    onClick={() => setScanType("quick")}
                    className={`px-3 py-1.5 rounded font-mono text-xs border text-center transition-all ${
                      scanType === "quick"
                        ? "bg-slate-850 text-slate-200 border-slate-700"
                        : "bg-transparent text-slate-500 border-slate-900 hover:text-slate-300"
                    }`}
                  >
                    quick
                  </button>
                  <button
                    type="button"
                    id="btn-scan-full"
                    onClick={() => setScanType("full")}
                    className={`px-3 py-1.5 rounded font-mono text-xs border text-center transition-all ${
                      scanType === "full"
                        ? "bg-slate-850 text-slate-200 border-slate-700"
                        : "bg-transparent text-slate-500 border-slate-900 hover:text-slate-300"
                    }`}
                  >
                    full
                  </button>
                </div>
              </div>
            </div>
          )}

          {selectedTool === "get_audit_log" && (
            <div className="space-y-3 animate-fade-in">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">row_limit (min: 1, max: 1000)</label>
                <input
                  type="number"
                  id="input-log-limit"
                  value={logLimit}
                  onChange={(e) => setLogLimit(Number(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 font-mono text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>
          )}
        </div>

        <button
          type="submit"
          id="btn-trigger-mcp-call"
          className="w-full py-3 bg-emerald-500 hover:bg-emerald-600 active:bg-emerald-700 text-slate-950 font-semibold font-mono text-xs uppercase tracking-wider rounded-lg shadow-xl shadow-emerald-500/10 transition-all flex items-center justify-center gap-2"
        >
          <Play className="h-4 w-4 fill-current shrink-0" />
          Call {selectedTool} through pipeline
        </button>
      </form>
    </div>
  );
}
