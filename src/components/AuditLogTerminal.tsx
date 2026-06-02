import React, { useState, useRef, useEffect } from "react";
import { Terminal, Trash2, Copy, Check, Search, Filter } from "lucide-react";
import { AuditEntry } from "../types";

interface AuditLogTerminalProps {
  logs: AuditEntry[];
  onClear: () => void;
}

export default function AuditLogTerminal({ logs, onClear }: AuditLogTerminalProps) {
  const [filterType, setFilterType] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom of terminal when logs expand
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const getFilteredLogs = () => {
    return logs.filter((log) => {
      // Filter by type
      if (filterType !== "all" && log.event !== filterType) {
        return false;
      }
      // Filter by search text
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const contentStr = JSON.stringify(log).toLowerCase();
        return contentStr.includes(query);
      }
      return true;
    });
  };

  const copyToClipboard = (log: AuditEntry) => {
    navigator.clipboard.writeText(JSON.stringify(log, null, 2));
    setCopiedId(log.id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const getEventColor = (evt: string) => {
    switch (evt) {
      case "tool_request":
        return "text-indigo-400";
      case "security_check":
        return "text-rose-400";
      case "authorization_decision":
        return "text-amber-400";
      case "tool_execution":
        return "text-emerald-400";
      default:
        return "text-slate-400";
    }
  };

  const filtered = getFilteredLogs();

  return (
    <div className="bg-slate-955 border border-slate-900 rounded-xl p-5 shadow-2xl space-y-4" id="audit-terminal-card">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-900 pb-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-indigo-500/10 text-indigo-400">
            <Terminal className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-sans font-medium text-slate-100 text-lg leading-tight">Live Pipeline Audit Logs</h3>
            <p className="text-xs text-slate-500 font-mono font-medium">mcp_audit.log tail output stream</p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end">
          <button
            type="button"
            id="btn-clear-logs"
            onClick={onClear}
            className="flex items-center gap-1.5 text-xs font-mono text-slate-550 hover:text-slate-300 transition-all px-2.5 py-1.5 hover:bg-slate-900/50 rounded border border-transparent hover:border-slate-800"
          >
            <Trash2 className="h-3.5 w-3.5" /> Clear terminal
          </button>
        </div>
      </div>

      {/* Searching & Filter Tabs */}
      <div className="flex flex-col md:flex-row gap-2" id="logs-filters-panel">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            id="input-terminal-search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search log parameters, timestamps or request-IDs..."
            className="w-full bg-slate-900 border border-slate-850 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-550"
          />
        </div>

        <div className="flex gap-1 overflow-x-auto pb-1" id="filter-tabs">
          {[
            { id: "all", label: "All Logs" },
            { id: "tool_request", label: "Requests" },
            { id: "security_check", label: "Threat Guards" },
            { id: "authorization_decision", label: "Decisions" },
            { id: "tool_execution", label: "Executions" },
          ].map((tab) => (
            <button
              type="button"
              id={`tab-filter-${tab.id}`}
              key={tab.id}
              onClick={() => setFilterType(tab.id)}
              className={`px-3 py-2 rounded-lg font-mono text-xs border whitespace-nowrap transition-all ${
                filterType === tab.id
                  ? "bg-indigo-500/10 border-indigo-500/35 text-indigo-300 font-semibold"
                  : "bg-transparent border-transparent text-slate-500 hover:text-slate-350"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Terminal View */}
      <div className="bg-slate-950 rounded-xl border border-slate-900/80 p-4 font-mono text-xs h-[420px] overflow-y-auto flex flex-col relative" id="terminal-body-bg">
        <div className="flex items-center gap-1 text-[11px] text-slate-650 mb-3 border-b border-slate-900/40 pb-2">
          <span>CONSOLE: mcp @ security-server ~ tail -f mcp_audit.log</span>
          <span className="h-1.5 w-1.5 bg-emerald-500 rounded-full animate-ping ml-1" />
        </div>

        {filtered.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-600 text-[11px] space-y-1">
            <span>&gt;_ [Log stream empty]</span>
            <span>Verify triggers or change filtering options</span>
          </div>
        ) : (
          <div className="space-y-4 flex-1">
            {filtered.map((log) => (
              <div
                key={log.id}
                id={`terminal-log-${log.id}`}
                className="group relative bg-slate-900/25 hover:bg-slate-900/60 p-3 rounded-lg border border-slate-900/60 hover:border-slate-800/80 transition-all"
              >
                {/* Floating copy button */}
                <button
                  type="button"
                  id={`btn-copy-log-${log.id}`}
                  onClick={() => copyToClipboard(log)}
                  className="absolute right-2 top-2 p-1.5 bg-slate-950 border border-slate-850 hover:border-slate-700 text-slate-400 hover:text-slate-200 rounded opacity-0 group-hover:opacity-100 transition-all duration-150"
                  title="Copy log entry JSON"
                >
                  {copiedId === log.id ? (
                    <Check className="h-3 w-3 text-emerald-400" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                </button>

                {/* Log Header line */}
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-1 text-[10px] text-slate-500 mb-2 font-semibold">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-slate-400">[{log.timestamp}]</span>
                    <span className={`px-1.5 py-0.2 rounded-sm bg-slate-950 uppercase shrink ${getEventColor(log.event)}`}>
                      {log.event}
                    </span>
                  </div>
                  <span className="text-slate-650 shrink truncate">Req ID: {log.request_id}</span>
                </div>

                {/* Event-specific visual formatting */}
                {log.event === "tool_request" && (
                  <div className="text-indigo-200">
                    Client <span className="text-indigo-400 font-bold">{log.user_id}</span> requested tool{" "}
                    <span className="text-emerald-400 font-bold font-mono">"{log.tool_name}"</span>
                    <span className="text-slate-550 block text-[10.5px] mt-1">Scopes authorized: [{log.scopes?.join(", ")}]</span>
                  </div>
                )}

                {log.event === "security_check" && (
                  <div className="text-rose-200 space-y-1">
                    <div>
                      Prompt vulnerability assessment executed:{" "}
                      <span className={log.result?.detected ? "text-rose-400 font-bold" : "text-emerald-400"}>
                        {log.result?.detected ? "THREAT_DETECTED" : "GREEN_NORMAL"}
                      </span>
                    </div>
                    <div className="text-[10.5px] text-slate-500 leading-normal">
                      Scan: {log.check_type} | Risk: {log.result?.risk_score} | Sensitivity: 0.70 | Decision: {log.result?.recommendation?.toUpperCase()}
                    </div>
                  </div>
                )}

                {log.event === "authorization_decision" && (
                  <div className="text-amber-200">
                    Authorization middleware resolved:{" "}
                    <span className={log.decision === "blocked" || log.decision === "denied" ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
                      {log.decision?.toUpperCase()}
                    </span>
                    <p className="text-slate-500 block text-[10.5px] mt-1">Audit description: {log.reason}</p>
                  </div>
                )}

                {log.event === "tool_execution" && (
                  <div className="text-emerald-200 space-y-1">
                    <div>
                      Standard output completed:{" "}
                      <span className={log.success ? "text-emerald-400 font-bold" : "text-rose-400 font-bold"}>
                        {log.success ? "EXIT_OK" : "EXIT_ERROR"}
                      </span>{" "}
                      ({log.duration_ms}ms)
                    </div>
                    {log.error ? (
                      <p className="text-rose-300 block text-[10.5px] mt-1 bg-rose-500/10 p-1 rounded font-mono border border-rose-500/15">
                        Error stderr: {log.error}
                      </p>
                    ) : (
                      log.details && (
                        <pre className="text-[10px] text-slate-400 leading-tight bg-slate-950 p-2 rounded border border-slate-900 overflow-x-auto max-w-full">
                          {JSON.stringify(log.details, null, 2)}
                        </pre>
                      )
                    )}
                  </div>
                )}
              </div>
            ))}
            <div ref={terminalEndRef} />
          </div>
        )}
      </div>
    </div>
  );
}
