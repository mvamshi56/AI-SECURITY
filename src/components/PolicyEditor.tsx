import React, { useState } from "react";
import { Sliders, ShieldCheck, HelpCircle } from "lucide-react";
import { SecurityPolicy, SecurityLevel } from "../types";

interface PolicyEditorProps {
  policies: SecurityPolicy[];
  onUpdatePolicy: (updated: SecurityPolicy) => void;
  onResetPolicies: () => void;
}

export default function PolicyEditor({ policies, onUpdatePolicy, onResetPolicies }: PolicyEditorProps) {
  const [editingTool, setEditingTool] = useState<string | null>(null);
  
  // Temporary edit states
  const [scope, setScope] = useState("");
  const [level, setLevel] = useState<SecurityLevel>("low");
  const [approval, setApproval] = useState(false);
  const [rateLimit, setRateLimit] = useState(10);
  const [roles, setRoles] = useState<string[]>([]);
  const [roleText, setRoleText] = useState("");

  const handleStartEdit = (policy: SecurityPolicy) => {
    setEditingTool(policy.tool_name);
    setScope(policy.required_scope);
    setLevel(policy.min_security_level);
    setApproval(policy.requires_human_approval);
    setRateLimit(policy.max_requests_per_minute);
    setRoles([...policy.allowed_roles]);
    setRoleText(policy.allowed_roles.join(", "));
  };

  const handleSave = (toolName: string) => {
    const updatedRoles = roleText
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    onUpdatePolicy({
      tool_name: toolName,
      required_scope: scope,
      min_security_level: level,
      requires_human_approval: approval,
      max_requests_per_minute: Number(rateLimit),
      allowed_roles: updatedRoles,
    });

    setEditingTool(null);
  };

  const getLevelColor = (lvl: SecurityLevel) => {
    switch (lvl) {
      case "critical":
        return "text-rose-400 bg-rose-500/15 border-rose-500/30";
      case "high":
        return "text-orange-400 bg-orange-500/15 border-orange-500/30";
      case "medium":
        return "text-amber-400 bg-amber-500/15 border-amber-500/30";
      case "low":
      default:
        return "text-emerald-400 bg-emerald-500/15 border-emerald-500/30";
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-2xl space-y-4" id="policy-editor-card">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-indigo-500/10 text-indigo-400">
            <Sliders className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-sans font-medium text-slate-100 text-lg leading-tight">Access Control & Role Policies</h3>
            <p className="text-xs text-slate-400 font-mono">Simulated IAM administration registry</p>
          </div>
        </div>

        <button
          type="button"
          onClick={onResetPolicies}
          id="btn-properties-reset"
          className="text-[10px] font-mono text-indigo-400 hover:text-indigo-300 underline underline-offset-2"
        >
          Reset defaults
        </button>
      </div>

      <div className="space-y-3 max-h-[360px] overflow-y-auto pr-1">
        {policies.map((policy) => {
          const isEditing = editingTool === policy.tool_name;

          return (
            <div
              key={policy.tool_name}
              id={`policy-item-${policy.tool_name}`}
              className={`p-3.5 border rounded-lg transition-all ${
                isEditing
                  ? "bg-slate-950 border-indigo-550 shadow-md"
                  : "bg-slate-950/40 border-slate-850 hover:bg-slate-950/65"
              }`}
            >
              {/* Header */}
              <div className="flex items-start justify-between gap-4 mb-2">
                <div>
                  <span className="text-xs font-mono font-bold text-slate-200">{policy.tool_name}</span>
                  <p className="text-[10px] text-slate-500 font-mono">IAM rule validation schema</p>
                </div>

                {!isEditing && (
                  <button
                    type="button"
                    id={`btn-edit-policy-${policy.tool_name}`}
                    onClick={() => handleStartEdit(policy)}
                    className="text-[10px] font-mono text-emerald-400 px-2.5 py-1 bg-emerald-550/10 hover:bg-emerald-550/20 rounded font-bold"
                  >
                    Edit rule
                  </button>
                )}
              </div>

              {isEditing ? (
                <div className="space-y-3 mt-3 pt-3 border-t border-slate-900 animate-fade-in text-[11px] font-mono text-slate-400">
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-[9px] uppercase text-slate-500 mb-1">Required Scope</label>
                      <input
                        type="text"
                        value={scope}
                        onChange={(e) => setScope(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-[9px] uppercase text-slate-500 mb-1">Min Security Level</label>
                      <select
                        value={level}
                        onChange={(e) => setLevel(e.target.value as SecurityLevel)}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-indigo-550"
                      >
                        <option value="low">low</option>
                        <option value="medium">medium</option>
                        <option value="high">high</option>
                        <option value="critical">critical</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-[9px] uppercase text-slate-500 mb-1">Rate Limit (rpm)</label>
                      <input
                        type="number"
                        value={rateLimit}
                        onChange={(e) => setRateLimit(Number(e.target.value))}
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-[9px] uppercase text-slate-500 mb-1">Allowed Roles (csv)</label>
                      <input
                        type="text"
                        value={roleText}
                        onChange={(e) => setRoleText(e.target.value)}
                        placeholder="user, admin"
                        className="w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs focus:outline-none"
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-between py-1 bg-slate-900/60 rounded px-2.5">
                    <label className="text-[10px] text-slate-300">Requires Human Approval Gate</label>
                    <input
                      type="checkbox"
                      checked={approval}
                      onChange={(e) => setApproval(e.target.checked)}
                      className="h-4 w-4 accent-indigo-500 text-slate-950 rounded cursor-pointer"
                    />
                  </div>

                  <div className="flex justify-end gap-1.5 pt-1">
                    <button
                      type="button"
                      onClick={() => setEditingTool(null)}
                      className="px-2.5 py-1 text-[10px] bg-slate-800 hover:bg-slate-700 hover:text-slate-200 text-slate-400 rounded"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      id={`btn-save-policy-${policy.tool_name}`}
                      onClick={() => handleSave(policy.tool_name)}
                      className="px-2.5 py-1 text-[10px] bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold rounded"
                    >
                      Save Rule
                    </button>
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[10px] font-mono text-slate-400">
                  <div className="flex justify-between border-b border-slate-900/50 pb-1">
                    <span className="text-slate-550">Scope:</span>
                    <span className="text-indigo-400 font-bold">{policy.required_scope}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-900/50 pb-1">
                    <span className="text-slate-550">Audit level:</span>
                    <span className={`px-1 rounded-sm border text-[9px] leading-tight ${getLevelColor(policy.min_security_level)}`}>
                      {policy.min_security_level}
                    </span>
                  </div>
                  <div className="flex justify-between border-b border-slate-900/50 p-0">
                    <span className="text-slate-550">H-I-T-L Lock:</span>
                    <span className={policy.requires_human_approval ? "text-amber-400 font-bold" : "text-slate-500 animate-none"}>
                      {policy.requires_human_approval ? "ENABLED" : "BYPASSED"}
                    </span>
                  </div>
                  <div className="flex justify-between border-b border-slate-900/50 p-0">
                    <span className="text-slate-550">Rate boundary:</span>
                    <span className="text-slate-300 font-semibold">{policy.max_requests_per_minute} rpm</span>
                  </div>
                  <div className="col-span-2 flex items-start gap-1 pb-1 pt-1.5 leading-normal">
                    <span className="text-slate-550 text-[9px] uppercase tracking-wider font-semibold">Roles permitted:</span>
                    <div className="flex flex-wrap gap-1 shrink">
                      {policy.allowed_roles.map((r) => (
                        <span key={r} className="bg-slate-900 text-slate-300 border border-slate-800 px-1 rounded-sm text-[9px]">
                          {r}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
