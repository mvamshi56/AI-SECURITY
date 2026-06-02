import React from "react";
import { ShieldCheck, Eye, KeyRound, UserCheck, Flame, Cpu, CheckCircle2, XCircle, Clock } from "lucide-react";
import { PipelineExecutionState } from "../types";

interface PipelineVisualizerProps {
  pipeline: PipelineExecutionState;
  onHumanApprove: (approved: boolean) => void;
}

export default function PipelineVisualizer({ pipeline, onHumanApprove }: PipelineVisualizerProps) {
  const getStepStatusStyles = (status: "idle" | "processing" | "success" | "blocked" | "denied" | "pending") => {
    switch (status) {
      case "processing":
        return {
          card: "bg-indigo-500/10 border-indigo-500/60 shadow-indigo-500/5",
          icon: "bg-indigo-500 text-slate-950 animate-pulse",
          text: "text-indigo-400",
          stepSign: "border-indigo-500/50 text-indigo-400 font-semibold"
        };
      case "success":
        return {
          card: "bg-emerald-500/10 border-emerald-500/50 shadow-emerald-500/5",
          icon: "bg-emerald-500 text-slate-950",
          text: "text-emerald-400",
          stepSign: "border-emerald-500 text-emerald-400 font-semibold"
        };
      case "blocked":
      case "denied":
        return {
          card: "bg-rose-500/10 border-rose-500/60 shadow-rose-500/5",
          icon: "bg-rose-500 text-rose-950",
          text: "text-rose-400",
          stepSign: "border-rose-500 text-rose-400 font-bold"
        };
      case "pending":
        return {
          card: "bg-amber-500/10 border-amber-500/60 shadow-amber-500/5 animate-pulse",
          icon: "bg-amber-500 text-slate-950 font-bold",
          text: "text-amber-400",
          stepSign: "border-amber-500 text-amber-400 font-bold"
        };
      case "idle":
      default:
        return {
          card: "bg-slate-950/40 border-slate-850/80 text-slate-550",
          icon: "bg-slate-900 border border-slate-800 text-slate-500",
          text: "text-slate-400",
          stepSign: "border-slate-800 text-slate-550 font-medium"
        };
    }
  };

  const stepsList = [
    {
      id: "input_validation",
      name: "Input Schema Review",
      description: "Zod parameter syntax & path traversal audits",
      icon: ShieldCheck,
    },
    {
      id: "prompt_injection",
      name: "Prompt Injection Filter",
      description: "Scans payload regexes, entropy and risk ratios",
      icon: Flame,
    },
    {
      id: "authorization",
      name: "Scope & Role Authorization",
      description: "Checks OAuth bounds, required scopes and roles",
      icon: KeyRound,
    },
    {
      id: "human_approval",
      name: "Human-in-the-Loop Gateway",
      description: "Halts high-risk command sets for supervisor checks",
      icon: UserCheck,
    },
    {
      id: "execution",
      name: "Isolated Tool Output",
      description: "Launches server subprocess with status reports",
      icon: Cpu,
    },
  ] as const;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-2xl space-y-4" id="pipeline-visualizer-card">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-indigo-500/10 text-indigo-400">
            <Eye className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-sans font-medium text-slate-100 text-lg leading-tight">Secure Pipeline Monitoring</h3>
            <p className="text-xs text-slate-400 font-mono">Real-time middleware inspection</p>
          </div>
        </div>

        {pipeline.requestId && (
          <span className="text-[9px] font-mono bg-slate-950 border border-slate-800 px-2 py-1 rounded text-indigo-400">
            Req ID: {pipeline.requestId}
          </span>
        )}
      </div>

      {pipeline.currentStep === "idle" ? (
        <div className="flex flex-col items-center justify-center py-12 text-center text-slate-500 space-y-2 border border-dashed border-slate-800 rounded-lg bg-slate-950/20" id="idle-pipeline-overlay">
          <ShieldCheck className="h-10 w-10 text-slate-600 animate-pulse" />
          <p className="font-mono text-xs">Awaiting client request triggers...</p>
          <p className="text-[10px] text-slate-600">Select any tool, edit arguments and click "Call Tool" to view live telemetry.</p>
        </div>
      ) : (
        <div className="space-y-3 relative" id="active-pipeline-path">
          {/* Vertical progress line connecting cards */}
          <div className="absolute left-6 top-3 bottom-3 w-[2px] bg-slate-800 -z-0" />

          {stepsList.map((step, idx) => {
            const stepState = pipeline.steps[step.id];
            const hasCompleted = ["success", "blocked", "denied"].includes(stepState.status);
            const style = getStepStatusStyles(stepState.status);
            const IconComponent = step.icon;

            return (
              <div
                key={step.id}
                id={`pipeline-step-${step.id}`}
                className={`flex gap-4 p-3.5 border rounded-lg transition-all duration-300 relative z-10 ${style.card}`}
              >
                <div className={`h-8 w-8 rounded-full flex items-center justify-center shrink-0 ${style.icon}`}>
                  <IconComponent className="h-4.5 w-4.5" />
                </div>

                <div className="flex-1 min-w-0 space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <p className={`text-xs font-mono font-semibold truncate ${style.text}`}>
                      {idx + 1}. {step.name}
                    </p>
                    <span className={`text-[9px] font-mono px-1.5 py-0.2 border rounded ${style.stepSign}`}>
                      {stepState.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400 leading-normal truncate">{step.description}</p>
                  
                  {stepState.message && (
                    <div className="text-[10px] bg-slate-950/80 rounded px-2.5 py-1.5 font-mono text-slate-300 mt-1.5 border border-slate-800/80 leading-normal whitespace-pre-wrap">
                      {stepState.message}
                    </div>
                  )}

                  {/* Manual Approval Actions Embedded */}
                  {step.id === "human_approval" && stepState.status === "pending" && (
                    <div className="mt-3 p-3 bg-slate-950 border border-amber-500/45 rounded-lg space-y-3 animate-fade-in" id="approval-interactive-box">
                      <div className="flex items-start gap-2">
                        <Clock className="h-4 w-4 text-amber-400 shrink-0 mt-0.5 animate-spin" />
                        <div>
                          <p className="text-[10px] font-semibold text-amber-400 font-mono">MESSAGING PIPELINE HALTED: SUPERVISER REVIEW</p>
                          <p className="text-[9px] text-slate-400 font-mono">This command triggers standard critical risk thresholds. Confirm permissions to release the process:</p>
                        </div>
                      </div>
                      
                      {pipeline.payload && (
                        <div className="bg-slate-900 rounded p-2 text-[9px] font-mono text-slate-400 truncate max-w-full">
                          Params: {JSON.stringify(pipeline.payload)}
                        </div>
                      )}

                      <div className="flex gap-2">
                        <button
                          type="button"
                          id="btn-approve-hire"
                          onClick={() => onHumanApprove(true)}
                          className="px-3 py-1.5 bg-emerald-500 hover:bg-emerald-600 active:bg-emerald-700 text-slate-950 font-bold font-mono text-[10px] uppercase rounded transition-all flex items-center gap-1"
                        >
                          <CheckCircle2 className="h-3.5 w-3.5" /> Release Tool Execution
                        </button>
                        <button
                          type="button"
                          id="btn-reject-hire"
                          onClick={() => onHumanApprove(false)}
                          className="px-3 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/35 font-bold font-mono text-[10px] uppercase rounded transition-all flex items-center gap-1"
                        >
                          <XCircle className="h-3.5 w-3.5" /> Terminate Call
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
