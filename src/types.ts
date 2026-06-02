/**
 * Shared Type Definitions for the AI Security MCP Sandbox
 */

export type SecurityLevel = "low" | "medium" | "high" | "critical";

export interface SecurityPolicy {
  tool_name: string;
  required_scope: string;
  min_security_level: SecurityLevel;
  requires_human_approval: boolean;
  max_requests_per_minute: number;
  allowed_roles: string[];
}

export interface TokenDetails {
  id: string;
  sub: string;
  roles: string[];
  scopes: string[];
  security_level: SecurityLevel;
  label: string;
  description: string;
}

export interface InjectionFindings {
  detected: boolean;
  risk_score: number;
  matches: Array<{
    type: string;
    pattern_id?: number;
    match?: string;
    count?: number;
    keywords_found?: string[];
    value?: number;
    note?: string;
  }>;
  recommendation: "allow" | "flag_for_review" | "block";
}

export interface PipelineStepState {
  status: "idle" | "processing" | "success" | "blocked" | "denied" | "pending";
  message?: string;
}

export interface PipelineExecutionState {
  currentStep: "idle" | "input_validation" | "prompt_injection" | "authorization" | "human_approval" | "execution";
  steps: {
    input_validation: PipelineStepState;
    prompt_injection: PipelineStepState;
    authorization: PipelineStepState;
    human_approval: PipelineStepState;
    execution: PipelineStepState;
  };
  payload?: any;
  result?: any;
  requestId?: string;
}

export interface AuditEntry {
  id: string;
  event: string;
  request_id: string;
  timestamp: string;
  tool_name?: string;
  user_id?: string;
  scopes?: string[];
  decision?: string;
  reason?: string;
  check_type?: string;
  result?: any;
  success?: boolean;
  duration_ms?: number;
  error?: string;
  details?: Record<string, any>;
}
