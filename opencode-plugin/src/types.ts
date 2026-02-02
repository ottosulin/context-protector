/**
 * Type definitions for Context Protector OpenCode Plugin
 */

/**
 * Alert returned by the guardrail when a threat is detected
 */
export interface GuardrailAlert {
  /** Human-readable explanation of the threat */
  explanation: string
  /** Additional metadata about the detection */
  data: Record<string, unknown>
}

/**
 * Result from checking content with the guardrail backend
 */
export interface CheckResult {
  /** Whether the content is safe (no threats detected) */
  safe: boolean
  /** Alert details if content is unsafe, null if safe */
  alert: GuardrailAlert | null
}

/**
 * Content type being checked
 */
export type ContentType = "tool_input" | "tool_output"

/**
 * Response mode configuration
 */
export type ResponseMode = "warn" | "block"

/**
 * Plugin configuration options
 */
export interface PluginConfig {
  /** Response mode: 'warn' logs warnings, 'block' throws errors */
  responseMode: ResponseMode
  /** Provider to use: LlamaFirewall, NeMoGuardrails, GCPModelArmor */
  provider: string
  /** Enable built-in .env file protection */
  envProtection: boolean
  /** Patterns to always block from being read */
  blockedFilePatterns: string[]
  /** Tools to skip checking (for performance) */
  skipTools: string[]
  /** Enable debug logging */
  debug: boolean
}

/**
 * Default plugin configuration
 */
export const DEFAULT_CONFIG: PluginConfig = {
  responseMode: "warn",
  provider: "LlamaFirewall",
  envProtection: true,
  blockedFilePatterns: [".env", ".env.*", "*.pem", "*.key", "credentials.json"],
  skipTools: [],
  debug: false,
}

/**
 * Input to tool.execute.before hook (matches OpenCode API)
 */
export interface ToolExecuteInput {
  tool: string
  sessionID: string
  callID: string
}

/**
 * Output from tool.execute.before hook (mutable, matches OpenCode API)
 */
export interface ToolExecuteBeforeOutput {
  args: Record<string, unknown>
}

/**
 * Output from tool.execute.after hook (mutable, matches OpenCode API)
 */
export interface ToolExecuteAfterOutput {
  title: string
  output: string
  metadata: Record<string, unknown>
}

/**
 * Backend check function signature
 */
export type CheckFunction = (
  content: string,
  type: ContentType
) => Promise<CheckResult>
