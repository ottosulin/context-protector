/**
 * Context Protector Plugin for OpenCode
 *
 * Protects AI coding agents from prompt injection attacks by scanning
 * tool inputs (before execution) and outputs (after execution).
 *
 * @packageDocumentation
 */

import type { Plugin } from "@opencode-ai/plugin"
import {
  checkWithBackend,
  isBackendAvailable,
  safeResult,
} from "./backend.js"
import { mergeConfig, isBlockedFile } from "./config.js"
import type {
  CheckResult,
  ContentType,
  ToolExecuteInput,
  ToolExecuteBeforeOutput,
  ToolExecuteAfterOutput,
} from "./types.js"

// Re-export types for consumers
export type {
  CheckResult,
  ContentType,
  PluginConfig,
  GuardrailAlert,
} from "./types.js"
export { DEFAULT_CONFIG } from "./types.js"
export { BackendError, isBackendAvailable } from "./backend.js"

interface LogEntry {
  service: string
  level: "debug" | "info" | "warn" | "error"
  message: string
  extra?: Record<string, unknown>
}

interface Logger {
  log(entry: LogEntry): void
}

function createLogger(debug: boolean): Logger {
  return {
    log(entry) {
      if (entry.level === "debug" && !debug) return
      const prefix = `[context-protector] [${entry.level.toUpperCase()}]`
      const msg = `${prefix} ${entry.message}`
      const method = entry.level === "debug" ? "log" : entry.level
      if (entry.extra) {
        console[method](msg, entry.extra)
      } else {
        console[method](msg)
      }
    },
  }
}

/**
 * Check content for threats
 */
async function checkContent(
  content: string,
  type: ContentType,
  logger: Logger
): Promise<CheckResult> {
  try {
    const result = await checkWithBackend(content, type)
    
    logger.log({
      service: "context-protector",
      level: "debug",
      message: `Checked ${type}: safe=${result.safe}`,
      extra: { contentLength: content.length, type },
    })
    
    return result
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    
    logger.log({
      service: "context-protector",
      level: "warn",
      message: `Backend check failed: ${message}`,
      extra: { error: message, type },
    })
    
    return safeResult()
  }
}

/**
 * Format alert message for display
 */
function formatAlert(
  explanation: string,
  mode: "block" | "warn",
  tool?: string
): string {
  const prefix = mode === "block" ? "BLOCK" : "WARNING"
  const toolInfo = tool ? ` in tool '${tool}'` : ""
  return `[CONTEXT-GUARD ${prefix}] Potentially malicious content detected${toolInfo}: ${explanation}`
}

/**
 * Context Protector Plugin
 *
 * Protects against prompt injection by scanning tool inputs and outputs.
 *
 * @example
 * ```typescript
 * // In opencode.json
 * {
 *   "plugin": ["opencode-context-protector"]
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Environment configuration
 * CONTEXT_PROTECTOR_RESPONSE_MODE=block
 * CONTEXT_PROTECTOR_ENV_PROTECTION=true
 * ```
 */
export const ContextProtector: Plugin = async (_ctx) => {
  const config = mergeConfig()
  const logger = createLogger(config.debug)
  const backendAvailable = await isBackendAvailable()
  
  if (backendAvailable) {
    logger.log({
      service: "context-protector",
      level: "info",
      message: "Context Protector initialized with Python backend",
      extra: {
        responseMode: config.responseMode,
        provider: config.provider,
        envProtection: config.envProtection,
      },
    })
  } else {
    logger.log({
      service: "context-protector",
      level: "warn",
      message:
        "Python backend not available. Install with: pip install context-protector",
      extra: { envProtection: config.envProtection },
    })
  }

  return {
    /**
     * Hook: Before tool execution (PreToolUse equivalent)
     *
     * Checks tool input arguments for malicious content.
     * Can block execution by throwing an error in block mode.
     */
    "tool.execute.before": async (
      input: ToolExecuteInput,
      output: ToolExecuteBeforeOutput
    ) => {
      const { tool } = input
      
      // Skip if tool is in skip list
      if (config.skipTools.includes(tool)) {
        return
      }

      // Built-in .env file protection
      if (config.envProtection && tool === "read") {
        const filePath = output.args.filePath as string | undefined
        if (filePath && isBlockedFile(filePath, config.blockedFilePatterns)) {
          const message = `Security: Cannot read sensitive file '${filePath}'`
          
          logger.log({
            service: "context-protector",
            level: "warn",
            message,
            extra: { tool, filePath, patterns: config.blockedFilePatterns },
          })
          
          if (config.responseMode === "block") {
            throw new Error(`[CONTEXT-GUARD BLOCK] ${message}`)
          }
        }
      }

      // Skip backend check if not available
      if (!backendAvailable) {
        return
      }

      // Convert args to content string for checking
      const content = JSON.stringify(output.args)
      
      // Skip empty content
      if (!content || content === "{}") {
        return
      }

      const result = await checkContent(content, "tool_input", logger)

      if (!result.safe && result.alert) {
        const message = formatAlert(result.alert.explanation, config.responseMode, tool)

        if (config.responseMode === "block") {
          logger.log({
            service: "context-protector",
            level: "error",
            message: `Blocked tool execution: ${result.alert.explanation}`,
            extra: { tool, ...result.alert.data },
          })
          throw new Error(message)
        } else {
          logger.log({
            service: "context-protector",
            level: "warn",
            message: result.alert.explanation,
            extra: { tool, ...result.alert.data },
          })
        }
      }
    },

    /**
     * Hook: After tool execution (PostToolUse equivalent)
     *
     * Checks tool output for malicious content.
     * Cannot block since tool already executed, but logs warnings.
     */
    "tool.execute.after": async (
      input: ToolExecuteInput,
      output: ToolExecuteAfterOutput
    ) => {
      const { tool } = input
      
      // Skip if tool is in skip list
      if (config.skipTools.includes(tool)) {
        return
      }

      // Skip if no output or backend not available
      if (!output.output || !backendAvailable) {
        return
      }

      // Use the output string directly
      const content = output.output

      // Skip empty content
      if (!content || content === "null" || content === "undefined") {
        return
      }

      const result = await checkContent(content, "tool_output", logger)

      if (!result.safe && result.alert) {
        const level = config.responseMode === "block" ? "error" : "warn"
        const message = formatAlert(result.alert.explanation, config.responseMode, tool)

        logger.log({
          service: "context-protector",
          level,
          message,
          extra: {
            tool,
            contentLength: content.length,
            ...result.alert.data,
          },
        })

        // Note: Cannot actually block post-execution, tool already ran
        // The warning is logged for awareness
      }
    },
  }
}

// Default export for convenience
export default ContextProtector
