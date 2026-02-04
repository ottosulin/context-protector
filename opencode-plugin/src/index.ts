/**
 * Context Protector Plugin for OpenCode
 *
 * Protects AI coding agents from prompt injection attacks by scanning
 * tool inputs (before execution) and outputs (after execution).
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

async function checkContent(
  content: string,
  type: ContentType
): Promise<CheckResult> {
  try {
    return await checkWithBackend(content, type)
  } catch {
    return safeResult()
  }
}

const ContextProtector: Plugin = async (_ctx) => {
  const config = mergeConfig()
  const backendAvailable = await isBackendAvailable()

  return {
    "tool.execute.before": async (
      input: ToolExecuteInput,
      output: ToolExecuteBeforeOutput
    ) => {
      const { tool } = input

      if (config.skipTools.includes(tool)) {
        return
      }

      if (config.envProtection && tool === "read") {
        const filePath = output.args.filePath as string | undefined
        if (filePath && isBlockedFile(filePath, config.blockedFilePatterns)) {
          if (config.responseMode === "block") {
            throw new Error(`[CONTEXT-GUARD] Cannot read sensitive file: ${filePath}`)
          }
        }
      }

      if (!backendAvailable) {
        return
      }

      const content = JSON.stringify(output.args)
      if (!content || content === "{}") {
        return
      }

      const result = await checkContent(content, "tool_input")

      if (!result.safe && result.alert && config.responseMode === "block") {
        throw new Error(`[CONTEXT-GUARD] ${result.alert.explanation}`)
      }
    },

    "tool.execute.after": async (
      input: ToolExecuteInput,
      output: ToolExecuteAfterOutput
    ) => {
      const { tool } = input

      if (config.skipTools.includes(tool)) {
        return
      }

      if (!output.output || !backendAvailable) {
        return
      }

      const content = output.output
      if (!content || content === "null" || content === "undefined") {
        return
      }

      await checkContent(content, "tool_output")
    },
  }
}

export default ContextProtector
