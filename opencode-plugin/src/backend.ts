/**
 * Python backend wrapper for Context Protector
 * 
 * Calls the `context-protector --check` CLI command via subprocess
 * to perform actual content checking.
 */

import { spawn } from "child_process"
import type { CheckResult, ContentType } from "./types.js"

/**
 * Default timeout for backend calls (10 seconds)
 */
const DEFAULT_TIMEOUT_MS = 10_000

/**
 * Check if the Python backend is available
 */
export async function isBackendAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn("context-protector", ["--version"], {
      stdio: ["ignore", "pipe", "ignore"],
    })
    
    proc.on("error", () => resolve(false))
    proc.on("close", (code) => resolve(code === 0))
    
    // Timeout after 2 seconds
    setTimeout(() => {
      proc.kill()
      resolve(false)
    }, 2000)
  })
}

/**
 * Error thrown when the backend fails
 */
export class BackendError extends Error {
  public readonly code?: number
  public readonly stderr?: string

  constructor(message: string, code?: number, stderr?: string) {
    super(message)
    this.code = code
    this.stderr = stderr
    this.name = "BackendError"
    Object.setPrototypeOf(this, BackendError.prototype)
  }
}

/**
 * Check content using the Python backend
 * 
 * @param content - Content to check
 * @param type - Type of content (tool_input or tool_output)
 * @param timeoutMs - Timeout in milliseconds
 * @returns CheckResult with safe status and optional alert
 * @throws BackendError if the backend fails
 */
export async function checkWithBackend(
  content: string,
  type: ContentType,
  timeoutMs: number = DEFAULT_TIMEOUT_MS
): Promise<CheckResult> {
  const input = JSON.stringify({ content, type })
  
  return new Promise((resolve, reject) => {
    const proc = spawn("context-protector", ["--check"], {
      stdio: ["pipe", "pipe", "pipe"],
    })
    
    let stdout = ""
    let stderr = ""
    let timedOut = false
    
    // Set timeout
    const timeout = setTimeout(() => {
      timedOut = true
      proc.kill("SIGTERM")
      reject(new BackendError("Backend timeout", undefined, undefined))
    }, timeoutMs)
    
    proc.stdout.on("data", (data: Buffer) => {
      stdout += data.toString()
    })
    
    proc.stderr.on("data", (data: Buffer) => {
      stderr += data.toString()
    })
    
    proc.on("error", (err) => {
      clearTimeout(timeout)
      reject(new BackendError(`Failed to spawn backend: ${err.message}`))
    })
    
    proc.on("close", (code) => {
      clearTimeout(timeout)
      
      if (timedOut) return
      
      if (code !== 0) {
        reject(new BackendError(
          `Backend exited with code ${code}`,
          code ?? undefined,
          stderr || undefined
        ))
        return
      }
      
      try {
        const result = JSON.parse(stdout.trim()) as CheckResult
        resolve(result)
      } catch (err) {
        reject(new BackendError(
          `Failed to parse backend response: ${stdout}`,
          code ?? undefined,
          stderr || undefined
        ))
      }
    })
    
    // Write input and close stdin
    proc.stdin.write(input)
    proc.stdin.end()
  })
}

/**
 * Create a safe check result (for when backend is unavailable)
 */
export function safeResult(): CheckResult {
  return { safe: true, alert: null }
}

/**
 * Create an error check result
 */
export function errorResult(message: string): CheckResult {
  return {
    safe: true, // Fail open - don't block on errors
    alert: {
      explanation: `Backend error: ${message}`,
      data: { error: true },
    },
  }
}
