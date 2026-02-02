/**
 * Tests for the main plugin module
 */

import { describe, expect, test, mock, beforeEach, afterEach } from "bun:test"
import { ContextProtector, DEFAULT_CONFIG } from "../src/index"
import type { CheckResult } from "../src/types"

// Mock the backend module
const mockCheckWithBackend = mock(
  async (): Promise<CheckResult> => ({ safe: true, alert: null })
)
const mockIsBackendAvailable = mock(async () => true)

// Create a mock logger
function createMockLogger() {
  const logs: Array<{
    service: string
    level: string
    message: string
    extra?: Record<string, unknown>
  }> = []

  return {
    logs,
    log: mock(async (entry: typeof logs[0]) => {
      logs.push(entry)
    }),
  }
}

// Create mock context for plugin
function createMockContext(logger = createMockLogger()) {
  return {
    project: { name: "test-project" },
    client: { app: logger },
    $: mock(() => Promise.resolve("")),
    directory: "/test/project",
    worktree: "/test/project",
  }
}

describe("ContextProtector Plugin", () => {
  let originalEnv: Record<string, string | undefined>

  beforeEach(() => {
    // Save environment
    originalEnv = {
      CONTEXT_PROTECTOR_RESPONSE_MODE: process.env.CONTEXT_PROTECTOR_RESPONSE_MODE,
      CONTEXT_PROTECTOR_ENV_PROTECTION: process.env.CONTEXT_PROTECTOR_ENV_PROTECTION,
      CONTEXT_PROTECTOR_DEBUG: process.env.CONTEXT_PROTECTOR_DEBUG,
    }
    // Clear environment
    delete process.env.CONTEXT_PROTECTOR_RESPONSE_MODE
    delete process.env.CONTEXT_PROTECTOR_ENV_PROTECTION
    delete process.env.CONTEXT_PROTECTOR_DEBUG
  })

  afterEach(() => {
    // Restore environment
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value !== undefined) {
        process.env[key] = value
      } else {
        delete process.env[key]
      }
    }
  })

  describe("Plugin initialization", () => {
    test("exports ContextProtector function", () => {
      expect(typeof ContextProtector).toBe("function")
    })

    test("returns hooks object", async () => {
      const ctx = createMockContext()
      const hooks = await ContextProtector(ctx as any)
      expect(hooks).toHaveProperty("tool.execute.before")
      expect(hooks).toHaveProperty("tool.execute.after")
    })

    test("logs initialization message", async () => {
      const logger = createMockLogger()
      const ctx = createMockContext(logger)
      await ContextProtector(ctx as any)

      // Should have logged something
      expect(logger.logs.length).toBeGreaterThan(0)
    })
  })

  describe("tool.execute.before hook", () => {
    describe("file protection", () => {
      test("blocks .env file reads in block mode", async () => {
        process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
        const ctx = createMockContext()
        const hooks = await ContextProtector(ctx as any)
        const beforeHook = hooks["tool.execute.before"] as Function

        const input = { tool: "read" }
        const output = { args: { filePath: ".env" } }

        await expect(beforeHook(input, output)).rejects.toThrow(
          /CONTEXT-GUARD BLOCK.*Cannot read sensitive file/
        )
      })

      test("warns about .env file reads in warn mode", async () => {
        process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "warn"
        const logger = createMockLogger()
        const ctx = createMockContext(logger)
        const hooks = await ContextProtector(ctx as any)
        const beforeHook = hooks["tool.execute.before"] as Function

        const input = { tool: "read" }
        const output = { args: { filePath: "/path/to/.env" } }

        // Should not throw in warn mode
        await beforeHook(input, output)

        // Should have logged a warning
        const warnings = logger.logs.filter((l) => l.level === "warn")
        expect(warnings.length).toBeGreaterThan(0)
        expect(warnings.some((w) => w.message.includes(".env"))).toBe(true)
      })

      test("blocks .env.local file reads", async () => {
        process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
        const ctx = createMockContext()
        const hooks = await ContextProtector(ctx as any)
        const beforeHook = hooks["tool.execute.before"] as Function

        const input = { tool: "read" }
        const output = { args: { filePath: ".env.local" } }

        await expect(beforeHook(input, output)).rejects.toThrow(/Cannot read sensitive file/)
      })

      test("blocks .pem file reads", async () => {
        process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
        const ctx = createMockContext()
        const hooks = await ContextProtector(ctx as any)
        const beforeHook = hooks["tool.execute.before"] as Function

        const input = { tool: "read" }
        const output = { args: { filePath: "/ssl/server.pem" } }

        await expect(beforeHook(input, output)).rejects.toThrow(/Cannot read sensitive file/)
      })

      test("blocks credentials.json file reads", async () => {
        process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
        const ctx = createMockContext()
        const hooks = await ContextProtector(ctx as any)
        const beforeHook = hooks["tool.execute.before"] as Function

        const input = { tool: "read" }
        const output = { args: { filePath: "/gcp/credentials.json" } }

        await expect(beforeHook(input, output)).rejects.toThrow(/Cannot read sensitive file/)
      })

      test("allows normal file reads", async () => {
        process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
        const ctx = createMockContext()
        const hooks = await ContextProtector(ctx as any)
        const beforeHook = hooks["tool.execute.before"] as Function

        const input = { tool: "read" }
        const output = { args: { filePath: "src/index.ts" } }

        // Should not throw
        await beforeHook(input, output)
      })

      test("respects ENV_PROTECTION=false", async () => {
        process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
        process.env.CONTEXT_PROTECTOR_ENV_PROTECTION = "false"
        const ctx = createMockContext()
        const hooks = await ContextProtector(ctx as any)
        const beforeHook = hooks["tool.execute.before"] as Function

        const input = { tool: "read" }
        const output = { args: { filePath: ".env" } }

        // Should not throw when env protection is disabled
        await beforeHook(input, output)
      })
    })

    describe("skip tools", () => {
      test("skips tools in skip list", async () => {
        process.env.CONTEXT_PROTECTOR_SKIP_TOOLS = "read,write"
        const ctx = createMockContext()
        const hooks = await ContextProtector(ctx as any)
        const beforeHook = hooks["tool.execute.before"] as Function

        const input = { tool: "read" }
        const output = { args: { filePath: ".env" } }

        // Should not throw because 'read' is in skip list
        await beforeHook(input, output)
      })
    })

    describe("empty content handling", () => {
      test("skips empty args", async () => {
        const ctx = createMockContext()
        const hooks = await ContextProtector(ctx as any)
        const beforeHook = hooks["tool.execute.before"] as Function

        const input = { tool: "bash" }
        const output = { args: {} }

        // Should not throw or call backend
        await beforeHook(input, output)
      })
    })
  })

  describe("tool.execute.after hook", () => {
    test("skips when no result", async () => {
      const logger = createMockLogger()
      const ctx = createMockContext(logger)
      const hooks = await ContextProtector(ctx as any)
      const afterHook = hooks["tool.execute.after"] as Function

      const input = { tool: "bash" }
      const output = { args: {}, result: undefined }

      await afterHook(input, output)

      // Should not log any warnings
      const warnings = logger.logs.filter(
        (l) => l.level === "warn" && l.message.includes("CONTEXT-GUARD")
      )
      expect(warnings).toHaveLength(0)
    })

    test("skips null result", async () => {
      const logger = createMockLogger()
      const ctx = createMockContext(logger)
      const hooks = await ContextProtector(ctx as any)
      const afterHook = hooks["tool.execute.after"] as Function

      const input = { tool: "bash" }
      const output = { args: {}, result: null }

      await afterHook(input, output)
    })

    test("skips tools in skip list", async () => {
      process.env.CONTEXT_PROTECTOR_SKIP_TOOLS = "bash"
      const logger = createMockLogger()
      const ctx = createMockContext(logger)
      const hooks = await ContextProtector(ctx as any)
      const afterHook = hooks["tool.execute.after"] as Function

      const input = { tool: "bash" }
      const output = { args: {}, result: "some output" }

      await afterHook(input, output)
    })
  })

  describe("exports", () => {
    test("exports DEFAULT_CONFIG", () => {
      expect(DEFAULT_CONFIG).toBeDefined()
      expect(DEFAULT_CONFIG.responseMode).toBe("warn")
    })

    test("exports ContextProtector as default", async () => {
      const defaultExport = await import("../src/index")
      expect(defaultExport.default).toBe(ContextProtector)
    })
  })
})

describe("formatAlert helper", () => {
  // Test the alert formatting through the plugin behavior
  test("formats block alerts correctly", async () => {
    process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
    const ctx = createMockContext()
    const hooks = await ContextProtector(ctx as any)
    const beforeHook = hooks["tool.execute.before"] as Function

    const input = { tool: "read" }
    const output = { args: { filePath: ".env" } }

    try {
      await beforeHook(input, output)
    } catch (e) {
      expect((e as Error).message).toContain("[CONTEXT-GUARD BLOCK]")
    }
  })
})
