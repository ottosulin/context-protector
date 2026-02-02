/**
 * Tests for types module
 */

import { describe, expect, test } from "bun:test"
import { DEFAULT_CONFIG } from "../src/types"
import type {
  CheckResult,
  ContentType,
  GuardrailAlert,
  PluginConfig,
  ResponseMode,
} from "../src/types"

describe("DEFAULT_CONFIG", () => {
  test("has expected default values", () => {
    expect(DEFAULT_CONFIG.responseMode).toBe("warn")
    expect(DEFAULT_CONFIG.provider).toBe("LlamaFirewall")
    expect(DEFAULT_CONFIG.envProtection).toBe(true)
    expect(DEFAULT_CONFIG.debug).toBe(false)
  })

  test("has default blocked file patterns", () => {
    expect(DEFAULT_CONFIG.blockedFilePatterns).toContain(".env")
    expect(DEFAULT_CONFIG.blockedFilePatterns).toContain(".env.*")
    expect(DEFAULT_CONFIG.blockedFilePatterns).toContain("*.pem")
    expect(DEFAULT_CONFIG.blockedFilePatterns).toContain("*.key")
    expect(DEFAULT_CONFIG.blockedFilePatterns).toContain("credentials.json")
  })

  test("has empty skip tools by default", () => {
    expect(DEFAULT_CONFIG.skipTools).toEqual([])
  })
})

describe("Type definitions", () => {
  test("CheckResult types compile correctly", () => {
    const safeResult: CheckResult = {
      safe: true,
      alert: null,
    }
    expect(safeResult.safe).toBe(true)
    expect(safeResult.alert).toBeNull()

    const unsafeResult: CheckResult = {
      safe: false,
      alert: {
        explanation: "Malicious content detected",
        data: { severity: "high" },
      },
    }
    expect(unsafeResult.safe).toBe(false)
    expect(unsafeResult.alert?.explanation).toBe("Malicious content detected")
  })

  test("ContentType accepts valid values", () => {
    const inputType: ContentType = "tool_input"
    const outputType: ContentType = "tool_output"
    expect(inputType).toBe("tool_input")
    expect(outputType).toBe("tool_output")
  })

  test("ResponseMode accepts valid values", () => {
    const warn: ResponseMode = "warn"
    const block: ResponseMode = "block"
    expect(warn).toBe("warn")
    expect(block).toBe("block")
  })

  test("GuardrailAlert structure is correct", () => {
    const alert: GuardrailAlert = {
      explanation: "Test explanation",
      data: {
        detectionType: "injection",
        confidence: 0.95,
        nested: { key: "value" },
      },
    }
    expect(alert.explanation).toBe("Test explanation")
    expect(alert.data.detectionType).toBe("injection")
    expect(alert.data.confidence).toBe(0.95)
  })

  test("PluginConfig allows partial overrides", () => {
    const config: PluginConfig = {
      ...DEFAULT_CONFIG,
      responseMode: "block",
      debug: true,
    }
    expect(config.responseMode).toBe("block")
    expect(config.debug).toBe(true)
    expect(config.provider).toBe("LlamaFirewall") // From defaults
  })
})
