/**
 * Tests for config module
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import {
  loadConfigFromEnv,
  mergeConfig,
  isBlockedFile,
} from "../src/config"
import { DEFAULT_CONFIG } from "../src/types"

describe("loadConfigFromEnv", () => {
  // Store original env values
  const originalEnv: Record<string, string | undefined> = {}
  const envVars = [
    "CONTEXT_PROTECTOR_RESPONSE_MODE",
    "CONTEXT_PROTECTOR_PROVIDER",
    "CONTEXT_PROTECTOR_ENV_PROTECTION",
    "CONTEXT_PROTECTOR_BLOCKED_FILE_PATTERNS",
    "CONTEXT_PROTECTOR_SKIP_TOOLS",
    "CONTEXT_PROTECTOR_DEBUG",
  ]

  beforeEach(() => {
    // Save and clear env vars
    for (const key of envVars) {
      originalEnv[key] = process.env[key]
      delete process.env[key]
    }
  })

  afterEach(() => {
    // Restore env vars
    for (const key of envVars) {
      if (originalEnv[key] !== undefined) {
        process.env[key] = originalEnv[key]
      } else {
        delete process.env[key]
      }
    }
  })

  test("returns empty object when no env vars set", () => {
    const config = loadConfigFromEnv()
    expect(Object.keys(config)).toHaveLength(0)
  })

  test("parses RESPONSE_MODE correctly", () => {
    process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
    expect(loadConfigFromEnv().responseMode).toBe("block")

    process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "WARN"
    expect(loadConfigFromEnv().responseMode).toBe("warn")

    process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "Block"
    expect(loadConfigFromEnv().responseMode).toBe("block")
  })

  test("ignores invalid RESPONSE_MODE", () => {
    process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "invalid"
    expect(loadConfigFromEnv().responseMode).toBeUndefined()
  })

  test("parses PROVIDER correctly", () => {
    process.env.CONTEXT_PROTECTOR_PROVIDER = "NeMoGuardrails"
    expect(loadConfigFromEnv().provider).toBe("NeMoGuardrails")
  })

  test("parses ENV_PROTECTION boolean", () => {
    process.env.CONTEXT_PROTECTOR_ENV_PROTECTION = "true"
    expect(loadConfigFromEnv().envProtection).toBe(true)

    process.env.CONTEXT_PROTECTOR_ENV_PROTECTION = "false"
    expect(loadConfigFromEnv().envProtection).toBe(false)

    process.env.CONTEXT_PROTECTOR_ENV_PROTECTION = "1"
    expect(loadConfigFromEnv().envProtection).toBe(true)

    process.env.CONTEXT_PROTECTOR_ENV_PROTECTION = "0"
    expect(loadConfigFromEnv().envProtection).toBe(false)

    process.env.CONTEXT_PROTECTOR_ENV_PROTECTION = "on"
    expect(loadConfigFromEnv().envProtection).toBe(true)

    process.env.CONTEXT_PROTECTOR_ENV_PROTECTION = "off"
    expect(loadConfigFromEnv().envProtection).toBe(false)
  })

  test("parses BLOCKED_FILE_PATTERNS as comma-separated list", () => {
    process.env.CONTEXT_PROTECTOR_BLOCKED_FILE_PATTERNS = ".env,.secret,*.pem"
    expect(loadConfigFromEnv().blockedFilePatterns).toEqual([
      ".env",
      ".secret",
      "*.pem",
    ])
  })

  test("handles whitespace in BLOCKED_FILE_PATTERNS", () => {
    process.env.CONTEXT_PROTECTOR_BLOCKED_FILE_PATTERNS = " .env , .secret , *.pem "
    expect(loadConfigFromEnv().blockedFilePatterns).toEqual([
      ".env",
      ".secret",
      "*.pem",
    ])
  })

  test("handles empty BLOCKED_FILE_PATTERNS", () => {
    process.env.CONTEXT_PROTECTOR_BLOCKED_FILE_PATTERNS = ""
    expect(loadConfigFromEnv().blockedFilePatterns).toEqual(
      DEFAULT_CONFIG.blockedFilePatterns
    )
  })

  test("parses SKIP_TOOLS as comma-separated list", () => {
    process.env.CONTEXT_PROTECTOR_SKIP_TOOLS = "read,write"
    expect(loadConfigFromEnv().skipTools).toEqual(["read", "write"])
  })

  test("parses DEBUG boolean", () => {
    process.env.CONTEXT_PROTECTOR_DEBUG = "true"
    expect(loadConfigFromEnv().debug).toBe(true)

    process.env.CONTEXT_PROTECTOR_DEBUG = "yes"
    expect(loadConfigFromEnv().debug).toBe(true)
  })
})

describe("mergeConfig", () => {
  beforeEach(() => {
    // Clear all env vars
    delete process.env.CONTEXT_PROTECTOR_RESPONSE_MODE
    delete process.env.CONTEXT_PROTECTOR_PROVIDER
  })

  test("returns defaults when no overrides", () => {
    const config = mergeConfig()
    expect(config).toEqual(DEFAULT_CONFIG)
  })

  test("merges provided config with defaults", () => {
    const config = mergeConfig({ responseMode: "block" })
    expect(config.responseMode).toBe("block")
    expect(config.provider).toBe("LlamaFirewall") // From defaults
  })

  test("env vars override provided config", () => {
    process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
    const config = mergeConfig({ responseMode: "warn" })
    expect(config.responseMode).toBe("block")
  })

  test("merges all three sources correctly", () => {
    process.env.CONTEXT_PROTECTOR_RESPONSE_MODE = "block"
    const config = mergeConfig({
      provider: "NeMoGuardrails",
      debug: true,
    })
    expect(config.responseMode).toBe("block") // From env
    expect(config.provider).toBe("NeMoGuardrails") // From provided
    expect(config.debug).toBe(true) // From provided
    expect(config.envProtection).toBe(true) // From defaults
  })
})

describe("isBlockedFile", () => {
  const patterns = DEFAULT_CONFIG.blockedFilePatterns

  describe("exact match", () => {
    test("matches .env exactly", () => {
      expect(isBlockedFile(".env", patterns)).toBe(true)
      expect(isBlockedFile("/path/to/.env", patterns)).toBe(true)
      expect(isBlockedFile("project/.env", patterns)).toBe(true)
    })

    test("matches credentials.json exactly", () => {
      expect(isBlockedFile("credentials.json", patterns)).toBe(true)
      expect(isBlockedFile("/path/credentials.json", patterns)).toBe(true)
    })
  })

  describe("prefix match (.env.*)", () => {
    test("matches .env.local", () => {
      expect(isBlockedFile(".env.local", patterns)).toBe(true)
    })

    test("matches .env.production", () => {
      expect(isBlockedFile(".env.production", patterns)).toBe(true)
    })

    test("matches .env.development", () => {
      expect(isBlockedFile(".env.development", patterns)).toBe(true)
    })
  })

  describe("extension match (*.pem, *.key)", () => {
    test("matches .pem files", () => {
      expect(isBlockedFile("server.pem", patterns)).toBe(true)
      expect(isBlockedFile("/ssl/private.pem", patterns)).toBe(true)
    })

    test("matches .key files", () => {
      expect(isBlockedFile("private.key", patterns)).toBe(true)
      expect(isBlockedFile("/ssh/id_rsa.key", patterns)).toBe(true)
    })
  })

  describe("non-matching files", () => {
    test("allows regular source files", () => {
      expect(isBlockedFile("index.ts", patterns)).toBe(false)
      expect(isBlockedFile("src/main.py", patterns)).toBe(false)
    })

    test("allows config files", () => {
      expect(isBlockedFile("package.json", patterns)).toBe(false)
      expect(isBlockedFile("tsconfig.json", patterns)).toBe(false)
    })

    test("allows README files", () => {
      expect(isBlockedFile("README.md", patterns)).toBe(false)
    })

    test("does not match partial names", () => {
      expect(isBlockedFile(".environment", patterns)).toBe(false)
      expect(isBlockedFile("env.js", patterns)).toBe(false)
    })
  })

  describe("custom patterns", () => {
    test("works with custom patterns", () => {
      const customPatterns = [".secret", "*.enc"]
      expect(isBlockedFile(".secret", customPatterns)).toBe(true)
      expect(isBlockedFile("data.enc", customPatterns)).toBe(true)
      expect(isBlockedFile(".env", customPatterns)).toBe(false)
    })

    test("works with empty patterns", () => {
      expect(isBlockedFile(".env", [])).toBe(false)
      expect(isBlockedFile("any-file.txt", [])).toBe(false)
    })
  })
})
