/**
 * Configuration handling for Context Protector plugin
 */

import {
  DEFAULT_CONFIG,
  type PluginConfig,
  type ResponseMode,
} from "./types.js"

/**
 * Environment variable prefix
 */
const ENV_PREFIX = "CONTEXT_PROTECTOR_"

/**
 * Parse a boolean from environment variable
 */
function parseBool(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue
  const lower = value.toLowerCase()
  return lower === "true" || lower === "1" || lower === "on" || lower === "yes"
}

/**
 * Parse a comma-separated list from environment variable
 */
function parseList(value: string | undefined, defaultValue: string[]): string[] {
  if (value === undefined || value.trim() === "") return defaultValue
  return value.split(",").map((s) => s.trim()).filter(Boolean)
}

/**
 * Load configuration from environment variables
 */
export function loadConfigFromEnv(): Partial<PluginConfig> {
  const config: Partial<PluginConfig> = {}

  const responseMode = process.env[`${ENV_PREFIX}RESPONSE_MODE`]
  if (responseMode) {
    const lower = responseMode.toLowerCase()
    if (lower === "warn" || lower === "block") {
      config.responseMode = lower as ResponseMode
    }
  }

  const provider = process.env[`${ENV_PREFIX}PROVIDER`]
  if (provider) {
    config.provider = provider
  }

  const envProtection = process.env[`${ENV_PREFIX}ENV_PROTECTION`]
  if (envProtection !== undefined) {
    config.envProtection = parseBool(envProtection, DEFAULT_CONFIG.envProtection)
  }

  const blockedPatterns = process.env[`${ENV_PREFIX}BLOCKED_FILE_PATTERNS`]
  if (blockedPatterns !== undefined) {
    config.blockedFilePatterns = parseList(blockedPatterns, DEFAULT_CONFIG.blockedFilePatterns)
  }

  const skipTools = process.env[`${ENV_PREFIX}SKIP_TOOLS`]
  if (skipTools !== undefined) {
    config.skipTools = parseList(skipTools, DEFAULT_CONFIG.skipTools)
  }

  const debug = process.env[`${ENV_PREFIX}DEBUG`]
  if (debug !== undefined) {
    config.debug = parseBool(debug, DEFAULT_CONFIG.debug)
  }

  return config
}

/**
 * Merge configuration from multiple sources
 * Priority: Environment > Provided config > Defaults
 */
export function mergeConfig(provided?: Partial<PluginConfig>): PluginConfig {
  const envConfig = loadConfigFromEnv()
  
  return {
    ...DEFAULT_CONFIG,
    ...provided,
    ...envConfig,
  }
}

/**
 * Check if a file path matches any of the blocked patterns
 */
export function isBlockedFile(filePath: string, patterns: string[]): boolean {
  const fileName = filePath.split("/").pop() || filePath
  
  for (const pattern of patterns) {
    // Simple glob matching
    if (pattern.startsWith("*.")) {
      // Extension match: *.pem, *.key
      const ext = pattern.slice(1) // .pem, .key
      if (fileName.endsWith(ext)) return true
    } else if (pattern.endsWith(".*")) {
      // Prefix match: .env.*
      const prefix = pattern.slice(0, -1) // .env.
      if (fileName.startsWith(prefix)) return true
    } else {
      // Exact match
      if (fileName === pattern) return true
      // Path contains
      if (filePath.includes(`/${pattern}`) || filePath.endsWith(pattern)) return true
    }
  }
  
  return false
}
