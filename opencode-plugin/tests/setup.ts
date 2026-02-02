/**
 * Test setup file for Bun test runner
 */

// Clear environment before each test suite
beforeAll(() => {
  // Ensure clean environment for tests
  const envVars = [
    "CONTEXT_PROTECTOR_RESPONSE_MODE",
    "CONTEXT_PROTECTOR_PROVIDER",
    "CONTEXT_PROTECTOR_ENV_PROTECTION",
    "CONTEXT_PROTECTOR_BLOCKED_FILE_PATTERNS",
    "CONTEXT_PROTECTOR_SKIP_TOOLS",
    "CONTEXT_PROTECTOR_DEBUG",
  ]
  
  for (const key of envVars) {
    delete process.env[key]
  }
})
