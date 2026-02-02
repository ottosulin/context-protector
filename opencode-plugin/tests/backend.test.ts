/**
 * Tests for backend module
 */

import { describe, expect, test, mock, spyOn } from "bun:test"
import {
  BackendError,
  safeResult,
  errorResult,
} from "../src/backend"

describe("BackendError", () => {
  test("creates error with message only", () => {
    const error = new BackendError("Test error")
    expect(error.message).toBe("Test error")
    expect(error.name).toBe("BackendError")
    expect(error.code).toBeUndefined()
    expect(error.stderr).toBeUndefined()
  })

  test("creates error with code and stderr", () => {
    const error = new BackendError("Test error", 1, "stderr output")
    expect(error.message).toBe("Test error")
    expect(error.code).toBe(1)
    expect(error.stderr).toBe("stderr output")
  })

  test("is instanceof Error", () => {
    const error = new BackendError("Test error")
    expect(error instanceof Error).toBe(true)
    expect(error instanceof BackendError).toBe(true)
  })
})

describe("safeResult", () => {
  test("returns safe=true with null alert", () => {
    const result = safeResult()
    expect(result.safe).toBe(true)
    expect(result.alert).toBeNull()
  })

  test("returns new object each time", () => {
    const result1 = safeResult()
    const result2 = safeResult()
    expect(result1).not.toBe(result2)
    expect(result1).toEqual(result2)
  })
})

describe("errorResult", () => {
  test("returns safe=true with error alert", () => {
    const result = errorResult("Something went wrong")
    expect(result.safe).toBe(true) // Fail open
    expect(result.alert).not.toBeNull()
    expect(result.alert?.explanation).toBe("Backend error: Something went wrong")
    expect(result.alert?.data.error).toBe(true)
  })

  test("includes full error message", () => {
    const result = errorResult("Connection refused to context-protector backend")
    expect(result.alert?.explanation).toContain("Connection refused")
  })
})

// Note: Integration tests for checkWithBackend and isBackendAvailable
// require the Python backend to be installed. These are tested separately
// in the integration test suite.

describe("checkWithBackend integration", () => {
  // These tests are skipped if the backend is not available
  // They serve as documentation for the expected behavior

  test.todo("returns safe result for benign content")
  test.todo("returns alert for malicious content")
  test.todo("handles timeout correctly")
  test.todo("handles backend process errors")
  test.todo("parses JSON response correctly")
})

describe("isBackendAvailable integration", () => {
  test.todo("returns true when context-protector is installed")
  test.todo("returns false when context-protector is not installed")
  test.todo("times out after 2 seconds")
})
