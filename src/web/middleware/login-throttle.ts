/**
 * Per-account login throttling.
 *
 * `@fastify/rate-limit` bounds attempts per client address, which a caller can
 * dodge by changing address (or by rotating a proxy header) while hammering one
 * account. This tracker bounds attempts per account instead: each failure
 * records one strike, and the wait before the next attempt grows with the
 * strike count, so guessing a password costs progressively more even when the
 * source address keeps changing.
 *
 * State lives in the server process. A restarted process starts every account
 * from zero strikes, which is the safe direction: it never locks a legitimate
 * user out across a deploy.
 * @module dsh-server-login/web/middleware/login-throttle
 */

/** Attempts allowed before the first delay applies. */
export const LOGIN_FREE_ATTEMPTS = 10

/** Longest wait a single account accumulates, in milliseconds. */
export const LOGIN_MAX_DELAY_MS = 15 * 60 * 1000

/** Per-account record: failure count and when the count was last raised. */
interface AccountState {
  strikes: number
  lastStrikeAt: number
}

/** Outcome of a pre-attempt check. */
export interface ThrottleDecision {
  /** Whether the attempt may proceed now. */
  readonly allowed: boolean
  /** Milliseconds the caller must wait when refused. */
  readonly retryAfterMs: number
  /** Strikes already recorded for the account. */
  readonly strikes: number
}

/** Bounds and clock for one tracker; all defaulted for production use. */
export interface LoginThrottleOptions {
  /** Failures tolerated before the first delay. */
  readonly freeAttempts?: number
  /** Ceiling for the exponential wait. */
  readonly maxDelayMs?: number
  /** Idle window after which an account's strikes are forgotten. */
  readonly resetAfterMs?: number
  /** Clock override for tests. */
  readonly now?: () => number
}

/**
 * Tracks failing login attempts per account handle (the submitted username,
 * lower-cased) and computes the wait before the next attempt.
 */
export class LoginThrottle {
  private readonly states = new Map<string, AccountState>()
  private readonly freeAttempts: number
  private readonly maxDelayMs: number
  private readonly resetAfterMs: number
  private readonly now: () => number

  /** @param options - bounds and clock; every field defaults. */
  constructor(options: LoginThrottleOptions = {}) {
    this.freeAttempts = options.freeAttempts ?? LOGIN_FREE_ATTEMPTS
    this.maxDelayMs = options.maxDelayMs ?? LOGIN_MAX_DELAY_MS
    this.resetAfterMs = options.resetAfterMs ?? LOGIN_MAX_DELAY_MS
    this.now = options.now ?? Date.now
  }

  /**
   * Decide whether an attempt may proceed.
   * @param account - the submitted account handle.
   * @returns the decision, including the wait still owed when refused.
   */
  check(account: string): ThrottleDecision {
    const key = account.trim().toLowerCase()
    const state = this.read(key)
    if (state === undefined) return { allowed: true, retryAfterMs: 0, strikes: 0 }

    const delay = this.delayFor(state.strikes)
    const elapsed = this.now() - state.lastStrikeAt
    const remaining = delay - elapsed
    if (remaining <= 0) return { allowed: true, retryAfterMs: 0, strikes: state.strikes }
    return { allowed: false, retryAfterMs: remaining, strikes: state.strikes }
  }

  /**
   * Record one failed attempt.
   * @param account - the submitted account handle.
   * @returns the strikes now recorded and the wait applied to the next attempt.
   */
  recordFailure(account: string): { strikes: number; delayMs: number } {
    const key = account.trim().toLowerCase()
    const previous = this.read(key)
    const strikes = (previous?.strikes ?? 0) + 1
    this.states.set(key, { strikes, lastStrikeAt: this.now() })
    return { strikes, delayMs: this.delayFor(strikes) }
  }

  /**
   * Clear an account after a successful login.
   * @param account - the account that authenticated.
   */
  recordSuccess(account: string): void {
    this.states.delete(account.trim().toLowerCase())
  }

  /** Current strikes for an account, for diagnostics and tests. */
  strikesFor(account: string): number {
    return this.read(account.trim().toLowerCase())?.strikes ?? 0
  }

  /**
   * Wait before the next attempt after `strikes` failures.
   *
   * Doubles per failure past the free allowance, capped at the configured
   * ceiling, so 10 failures are free, 11 cost 2s, 12 cost 4s, and the cap is
   * reached in a few more attempts.
   *
   * @param strikes - failures recorded so far.
   * @returns the delay in milliseconds.
   */
  private delayFor(strikes: number): number {
    if (strikes <= this.freeAttempts) return 0
    const exponent = strikes - this.freeAttempts - 1
    return Math.min(this.maxDelayMs, 2000 * 2 ** exponent)
  }

  /** Read an account's state, forgetting it once the reset window elapsed. */
  private read(key: string): AccountState | undefined {
    const state = this.states.get(key)
    if (state === undefined) return undefined
    if (this.now() - state.lastStrikeAt > this.resetAfterMs) {
      this.states.delete(key)
      return undefined
    }
    return state
  }
}

/** Process-wide tracker shared by the auth routes. */
export const loginThrottle = new LoginThrottle()
