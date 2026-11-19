/**
 * The LLM credentials every tenant runs on: platform keys from the server environment.
 * Tenants never receive a personal key, so a key saved earlier cannot shadow a fixed platform key.
 *
 * Forwards DEEPSEEK_API_KEY, OPENROUTER_API_KEY, and OPENAI_API_KEY when present.
 * @module dsh-server-login/supervisor/platform-key
 */

/**
 * Return the platform DeepSeek key, or null if unset.
 * Kept for backwards-compatibility.
 * @param env - process environment of the control plane.
 * @returns the trimmed platform key, or null when the platform has none set.
 */
export function platformApiKey(env: NodeJS.ProcessEnv): string | null {
  const key = env.DEEPSEEK_API_KEY?.trim()
  return key === undefined || key === '' ? null : key
}

/**
 * Return all platform API keys available in the control plane environment.
 * Injects each key into child DSH processes so whatever provider is active
 * (primary or contingency failover) can authenticate successfully.
 * @param env - process environment of the control plane.
 * @returns record of environment variables with trimmed non-empty keys.
 */
export function platformApiKeys(env: NodeJS.ProcessEnv): Record<string, string> {
  const keys: Record<string, string> = {}
  const deepseek = env.DEEPSEEK_API_KEY?.trim()
  if (deepseek) keys.DEEPSEEK_API_KEY = deepseek

  const openrouter = env.OPENROUTER_API_KEY?.trim()
  if (openrouter) keys.OPENROUTER_API_KEY = openrouter

  const openai = env.OPENAI_API_KEY?.trim()
  if (openai) keys.OPENAI_API_KEY = openai

  return keys
}
