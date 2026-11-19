/**
 * The LLM credential every tenant runs on: the platform's own DeepSeek key from
 * the server environment. Tenants never receive a personal key, so a key saved
 * earlier cannot shadow a fixed platform key.
 * @param env - process environment of the control plane.
 * @returns the trimmed platform key, or null when the platform has none set.
 */
export function platformApiKey(env: NodeJS.ProcessEnv): string | null {
  const key = env.DEEPSEEK_API_KEY?.trim()
  return key === undefined || key === '' ? null : key
}
