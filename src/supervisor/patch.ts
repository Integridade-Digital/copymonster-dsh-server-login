/**
 * cordis patch rendering for a child DSH. Always mounts the runtime plugin
 * (`dsh-server-login/runtime`), the host model-mask with the centralized LLM
 * routing policy, and the default agent model pointing to the virtual alias
 * (`copymonster/copy-monster-default`), plus any enabled plugins.
 *
 * This centralizes the LLM provider injection in `patches/main.yml`, ensuring
 * all tenants are served reliably while administrators manage routes in Settings > Models.
 * @module dsh-server-login/supervisor/patch
 */

export interface PatchRoutingPolicy {
  readonly primaryProvider?: string
  readonly primaryModel?: string
  readonly fallbackProvider?: string
  readonly fallbackModel?: string
  readonly failoverEnabled?: boolean
  readonly maxAttempts?: number
  readonly timeoutMs?: number
}

export interface RenderPatchOptions {
  readonly enabledPlugins?: readonly string[]
  readonly routingPolicy?: PatchRoutingPolicy
}

/** The runtime plugin patch row, mounted in every child DSH. */
const RUNTIME_ROW = '    - id: dsh-server-login-runtime\n      name: dsh-server-login/runtime'

const MODEL_MASK_BUNDLE = '@deepseek-ai/dsh-host-model-mask'
const AGENT_DEFAULT_MODEL_BUNDLE = '@deepseek-ai/dsh-agent-default-model'
const TENANT_MODEL_PROVIDER = 'copymonster'
const TENANT_MODEL_ID = 'copy-monster-default'

/** Default fallback routes if not explicitly provided or found in environment */
const DEFAULT_PRIMARY_PROVIDER = 'openrouter'
const DEFAULT_PRIMARY_MODEL = 'deepseek/deepseek-chat'
const DEFAULT_FALLBACK_PROVIDER = 'deepseek-official'
const DEFAULT_FALLBACK_MODEL = 'deepseek-chat'

export function resolveDefaultRoutingPolicy(): PatchRoutingPolicy {
  return {
    primaryProvider: process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_PROVIDER ?? DEFAULT_PRIMARY_PROVIDER,
    primaryModel: process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL ?? DEFAULT_PRIMARY_MODEL,
    fallbackProvider: process.env.DSH_SERVER_LOGIN_LLM_FALLBACK_PROVIDER ?? DEFAULT_FALLBACK_PROVIDER,
    fallbackModel: process.env.DSH_SERVER_LOGIN_LLM_FALLBACK_MODEL ?? DEFAULT_FALLBACK_MODEL,
    failoverEnabled: true,
    maxAttempts: 2,
    timeoutMs: 30000,
  }
}

/** Render a patch YAML for the child DSH, including runtime, model-mask, agent-default-model and enabledPlugins. */
export function renderPatch(
  pluginsOrOptions: readonly string[] | RenderPatchOptions = [],
  options?: RenderPatchOptions,
): string {
  const enabledPlugins: readonly string[] = Array.isArray(pluginsOrOptions)
    ? pluginsOrOptions
    : (pluginsOrOptions as RenderPatchOptions).enabledPlugins ?? []

  const policy: PatchRoutingPolicy = (Array.isArray(pluginsOrOptions)
    ? options?.routingPolicy
    : (pluginsOrOptions as RenderPatchOptions).routingPolicy)
    ?? resolveDefaultRoutingPolicy()

  const primaryProvider = policy.primaryProvider || DEFAULT_PRIMARY_PROVIDER
  const primaryModel = policy.primaryModel || DEFAULT_PRIMARY_MODEL
  const fallbackProvider = policy.fallbackProvider || DEFAULT_FALLBACK_PROVIDER
  const fallbackModel = policy.fallbackModel || DEFAULT_FALLBACK_MODEL
  const failoverEnabled = policy.failoverEnabled !== false
  const maxAttempts = policy.maxAttempts ?? 2
  const timeoutMs = policy.timeoutMs ?? 30000

  const modelMaskBlock = [
    `    - id: model-mask`,
    `      name: "${MODEL_MASK_BUNDLE}"`,
    `      config:`,
    `        virtualProvider: ${TENANT_MODEL_PROVIDER}`,
    `        virtualModel: ${TENANT_MODEL_ID}`,
    `        virtualModelName: Model CopyMonster`,
    `        primaryProvider: ${primaryProvider}`,
    `        primaryModel: ${primaryModel}`,
    `        fallbackProvider: ${fallbackProvider}`,
    `        fallbackModel: ${fallbackModel}`,
    `        fallbackPolicy:`,
    `          enabled: ${failoverEnabled}`,
    `          maxAttempts: ${maxAttempts}`,
    `          timeoutMs: ${timeoutMs}`,
    `        applyToTenantsOnly: true`,
  ].join('\n')

  const agentDefaultModelBlock = [
    `    - id: agent-default-model`,
    `      name: "${AGENT_DEFAULT_MODEL_BUNDLE}"`,
    `      config:`,
    `        provider: ${TENANT_MODEL_PROVIDER}`,
    `        model: ${TENANT_MODEL_ID}`,
  ].join('\n')

  const pluginRows = enabledPlugins.map((id: string) => `    - id: ${id}\n      name: ${id}`)

  const rows = [RUNTIME_ROW, modelMaskBlock, agentDefaultModelBlock, ...pluginRows]
  return `- insert:\n${rows.join('\n')}\n`
}
