/**
 * cordis patch rendering for a child DSH. Always mounts the runtime plugin
 * (`dsh-server-login/runtime`) and the default agent model pointing to the
 * virtual alias (`copymonster/copy-monster-default`), plus any enabled plugins.
 *
 * The host model-mask row is deliberately NOT rendered here: it lives in the
 * tenant profile patch that Settings > Models writes. Emitting it from this
 * overlay would make the overlay the higher-priority source and DSH would
 * reject admin writes with "overridden by a home patch or command-line overlay".
 * @module dsh-server-login/supervisor/patch
 */

export interface RenderPatchOptions {
  readonly enabledPlugins?: readonly string[]
}

/** The runtime plugin patch row, mounted in every child DSH. */
const RUNTIME_ROW = '    - id: dsh-server-login-runtime\n      name: dsh-server-login/runtime'

const AGENT_DEFAULT_MODEL_BUNDLE = '@deepseek-ai/dsh-agent-default-model'
const TENANT_MODEL_PROVIDER = 'copymonster'
const TENANT_MODEL_ID = 'copy-monster-default'

/**
 * Render a patch YAML for the child DSH, including runtime, agent-default-model
 * and enabledPlugins.
 * @param pluginsOrOptions enabled plugin ids, or an options object.
 * @param options enabled-plugin overrides when the first argument is an id list.
 * @returns the `- insert:` patch YAML text.
 */
export function renderPatch(
  pluginsOrOptions: readonly string[] | RenderPatchOptions = [],
  options?: RenderPatchOptions,
): string {
  const enabledPlugins: readonly string[] = Array.isArray(pluginsOrOptions)
    ? pluginsOrOptions
    : (pluginsOrOptions as RenderPatchOptions).enabledPlugins ?? options?.enabledPlugins ?? []

  const agentDefaultModelBlock = [
    `    - id: agent-default-model`,
    `      name: "${AGENT_DEFAULT_MODEL_BUNDLE}"`,
    `      config:`,
    `        provider: ${TENANT_MODEL_PROVIDER}`,
    `        model: ${TENANT_MODEL_ID}`,
  ].join('\n')

  const pluginRows = enabledPlugins.map((id: string) => `    - id: ${id}\n      name: ${id}`)

  const rows = [RUNTIME_ROW, agentDefaultModelBlock, ...pluginRows]
  return `- insert:\n${rows.join('\n')}\n`
}
