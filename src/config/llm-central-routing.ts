/**
 * Centralized LLM routing & mask contract for tenants.
 * Stored in Supabase `public.system_config` under key `llm.central_routing`.
 * @module dsh-server-login/config/llm-central-routing
 */

import { z } from 'zod'

export const SYSTEM_CONFIG_LLM_ROUTING_KEY = 'llm.central_routing'

/**
 * Single step in an LLM failover fallback chain.
 */
export const FallbackChainStepSchema = z.object({
  provider: z.string().min(1),
  model: z.string().min(1),
  maxRetries: z.number().int().min(0).max(5).default(1),
  timeoutMs: z.number().int().min(1000).max(60000).default(15000),
})

export type FallbackChainStep = z.infer<typeof FallbackChainStepSchema>

/**
 * Failover configuration schema.
 */
export const FailoverConfigSchema = z.object({
  enabled: z.boolean().default(true),
  primary: z.object({
    provider: z.string().min(1),
    model: z.string().min(1),
  }),
  chain: z.array(FallbackChainStepSchema).default([]),
})

export type FailoverConfig = z.infer<typeof FailoverConfigSchema>

/**
 * Model masking configuration for tenants.
 */
export const MaskConfigSchema = z.object({
  enabled: z.boolean().default(true),
  publicModelId: z.string().min(1).default('copy-monster-default'),
  publicModelName: z.string().min(1).default('Model CopyMonster'),
  /**
   * The mask applies strictly to tenant profiles/sessions.
   * Admins retain full visibility into real underlying models for audit/configuration.
   */
  applyToTenantsOnly: z.literal(true).default(true),
})

export type MaskConfig = z.infer<typeof MaskConfigSchema>

/**
 * Route slot for specialized model routing (lightweight vs heavy tasks).
 */
export const RouteSlotSchema = z.object({
  provider: z.string().min(1),
  model: z.string().min(1),
  tasks: z.array(z.string()).default([]),
})

export type RouteSlot = z.infer<typeof RouteSlotSchema>

/**
 * Intelligent task-based routing configuration.
 */
export const RoutingConfigSchema = z.object({
  light: RouteSlotSchema,
  heavy: RouteSlotSchema,
})

export type RoutingConfig = z.infer<typeof RoutingConfigSchema>

/**
 * Full schema for `llm.central_routing` in `public.system_config`.
 */
export const CentralRoutingConfigSchema = z.object({
  version: z.number().int().min(1).default(1),
  updatedAt: z.string().datetime().optional(),
  mask: MaskConfigSchema,
  routing: RoutingConfigSchema,
  failover: FailoverConfigSchema,
})

export type CentralRoutingConfig = z.infer<typeof CentralRoutingConfigSchema>

/**
 * Minimal valid routing configuration template.
 * The Admin MUST configure the primary provider and model via Settings > Models.
 * This template provides only structural defaults (mask, empty routing slots, failover disabled).
 * It does NOT contain any hardcoded provider — the gateway will fail explicitly if primary is not set.
 */
export const DEFAULT_CENTRAL_ROUTING_CONFIG: CentralRoutingConfig = {
  version: 1,
  mask: {
    enabled: true,
    publicModelId: 'copy-monster-default',
    publicModelName: 'Model CopyMonster',
    applyToTenantsOnly: true,
  },
  routing: {
    light: {
      provider: '',
      model: '',
      tasks: ['summarization', 'chat_title', 'search', 'quick_reply'],
    },
    heavy: {
      provider: '',
      model: '',
      tasks: ['code_refactor', 'long_form_copy', 'complex_reasoning'],
    },
  },
  failover: {
    enabled: false,
    primary: {
      provider: '',
      model: '',
    },
    chain: [],
  },
}

/**
 * Safely parse untrusted configuration from JSON or Supabase system_config.
 * @throws {z.ZodError} if validation fails.
 */
export function parseCentralRoutingConfig(input: unknown): CentralRoutingConfig {
  return CentralRoutingConfigSchema.parse(input)
}
