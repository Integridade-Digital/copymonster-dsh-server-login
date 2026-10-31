/**
 * Supabase client singleton for Auth operations.
 * @module dsh-server-login/supabase
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js'
import type { ServerConfig } from './config.js'

let supabaseClient: SupabaseClient | undefined

export function getSupabaseClient(config: ServerConfig): SupabaseClient {
  if (supabaseClient !== undefined) return supabaseClient
  supabaseClient = createClient(config.supabaseUrl, config.supabaseAnonKey)
  return supabaseClient
}

export function resetSupabaseClientForTest(): void {
  supabaseClient = undefined
}