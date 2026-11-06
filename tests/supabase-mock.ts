// In-memory test double for Supabase server client
// Used strictly by test runner to verify database ownership filtering in route handlers

export interface MockStore {
  automations: Array<{ id: string; user_id: string;[key: string]: any }>
  conversations: Array<{ id: string; user_id: string; recipient_id: string;[key: string]: any }>
  messages: Array<{ id: string; conversation_id: string; user_id: string;[key: string]: any }>
  users: Array<{ id: string; access_token?: string; username?: string;[key: string]: any }>
  ice_breakers: Array<{ id: string; user_id: string;[key: string]: any }>
  webhook_events: Array<{ id: string; event_type: string; user_id?: any; data?: any; processed_at?: string }>
  webhook_event_ledger: Array<{ id: string; event_key: string; event_type: string; user_id: any; status: string; attempt_count: number; max_attempts: number; retry_at?: string; lease_token?: string | null; lease_expires_at?: string | null; error_category?: string; error_code?: string; action_plan_sealed: boolean; data?: any; created_at?: string; updated_at?: string; completed_at?: string }>
  webhook_action_ledger: Array<{ id: string; event_id: string; action_key: string; action_type: string; status: string; attempt_count: number; max_attempts: number; retry_at?: string; lease_token?: string | null; lease_expires_at?: string | null; error_category?: string; error_code?: string; provider_message_id?: string; provider_status?: string; provider_payload_hash?: string; side_effect: boolean; created_at?: string; updated_at?: string; completed_at?: string }>
  queries: Array<{
    table: string
    filters: Array<{ field: string; value: any }>
    inFilters?: Array<{ field: string; values: any[] }>
    orClauses: Array<Array<{ field: string; op: string; value: string }>>
    isSingle: boolean
    isMaybeSingle?: boolean
    isDelete?: boolean
  }>
  failNextInsert?: boolean
  failNextDelete?: boolean
  failDeleteCount?: number
  throwNextDelete?: boolean
  deleteAppliesThenThrows?: boolean
  throwNextInsert?: boolean
  insertAppliesThenThrows?: boolean
  throwNextSelect?: boolean
  failNextUserSelect?: boolean
  throwNextUserSelect?: boolean
  rpcResults: Map<string, any>
  rpcErrors: Map<string, any>
  enforceRetryBackoff?: boolean
}

export const mockStore: MockStore = {
  automations: [],
  conversations: [],
  messages: [],
  users: [],
  ice_breakers: [],
  webhook_events: [],
  webhook_event_ledger: [],
  webhook_action_ledger: [],
  queries: [],
  rpcResults: new Map(),
  rpcErrors: new Map(),
  enforceRetryBackoff: false,
}

export function resetMockStore() {
  mockStore.automations = []
  mockStore.conversations = []
  mockStore.messages = []
  mockStore.users = []
  mockStore.ice_breakers = []
  mockStore.webhook_events = []
  mockStore.webhook_event_ledger = []
  mockStore.webhook_action_ledger = []
  mockStore.queries = []
  mockStore.failNextInsert = false
  mockStore.failNextDelete = false
  mockStore.failDeleteCount = 0
  mockStore.throwNextDelete = false
  mockStore.deleteAppliesThenThrows = false
  mockStore.throwNextInsert = false
  mockStore.insertAppliesThenThrows = false
  mockStore.throwNextSelect = false
  mockStore.failNextUserSelect = false
  mockStore.throwNextUserSelect = false
  mockStore.rpcResults = new Map()
  mockStore.rpcErrors = new Map()
  mockStore.enforceRetryBackoff = false
}

class QueryBuilder {
  private table: string
  private filters: Array<{ field: string; value: any }> = []
  private inFilters: Array<{ field: string; values: any[] }> = []
  private orClauses: Array<Array<{ field: string; op: string; value: string }>> = []
  private isDelete = false
  private isUpdate = false
  private updateData: any = null
  private isSingle = false
  private isMaybeSingle = false
  private isCount = false

  constructor(table: string) {
    this.table = table
  }

  select(_fields = "*", options?: { count?: string; head?: boolean }) {
    if (options?.count) this.isCount = true
    return this
  }

  delete(_options?: { count?: string }) {
    this.isDelete = true
    return this
  }

  update(data: any) {
    this.isUpdate = true
    this.updateData = data
    return this
  }

  insert(data: any) {
    if (mockStore.throwNextInsert) {
      mockStore.throwNextInsert = false
      throw new Error("Network connection dropped before INSERT response")
    }

    if (mockStore.insertAppliesThenThrows) {
      mockStore.insertAppliesThenThrows = false
      const list = Array.isArray(data) ? data : [data]
      const inserted = list.map((item) => ({
        id: item.id || `mock_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
        ...item,
      }))
      const tableData = (mockStore as any)[this.table] || []
      tableData.push(...inserted)
      throw new Error("Network response lost after INSERT applied")
    }

    if (mockStore.failNextInsert) {
      mockStore.failNextInsert = false
      const error = { code: "50000", message: "Simulated insert failure" }
      return {
        select: () => ({
          single: async () => ({ data: null, error }),
          then: (resolve: any) => resolve({ data: null, error }),
        }),
        then: (resolve: any) => resolve({ data: null, error }),
      }
    }

    const list = Array.isArray(data) ? data : [data]
    const tableData = (mockStore as any)[this.table] || []

    for (const item of list) {
      if (item.id && tableData.some((r: any) => String(r.id) === String(item.id))) {
        const error = { code: "23505", message: "duplicate key value violates unique constraint" }
        return {
          select: () => ({
            single: async () => ({ data: null, error }),
            then: (resolve: any) => resolve({ data: null, error }),
          }),
          then: (resolve: any) => resolve({ data: null, error }),
        }
      }
    }

    const inserted = list.map((item) => ({
      id: item.id || `mock_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      ...item,
    }))
    tableData.push(...inserted)
    return {
      select: () => ({
        single: async () => ({ data: inserted[0], error: null }),
        then: (resolve: any) => resolve({ data: inserted, error: null }),
      }),
      then: (resolve: any) => resolve({ data: inserted, error: null }),
    }
  }

  upsert(data: any, _options?: any) {
    const tableData = (mockStore as any)[this.table] || []
    const index = tableData.findIndex((row: any) => row.id === data.id)
    if (index >= 0) {
      tableData[index] = { ...tableData[index], ...data }
    } else {
      tableData.push(data)
    }
    return Promise.resolve({ error: null })
  }

  eq(field: string, value: any) {
    this.filters.push({ field, value })
    return this
  }

  in(field: string, values: any[]) {
    this.inFilters.push({ field, values: Array.isArray(values) ? values : [values] })
    return this
  }

  or(clause: string) {
    const conditions = clause.split(",").map((part) => {
      const pieces = part.trim().split(".")
      const field = pieces[0]
      const op = pieces[1]
      const value = pieces.slice(2).join(".")
      return { field, op, value }
    })
    this.orClauses.push(conditions)
    return this
  }

  order(_field: string, _opts?: any) {
    return this
  }

  limit(_n: number) {
    return this
  }

  single() {
    this.isSingle = true
    return this.execute()
  }

  maybeSingle() {
    this.isMaybeSingle = true
    return this.execute()
  }

  then(resolve: any, reject?: any) {
    return this.execute().then(resolve, reject)
  }

  private async execute() {
    if (mockStore.queries) {
      mockStore.queries.push({
        table: this.table,
        filters: [...this.filters],
        inFilters: [...this.inFilters],
        orClauses: [...this.orClauses],
        isSingle: this.isSingle,
        isMaybeSingle: this.isMaybeSingle,
        isDelete: this.isDelete,
      })
    }

    if (this.table === "users" && mockStore.throwNextUserSelect) {
      mockStore.throwNextUserSelect = false
      throw new Error("Simulated user lookup network failure")
    }
    if (this.table === "users" && mockStore.failNextUserSelect) {
      mockStore.failNextUserSelect = false
      return { data: null, error: { code: "50002", message: "Simulated user lookup failure" } }
    }
    if (mockStore.throwNextSelect) {
      mockStore.throwNextSelect = false
      throw new Error("Simulated query failure")
    }

    let rows: any[] = [...((mockStore as any)[this.table] || [])]

    // Apply all .eq() filters
    for (const { field, value } of this.filters) {
      rows = rows.filter((r) => String(r[field]) === String(value))
    }

    // Apply all .in() filters
    for (const { field, values } of this.inFilters) {
      const stringValues = values.map((v) => String(v))
      rows = rows.filter((r) => stringValues.includes(String(r[field])))
    }

    // Apply all .or() clauses
    for (const conditions of this.orClauses) {
      rows = rows.filter((row) =>
        conditions.some(({ field, op, value }) => {
          if (op === "eq") {
            return String(row[field]) === String(value)
          }
          return false
        })
      )
    }

    if (this.isDelete) {
      if (mockStore.throwNextDelete) {
        mockStore.throwNextDelete = false
        throw new Error("Network connection dropped before DELETE response")
      }
      if (mockStore.deleteAppliesThenThrows) {
        mockStore.deleteAppliesThenThrows = false
        const remaining = ((mockStore as any)[this.table] || []).filter(
          (r: any) => !rows.some((del) => del.id === r.id)
        )
          ; (mockStore as any)[this.table] = remaining
        throw new Error("Network connection dropped after DELETE applied")
      }
      if (mockStore.failNextDelete) {
        mockStore.failNextDelete = false
        return { data: null, error: { code: "50001", message: "Simulated delete failure" } }
      }
      if (typeof mockStore.failDeleteCount === "number" && mockStore.failDeleteCount > 0) {
        mockStore.failDeleteCount--
        return { data: null, error: { code: "50001", message: "Simulated delete failure" } }
      }
      const remaining = ((mockStore as any)[this.table] || []).filter(
        (r: any) => !rows.some((del) => del.id === r.id)
      )
        ; (mockStore as any)[this.table] = remaining
      return { data: null, error: null, count: rows.length }
    }

    if (this.isUpdate) {
      for (const row of rows) {
        Object.assign(row, this.updateData)
      }
      return { data: this.isSingle ? rows[0] || null : rows, error: null }
    }

    if (this.isCount) {
      return { count: rows.length, data: null, error: null }
    }

    if (this.isMaybeSingle) {
      return { data: rows[0] || null, error: null }
    }

    if (this.isSingle) {
      return { data: rows[0] || null, error: rows.length > 0 ? null : { message: "Row not found" } }
    }

    return { data: rows, error: null }
  }
}

export async function getSupabaseServerClient() {
  return {
    from: (table: string) => new QueryBuilder(table),
    rpc: async (fnName: string, params: any) => {
      const error = mockStore.rpcErrors?.get(fnName)
      if (error) {
        mockStore.rpcErrors.delete(fnName)
        return { data: null, error }
      }
      const result = mockStore.rpcResults?.get(fnName)
      if (result !== undefined) {
        mockStore.rpcResults.delete(fnName)
        return { data: result, error: null }
      }

      // --- fn_webhook_claim_event ---
      if (fnName === "fn_webhook_claim_event") {
        const { p_event_key, p_event_type, p_user_id, p_data, p_lease_ttl_seconds } = params as any
        if (mockStore.throwNextInsert) {
          mockStore.throwNextInsert = false
          throw new Error("Network connection dropped before INSERT response")
        }
        if (mockStore.failNextInsert) {
          mockStore.failNextInsert = false
          return { data: null, error: { code: "50000", message: "Simulated insert failure" } }
        }
        // Check for duplicate event_key
        const existing = mockStore.webhook_event_ledger.find((r) => r.event_key === p_event_key)
        if (existing) {
          if (existing.status === "completed") {
            return { data: { outcome: "duplicate_completed", event_id: existing.id, lease_token: null, lease_expires_at: null }, error: null }
          }
          if (existing.status === "manual_review") {
            return { data: { outcome: "manual_review", event_id: existing.id, lease_token: null, lease_expires_at: null }, error: null }
          }
          if (existing.status === "dead_letter") {
            return { data: { outcome: "dead_letter", event_id: existing.id, lease_token: null, lease_expires_at: null }, error: null }
          }
          if (existing.status === "claimed" && existing.lease_expires_at && new Date(existing.lease_expires_at) > new Date()) {
            return { data: { outcome: "active_lease", event_id: existing.id, lease_token: null, lease_expires_at: null }, error: null }
          }
            if (existing.status === "released" && mockStore.enforceRetryBackoff && existing.retry_at && new Date(existing.retry_at) > new Date()) {
              return { data: { outcome: "retry_not_due", event_id: existing.id, lease_token: null, lease_expires_at: null }, error: null }
            }
            // Reclaim expired lease
            existing.status = "claimed"
            existing.attempt_count = (existing.attempt_count || 0) + 1
            existing.lease_token = `evt_lease_${Date.now()}`
            existing.lease_expires_at = new Date(Date.now() + (p_lease_ttl_seconds || 300) * 1000).toISOString()
            existing.updated_at = new Date().toISOString()
            if (!mockStore.webhook_events.some((e) => e.id === existing.id)) {
              mockStore.webhook_events.push({
                id: existing.id,
                event_type: existing.event_type,
                user_id: existing.user_id,
                data: existing.data,
                processed_at: existing.created_at,
              })
            }
            return { data: { outcome: "reclaimed", event_id: existing.id, lease_token: existing.lease_token, lease_expires_at: existing.lease_expires_at }, error: null }
          }
          // Insert new event
          const newEvent = {
            id: `evt_${Date.now()}`,
            event_key: p_event_key,
            event_type: p_event_type,
            user_id: p_user_id,
            data: p_data,
            status: "claimed",
            attempt_count: 1,
            max_attempts: 5,
            lease_token: `evt_lease_${Date.now()}`,
            lease_expires_at: new Date(Date.now() + (p_lease_ttl_seconds || 300) * 1000).toISOString(),
            action_plan_sealed: false,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          }
          mockStore.webhook_event_ledger.push(newEvent)
          mockStore.webhook_events.push({
            id: newEvent.id,
            event_type: p_event_type,
            user_id: p_user_id,
            data: p_data,
            processed_at: newEvent.created_at,
          })
          return { data: { outcome: "created", event_id: newEvent.id, lease_token: newEvent.lease_token, lease_expires_at: newEvent.lease_expires_at }, error: null }
        }

        // --- fn_webhook_register_action_plan ---
      else if (fnName === "fn_webhook_register_action_plan") {
          const { p_event_id, p_actions } = params as any
          const event = mockStore.webhook_event_ledger.find((r) => r.id === p_event_id)
          if (!event) return { data: { outcome: "event_not_found", plan_sealed: false, action_count: 0 }, error: null }
          if (event.action_plan_sealed) return { data: { outcome: "plan_sealed", plan_sealed: true, action_count: 0 }, error: null }

          const actions = p_actions || []
          for (const a of actions) {
            mockStore.webhook_action_ledger.push({
              id: `act_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
              event_id: p_event_id,
              action_key: a.action_key,
              action_type: a.action_type,
              status: "pending",
              attempt_count: 0,
              max_attempts: 3,
              side_effect: a.side_effect,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            })
          }
          event.action_plan_sealed = true
          event.updated_at = new Date().toISOString()
          const count = mockStore.webhook_action_ledger.filter((a) => a.event_id === p_event_id).length
          return { data: { outcome: "plan_registered", plan_sealed: true, action_count: count }, error: null }
        }

        // --- fn_webhook_claim_action ---
      else if (fnName === "fn_webhook_claim_action") {
          const { p_event_id, p_action_key } = params as any
          const action = mockStore.webhook_action_ledger.find((a) => a.event_id === p_event_id && a.action_key === p_action_key)
          if (!action) return { data: { outcome: "action_not_registered", action_id: null, lease_token: null, lease_expires_at: null }, error: null }
          if (action.status === "unknown" || action.status === "permanently_failed") {
            return { data: { outcome: "action_terminal", action_id: action.id, lease_token: null, lease_expires_at: null }, error: null }
          }
          if (action.status === "completed") {
            return { data: { outcome: "action_completed", action_id: action.id, lease_token: null, lease_expires_at: null }, error: null }
          }
          if (action.status === "processing" && action.lease_expires_at && new Date(action.lease_expires_at) > new Date()) {
            return { data: { outcome: "action_active_lease", action_id: action.id, lease_token: null, lease_expires_at: null }, error: null }
          }
            if (action.status === "retryable" && mockStore.enforceRetryBackoff && action.retry_at && new Date(action.retry_at) > new Date()) {
              return { data: { outcome: "retry_not_due", action_id: action.id, lease_token: null, lease_expires_at: null }, error: null }
            }
            if (action.status === "processing" && action.lease_expires_at && new Date(action.lease_expires_at) <= new Date() && action.side_effect) {
              action.status = "unknown"
              action.lease_token = null
              action.lease_expires_at = null
              action.attempt_count = (action.attempt_count || 0) + 1
              action.updated_at = new Date().toISOString()
              return { data: { outcome: "action_expired_unknown", action_id: action.id, lease_token: null, lease_expires_at: null }, error: null }
            }
            action.status = "processing"
            action.attempt_count = (action.attempt_count || 0) + 1
            action.lease_token = `act_lease_${Date.now()}`
            action.lease_expires_at = new Date(Date.now() + 300000).toISOString()
            action.updated_at = new Date().toISOString()
            return { data: { outcome: "claimed", action_id: action.id, lease_token: action.lease_token, lease_expires_at: action.lease_expires_at }, error: null }
          }

          // --- fn_webhook_mark_action_complete ---
      else if (fnName === "fn_webhook_mark_action_complete") {
            const { p_action_id } = params as any
            const action = mockStore.webhook_action_ledger.find((a) => a.id === p_action_id)
            if (!action || action.status !== "processing") return { data: false, error: null }
            action.status = "completed"
            action.lease_token = null
            action.lease_expires_at = null
            action.completed_at = new Date().toISOString()
            action.updated_at = new Date().toISOString()
            if (params.p_provider_message_id) action.provider_message_id = params.p_provider_message_id
            if (params.p_provider_status) action.provider_status = params.p_provider_status
            return { data: true, error: null }
          }

          // --- fn_webhook_mark_action_retryable ---
      else if (fnName === "fn_webhook_mark_action_retryable") {
            const { p_action_id, p_backoff_base_seconds = 60, p_backoff_cap_seconds = 3600 } = params as any
            const action = mockStore.webhook_action_ledger.find((a) => a.id === p_action_id)
            if (!action || action.status !== "processing") return { data: false, error: null }
            if ((action.attempt_count || 0) >= (action.max_attempts || 3)) {
              action.status = "permanently_failed"
              action.lease_token = null
              action.lease_expires_at = null
              action.updated_at = new Date().toISOString()
              return { data: true, error: null }
            }
            action.status = "retryable"
            action.lease_token = null
            action.lease_expires_at = null
            action.retry_at = new Date(Date.now() + Math.min(p_backoff_base_seconds * Math.pow(2, (action.attempt_count || 0) - 1), p_backoff_cap_seconds) * 1000).toISOString()
            action.updated_at = new Date().toISOString()
            return { data: true, error: null }
          }

          // --- fn_webhook_mark_action_unknown ---
      else if (fnName === "fn_webhook_mark_action_unknown") {
            const { p_action_id } = params as any
            const action = mockStore.webhook_action_ledger.find((a) => a.id === p_action_id)
            if (!action || action.status !== "processing") return { data: false, error: null }
            action.status = "unknown"
            action.lease_token = null
            action.lease_expires_at = null
            action.updated_at = new Date().toISOString()
            if (params.p_provider_status) action.provider_status = params.p_provider_status
            return { data: true, error: null }
          }

          // --- fn_webhook_mark_action_permanently_failed ---
      else if (fnName === "fn_webhook_mark_action_permanently_failed") {
            const { p_action_id } = params as any
            const action = mockStore.webhook_action_ledger.find((a) => a.id === p_action_id)
            if (!action || action.status !== "processing") return { data: false, error: null }
            action.status = "permanently_failed"
            action.lease_token = null
            action.lease_expires_at = null
            action.updated_at = new Date().toISOString()
            return { data: true, error: null }
          }

          // --- fn_webhook_transition_event ---
      else if (fnName === "fn_webhook_transition_event") {
            const { p_event_id, p_target_status } = params as any
            const event = mockStore.webhook_event_ledger.find((r) => r.id === p_event_id)
            if (!event) return { data: false, error: null }
            if (p_target_status === "completed") {
              if (!event.action_plan_sealed) return { data: false, error: null }
              const incomplete = mockStore.webhook_action_ledger.filter((a) => a.event_id === p_event_id && a.status !== "completed")
              if (incomplete.length > 0) return { data: false, error: null }
            }
            event.status = p_target_status
            event.attempt_count = (event.attempt_count || 0) + 1
            event.lease_token = null
            event.lease_expires_at = null
            event.updated_at = new Date().toISOString()
            if (p_target_status === "completed") event.completed_at = new Date().toISOString()
            if (p_target_status === "released") {
              mockStore.webhook_events = mockStore.webhook_events.filter((e) => e.id !== p_event_id)
            }
            return { data: true, error: null }
          }

          // --- fn_webhook_transition_to_manual_review ---
      else if (fnName === "fn_webhook_transition_to_manual_review") {
            const { p_event_id } = params as any
            const event = mockStore.webhook_event_ledger.find((r) => r.id === p_event_id)
            if (!event) return { data: false, error: null }
            event.status = "manual_review"
            event.lease_token = null
            event.lease_expires_at = null
            event.updated_at = new Date().toISOString()
            mockStore.webhook_events = mockStore.webhook_events.filter((e) => e.id !== p_event_id)
            return { data: true, error: null }
          }

          // --- fn_webhook_renew_event_lease ---
      else if (fnName === "fn_webhook_renew_event_lease") {
            const { p_event_id } = params as any
            const event = mockStore.webhook_event_ledger.find((r) => r.id === p_event_id)
            if (!event || event.status !== "claimed") return { data: false, error: null }
            event.lease_expires_at = new Date(Date.now() + 300000).toISOString()
            event.updated_at = new Date().toISOString()
            return { data: true, error: null }
          }

          // --- fn_webhook_renew_action_lease ---
      else if (fnName === "fn_webhook_renew_action_lease") {
            const { p_action_id } = params as any
            const action = mockStore.webhook_action_ledger.find((a) => a.id === p_action_id)
            if (!action || action.status !== "processing") return { data: false, error: null }
            action.lease_expires_at = new Date(Date.now() + 300000).toISOString()
            action.updated_at = new Date().toISOString()
            return { data: true, error: null }
          }

          // --- fn_webhook_recover_expired_leases ---
      else if (fnName === "fn_webhook_recover_expired_leases") {
            return { data: { event_recoveries: 0, action_recoveries: 0, action_unknown_count: 0 }, error: null }
          }

          return { data: null, error: { code: "PGRST116", message: `Unknown RPC function: ${fnName}` } }
        },
      }
    }

