// In-memory test double for Supabase server client
// Used strictly by test runner to verify database ownership filtering in route handlers

export interface MockStore {
  automations: Array<{ id: string; user_id: string; [key: string]: any }>
  conversations: Array<{ id: string; user_id: string; recipient_id: string; [key: string]: any }>
  messages: Array<{ id: string; conversation_id: string; user_id: string; [key: string]: any }>
  users: Array<{ id: string; access_token?: string; username?: string; [key: string]: any }>
  ice_breakers: Array<{ id: string; user_id: string; [key: string]: any }>
  webhook_events: Array<{ id: string; event_type: string; user_id?: any; data?: any; processed_at?: string }>
}

export const mockStore: MockStore = {
  automations: [],
  conversations: [],
  messages: [],
  users: [],
  ice_breakers: [],
  webhook_events: [],
}

export function resetMockStore() {
  mockStore.automations = []
  mockStore.conversations = []
  mockStore.messages = []
  mockStore.users = []
  mockStore.ice_breakers = []
  mockStore.webhook_events = []
}

class QueryBuilder {
  private table: string
  private filters: Array<{ field: string; value: any }> = []
  private orClauses: Array<Array<{ field: string; op: string; value: string }>> = []
  private isDelete = false
  private isUpdate = false
  private updateData: any = null
  private isSingle = false
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

  then(resolve: any, reject?: any) {
    return this.execute().then(resolve, reject)
  }

  private async execute() {
    let rows: any[] = [...((mockStore as any)[this.table] || [])]

    // Apply all .eq() filters
    for (const { field, value } of this.filters) {
      rows = rows.filter((r) => String(r[field]) === String(value))
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
      const remaining = ((mockStore as any)[this.table] || []).filter(
        (r: any) => !rows.some((del) => del.id === r.id)
      )
      ;(mockStore as any)[this.table] = remaining
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

    if (this.isSingle) {
      return { data: rows[0] || null, error: rows.length > 0 ? null : { message: "Row not found" } }
    }

    return { data: rows, error: null }
  }
}

export async function getSupabaseServerClient() {
  return {
    from: (table: string) => new QueryBuilder(table),
  }
}

