export type Scalar = string | number | null
export type Statement = { sql: string; params?: Scalar[] }
export type Row = Record<string, Scalar>

export interface Database {
  all<T>(sql: string, params?: Scalar[]): Promise<T[]>
  // A batch must commit all statements atomically or roll back every statement.
  batch(statements: Statement[]): Promise<void>
}

export async function first<T>(db: Database, sql: string, params: Scalar[] = []): Promise<T | undefined> {
  return (await db.all<T>(sql, params))[0]
}
