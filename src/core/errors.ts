export class AppError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message)
  }
}

export class StorageError extends Error {
  constructor(public conflict: boolean) {
    super(conflict ? 'Concurrent write or uniqueness conflict' : 'Storage unavailable')
  }
}

export function assert(condition: unknown, status: number, code: string, message: string): asserts condition {
  if (!condition) throw new AppError(status, code, message)
}
