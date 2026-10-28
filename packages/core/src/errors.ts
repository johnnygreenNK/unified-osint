export class AppError extends Error {
  constructor(message: string, public readonly code: string, public readonly httpStatus: number) {
    super(message);
    this.name = "AppError";
  }
}

export class ValidationError extends AppError {
  constructor(message: string) {
    super(message, "validation_error", 400);
  }
}

export class NotFoundError extends AppError {
  constructor(message: string) {
    super(message, "not_found", 404);
  }
}

export class ForbiddenError extends AppError {
  constructor(message: string) {
    super(message, "forbidden", 403);
  }
}

export class LimitExceededError extends AppError {
  constructor(message: string) {
    super(message, "limit_exceeded", 429);
  }
}
