export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly details?: unknown;
  public readonly isOperational: boolean;

  constructor(
    message: string,
    options: {
      statusCode?: number;
      code?: string;
      details?: unknown;
      isOperational?: boolean;
      cause?: unknown;
    } = {},
  ) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = options.statusCode ?? 500;
    this.code = options.code ?? "INTERNAL_SERVER_ERROR";
    this.details = options.details;
    this.isOperational = options.isOperational ?? true;

    if (options.cause) {
      this.cause = options.cause;
    }

    if (
      "captureStackTrace" in Error &&
      typeof (Error as any).captureStackTrace === "function"
    ) {
      (Error as any).captureStackTrace(this, this.constructor);
    }
  }
}

export class BadRequestError extends AppError {
  constructor(message = "Bad Request", details?: unknown) {
    super(message, { statusCode: 400, code: "BAD_REQUEST", details });
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = "Unauthorized", details?: unknown) {
    super(message, { statusCode: 401, code: "UNAUTHORIZED", details });
  }
}

export class ForbiddenError extends AppError {
  constructor(message = "Forbidden", details?: unknown) {
    super(message, { statusCode: 403, code: "FORBIDDEN", details });
  }
}

export class NotFoundError extends AppError {
  constructor(message = "Resource not found", details?: unknown) {
    super(message, { statusCode: 404, code: "NOT_FOUND", details });
  }
}

export class ConflictError extends AppError {
  constructor(message = "Conflict", details?: unknown) {
    super(message, { statusCode: 409, code: "CONFLICT", details });
  }
}

export class ValidationError extends AppError {
  constructor(message = "Validation failed", details?: unknown) {
    super(message, { statusCode: 422, code: "VALIDATION_ERROR", details });
  }
}

export class RateLimitError extends AppError {
  constructor(
    message = "Too many requests, please try again later",
    details?: unknown,
  ) {
    super(message, { statusCode: 429, code: "RATE_LIMIT_EXCEEDED", details });
  }
}

export class InternalServerError extends AppError {
  constructor(message = "Internal Server Error", details?: unknown) {
    super(message, {
      statusCode: 500,
      code: "INTERNAL_SERVER_ERROR",
      details,
      isOperational: false,
    });
  }
}

export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

export function normalizeError(error: unknown): {
  message: string;
  code: string;
  statusCode: number;
  details?: unknown;
} {
  if (isAppError(error)) {
    return {
      message: error.message,
      code: error.code,
      statusCode: error.statusCode,
      details: error.details,
    };
  }

  if (error instanceof Error) {
    return {
      message: error.message,
      code: "UNHANDLED_EXCEPTION",
      statusCode: 500,
    };
  }

  return {
    message: typeof error === "string" ? error : "An unexpected error occurred",
    code: "UNKNOWN_ERROR",
    statusCode: 500,
  };
}
