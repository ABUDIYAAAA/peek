export interface ApiSuccessResponse<T> {
  success: true;
  data: T;
  meta?: Record<string, unknown>;
  timestamp: string;
}

export interface ApiErrorDetail {
  code: string;
  message: string;
  details?: unknown;
}

export interface ApiErrorResponse {
  success: false;
  error: ApiErrorDetail;
  timestamp: string;
}

export type ApiResponse<T> = ApiSuccessResponse<T> | ApiErrorResponse;

export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export function apiSuccess<T>(
  data: T,
  meta?: Record<string, unknown>,
): ApiSuccessResponse<T> {
  return {
    success: true,
    data,
    ...(meta ? { meta } : {}),
    timestamp: new Date().toISOString(),
  };
}

export function apiPaginated<T>(
  data: T[],
  pagination: { page: number; limit: number; total: number },
  extraMeta?: Record<string, unknown>,
): ApiSuccessResponse<T[]> {
  const totalPages = Math.ceil(pagination.total / pagination.limit);
  const meta: PaginationMeta & Record<string, unknown> = {
    page: pagination.page,
    limit: pagination.limit,
    total: pagination.total,
    totalPages,
    hasNext: pagination.page < totalPages,
    hasPrev: pagination.page > 1,
    ...extraMeta,
  };

  return apiSuccess(data, meta);
}

export function apiError(
  message: string,
  options: {
    code?: string;
    details?: unknown;
  } = {},
): ApiErrorResponse {
  return {
    success: false,
    error: {
      code: options.code ?? "ERROR",
      message,
      ...(options.details !== undefined ? { details: options.details } : {}),
    },
    timestamp: new Date().toISOString(),
  };
}
