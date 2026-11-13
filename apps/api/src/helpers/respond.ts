import type { Context } from "hono";
import {
  apiSuccess,
  apiError,
  apiPaginated,
  type ApiSuccessResponse,
  type ApiErrorResponse,
} from "@peek/core";
import type { ContentfulStatusCode } from "hono/utils/http-status";

export function respondSuccess<T>(
  c: Context,
  data: T,
  meta?: Record<string, unknown>,
  status: ContentfulStatusCode = 200,
): Response {
  return c.json<ApiSuccessResponse<T>, ContentfulStatusCode>(
    apiSuccess(data, meta),
    status,
  );
}

export function respondPaginated<T>(
  c: Context,
  data: T[],
  pagination: { page: number; limit: number; total: number },
  extraMeta?: Record<string, unknown>,
  status: ContentfulStatusCode = 200,
): Response {
  return c.json<ApiSuccessResponse<T[]>, ContentfulStatusCode>(
    apiPaginated(data, pagination, extraMeta),
    status,
  );
}

export function respondError(
  c: Context,
  message: string,
  options: {
    code?: string;
    details?: unknown;
    status?: ContentfulStatusCode;
  } = {},
): Response {
  const status: ContentfulStatusCode = options.status ?? 500;
  return c.json<ApiErrorResponse, ContentfulStatusCode>(
    apiError(message, { code: options.code, details: options.details }),
    status,
  );
}
