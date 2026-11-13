import type { ErrorHandler } from "hono";
import {
  isAppError,
  apiError,
  zodIssuesToDetails,
  type ApiErrorResponse,
} from "@peek/core";
import { ZodError } from "zod";
import type { AppEnv } from "../types.js";
import type { ContentfulStatusCode } from "hono/utils/http-status";

export const errorHandler: ErrorHandler<AppEnv> = (err, c) => {
  const logger = c.get("logger");
  const isDev = (c.env?.ENVIRONMENT ?? "development") === "development";

  const errorMeta = {
    errorName: err.name,
    errorMessage: err.message,
    stack: err.stack,
    cause: err.cause,
  };

  if (logger) {
    if (isAppError(err) && err.statusCode < 500) {
      logger.warn(`Operational Error: ${err.message}`, {
        code: err.code,
        statusCode: err.statusCode,
        details: err.details,
      });
    } else {
      logger.error(`Unhandled Exception: ${err.message}`, errorMeta);
    }
  } else {
    console.error(`[ERROR] ${err.name}: ${err.message}`, errorMeta);
  }

  // AppError instance (e.g. NotFoundError, BadRequestError, etc.)
  if (isAppError(err)) {
    return c.json<ApiErrorResponse, ContentfulStatusCode>(
      apiError(err.message, {
        code: err.code,
        details: err.details,
      }),
      (err.statusCode || 500) as ContentfulStatusCode,
    );
  }

  // Zod validation errors
  if (err instanceof ZodError) {
    return c.json<ApiErrorResponse, ContentfulStatusCode>(
      apiError("Validation failed", {
        code: "VALIDATION_ERROR",
        details: zodIssuesToDetails(err),
      }),
      422,
    );
  }

  // Generic / Unexpected errors
  const status: ContentfulStatusCode = 500;
  const message = isDev ? err.message : "Internal Server Error";
  const details = isDev ? { stack: err.stack } : undefined;

  return c.json<ApiErrorResponse, ContentfulStatusCode>(
    apiError(message, {
      code: "INTERNAL_SERVER_ERROR",
      details,
    }),
    status,
  );
};
