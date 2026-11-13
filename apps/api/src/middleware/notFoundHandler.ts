import type { NotFoundHandler } from "hono";
import { apiError, type ApiErrorResponse } from "@peek/core";
import type { AppEnv } from "../types.js";

export const notFoundHandler: NotFoundHandler<AppEnv> = (c) => {
  return c.json<ApiErrorResponse>(
    apiError(`Route not found: ${c.req.method} ${c.req.path}`, {
      code: "NOT_FOUND",
    }),
    404,
  );
};
