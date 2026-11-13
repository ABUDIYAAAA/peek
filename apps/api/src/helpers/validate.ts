import { zValidator as honoZValidator } from "@hono/zod-validator";
import type { ValidationTargets } from "hono";
import type { ZodType } from "zod";
import { zodIssuesToDetails, apiError } from "@peek/core";

export function validateRequest<
  Target extends keyof ValidationTargets,
  Schema extends ZodType<any, any, any>,
>(target: Target, schema: Schema) {
  return honoZValidator(target, schema, (result, c) => {
    if (!result.success) {
      const details = zodIssuesToDetails(result.error);
      return c.json(
        apiError("Validation failed", {
          code: "VALIDATION_ERROR",
          details,
        }),
        422,
      );
    }
  });
}
