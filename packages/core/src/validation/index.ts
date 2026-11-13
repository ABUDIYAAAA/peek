import { z } from "zod";
import { ValidationError } from "../errors/index.js";

export const idParamSchema = z.object({
  id: z.string().min(1, "ID must not be empty"),
});

export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().trim().optional(),
  sort: z.string().trim().optional(),
  order: z.enum(["asc", "desc"]).default("desc"),
});

export type PaginationQuery = z.infer<typeof paginationQuerySchema>;

export interface CompatibleZodIssue {
  path?: readonly (string | number | symbol)[] | (string | number | symbol)[];
  message: string;
  code?: string;
}

export interface CompatibleZodError {
  issues: readonly CompatibleZodIssue[] | CompatibleZodIssue[];
}

export function zodIssuesToDetails(error: CompatibleZodError) {
  return error.issues.map((issue) => ({
    field:
      issue.path && issue.path.length > 0
        ? issue.path.map(String).join(".")
        : undefined,
    message: issue.message,
    code: issue.code,
  }));
}

export function validateData<T>(schema: z.ZodType<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw new ValidationError(
      "Validation error",
      zodIssuesToDetails(result.error),
    );
  }
  return result.data;
}
