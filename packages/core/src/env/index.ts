import { z } from "zod";
import { ValidationError } from "../errors/index.js";

export const baseEnvSchema = z.object({
  ENVIRONMENT: z
    .enum(["development", "production", "test"])
    .default("development"),
  PORT: z.coerce.number().int().positive().default(8787),
  APP_NAME: z.string().min(1).default("peek"),
  APP_URL: z.string().url().default("http://localhost:8787"),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),

  // Authentication & Secrets (Separate Secrets for Access and Refresh Tokens)
  JWT_ACCESS_SECRET: z
    .string()
    .min(16)
    .default("peek_jwt_access_secret_development_12345"),
  REFRESH_TOKEN_SECRET: z
    .string()
    .min(16)
    .default("peek_refresh_token_secret_development_67890"),
  ENCRYPTION_SECRET: z
    .string()
    .min(32, "ENCRYPTION_SECRET must be at least 32 characters long")
    .default("peek_encryption_secret_dev_32chars_long_minimum!!"),

  // GitHub OAuth App Configuration
  GITHUB_CLIENT_ID: z.string().min(1).default("mock_github_client_id"),
  GITHUB_CLIENT_SECRET: z.string().min(1).default("mock_github_client_secret"),
  GITHUB_REDIRECT_URI: z.string().url().optional(),

  // Frontend Redirect on Success
  FRONTEND_URL: z.string().url().optional(),

  // Cookie Settings
  COOKIE_ACCESS_NAME: z.string().min(1).default("peek_access_token"),
  COOKIE_REFRESH_NAME: z.string().min(1).default("peek_refresh_token"),
  COOKIE_DOMAIN: z.string().optional(),
  COOKIE_SECURE: z
    .string()
    .transform((val) => val === "true")
    .optional(),
  COOKIE_SAME_SITE: z.enum(["lax", "strict", "none"]).default("lax"),
  ACCESS_TOKEN_EXPIRY: z.string().default("15m"),
  REFRESH_TOKEN_EXPIRY: z.string().default("30d"),

  // Machine Identity / MCP OAuth 2.1 Token Secrets & Expiry
  MCP_TOKEN_SECRET: z
    .string()
    .min(16)
    .default("peek_mcp_token_secret_development_34567"),
  MCP_ACCESS_TOKEN_EXPIRY: z.string().default("1h"),
  MCP_REFRESH_TOKEN_EXPIRY: z.string().default("90d"),
});

export type BaseEnv = z.infer<typeof baseEnvSchema>;

export function createEnvValidator<T extends z.ZodRawShape>(extendedShape?: T) {
  const schema = extendedShape
    ? baseEnvSchema.extend(extendedShape)
    : baseEnvSchema;

  return {
    schema,
    validate(rawEnv: unknown): BaseEnv {
      const parsed = schema.safeParse(rawEnv);
      if (!parsed.success) {
        const formatted = parsed.error.format();
        const errorDetails = parsed.error.issues.map((issue) => ({
          variable: issue.path.join("."),
          message: issue.message,
        }));
        throw new ValidationError(
          `Environment validation failed: ${errorDetails.map((e) => `${e.variable}: ${e.message}`).join(", ")}`,
          { formatted, issues: errorDetails },
        );
      }
      return parsed.data as BaseEnv;
    },
    safeValidate(rawEnv: unknown) {
      return schema.safeParse(rawEnv);
    },
  };
}

export const defaultEnvValidator = createEnvValidator();
export const validateEnv = (rawEnv: unknown): BaseEnv =>
  defaultEnvValidator.validate(rawEnv);
export const safeValidateEnv = defaultEnvValidator.safeValidate;
