export type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export interface LogContext {
  requestId?: string;
  userId?: string;
  component?: string;
  [key: string]: unknown;
}

export interface LoggerOptions {
  name?: string;
  minLevel?: LogLevel;
  isDev?: boolean;
  context?: LogContext;
}

export class Logger {
  private readonly name: string;
  private readonly minLevel: LogLevel;
  private readonly isDev: boolean;
  private readonly context: LogContext;

  constructor(options: LoggerOptions = {}) {
    this.name = options.name ?? "peek";
    this.minLevel = options.minLevel ?? "info";
    this.isDev = options.isDev ?? false;
    this.context = options.context ?? {};
  }

  public withContext(additionalContext: LogContext): Logger {
    return new Logger({
      name: this.name,
      minLevel: this.minLevel,
      isDev: this.isDev,
      context: { ...this.context, ...additionalContext },
    });
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[this.minLevel];
  }

  private formatMessage(
    level: LogLevel,
    message: string,
    meta?: Record<string, unknown>,
  ): void {
    if (!this.shouldLog(level)) return;

    const timestamp = new Date().toISOString();
    const mergedMeta = { ...this.context, ...meta };
    const requestId =
      (mergedMeta.requestId as string) || this.context.requestId;

    if (this.isDev) {
      // Color-friendly human-readable format for development
      const colors = {
        debug: "\x1b[36m", // Cyan
        info: "\x1b[32m", // Green
        warn: "\x1b[33m", // Yellow
        error: "\x1b[31m", // Red
        reset: "\x1b[0m",
        dim: "\x1b[2m",
      };

      const tag = `${colors[level]}[${level.toUpperCase()}]${colors.reset}`;
      const reqTag = requestId
        ? `${colors.dim}[${requestId}]${colors.reset} `
        : "";
      const hasMeta =
        Object.keys(mergedMeta).filter((k) => k !== "requestId").length > 0;

      if (level === "error") {
        console.error(`${tag} ${reqTag}${message}`, hasMeta ? mergedMeta : "");
      } else if (level === "warn") {
        console.warn(`${tag} ${reqTag}${message}`, hasMeta ? mergedMeta : "");
      } else {
        console.log(`${tag} ${reqTag}${message}`, hasMeta ? mergedMeta : "");
      }
    } else {
      // Single-line JSON format for Cloudflare Observability / Logpush / Datadog
      const entry = {
        level,
        name: this.name,
        message,
        timestamp,
        ...mergedMeta,
      };

      if (level === "error") {
        console.error(JSON.stringify(entry));
      } else if (level === "warn") {
        console.warn(JSON.stringify(entry));
      } else {
        console.log(JSON.stringify(entry));
      }
    }
  }

  public debug(message: string, meta?: Record<string, unknown>): void {
    this.formatMessage("debug", message, meta);
  }

  public info(message: string, meta?: Record<string, unknown>): void {
    this.formatMessage("info", message, meta);
  }

  public warn(message: string, meta?: Record<string, unknown>): void {
    this.formatMessage("warn", message, meta);
  }

  public error(message: string, meta?: Record<string, unknown>): void {
    this.formatMessage("error", message, meta);
  }
}

export function createLogger(options: LoggerOptions = {}): Logger {
  return new Logger(options);
}
