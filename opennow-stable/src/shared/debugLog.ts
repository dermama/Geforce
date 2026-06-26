export type LogLevel = "info" | "warn" | "error" | "debug";

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  source: string;
  message: string;
  data?: unknown;
}

const MAX_LOGS = 500;
const logs: LogEntry[] = [];

export function log(level: LogLevel, source: string, message: string, data?: unknown): void {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level,
    source,
    message,
    data,
  };
  logs.push(entry);
  if (logs.length > MAX_LOGS) logs.shift();
  const prefix = `[${source}]`;
  if (level === "error") console.error(prefix, message, data ?? "");
  else if (level === "warn") console.warn(prefix, message, data ?? "");
  else console.log(prefix, message, data ?? "");
}

export function getLogs(): LogEntry[] {
  return [...logs];
}

export function clearLogs(): void {
  logs.length = 0;
}

export function exportLogs(): string {
  return logs
    .map((e) => {
      const time = e.timestamp.slice(11, 23);
      const extra = e.data ? `\n    data: ${JSON.stringify(e.data, null, 2)}` : "";
      return `[${time}] [${e.level.toUpperCase()}] [${e.source}] ${e.message}${extra}`;
    })
    .join("\n");
}
