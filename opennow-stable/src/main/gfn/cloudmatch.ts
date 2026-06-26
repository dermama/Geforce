import crypto from "node:crypto";

import type {
  ActiveSessionInfo,
  IceServer,
  SessionClaimRequest,
  SessionCreateRequest,
  SessionInfo,
  SessionPollRequest,
  SessionStopRequest,
  StreamSettings,
} from "@shared/gfn";

import {
  colorQualityBitDepth,
  colorQualityChromaFormat,
} from "@shared/gfn";

import type { CloudMatchRequest, CloudMatchResponse, GetSessionsResponse } from "./types";
import { SessionError } from "./errorCodes";

import { buildDeviceHeaders } from "@shared/deviceHeaders";
import { log } from "@shared/debugLog";

const GFN_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 NVIDIACEFClient/HEAD/debb5919f6 GFN-PC/2.0.80.173";
const GFN_CLIENT_VERSION = "2.0.80.173";

function normalizeIceServers(response: CloudMatchResponse): IceServer[] {
  const raw = response.session.iceServerConfiguration?.iceServers ?? [];
  const servers = raw
    .map((entry) => {
      const urls = Array.isArray(entry.urls) ? entry.urls : [entry.urls];
      return {
        urls,
        username: entry.username,
        credential: entry.credential,
      };
    })
    .filter((entry) => entry.urls.length > 0);

  if (servers.length > 0) {
    return servers;
  }

  return [
    { urls: ["stun:s1.stun.gamestream.nvidia.com:19308"] },
    { urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"] },
  ];
}

/**
 * Extract the streaming server IP from the CloudMatch response, matching Rust's
 * `streaming_server_ip()` priority chain:
 *   1. connectionInfo[usage==14].ip (direct IP)
 *   2. Host extracted from connectionInfo[usage==14].resourcePath (for rtsps:// URLs)
 *   3. sessionControlInfo.ip (fallback)
 */
function streamingServerIp(response: CloudMatchResponse): string | null {
  const connections = response.session.connectionInfo ?? [];
  const sigConn = connections.find((conn) => conn.usage === 14);

  if (sigConn) {
    // Priority 1: Direct IP field
    const rawIp = sigConn.ip;
    const directIp = Array.isArray(rawIp) ? rawIp[0] : rawIp;
    if (directIp && directIp.length > 0) {
      return directIp;
    }

    // Priority 2: Extract host from resourcePath (Alliance format: rtsps://host:port)
    if (sigConn.resourcePath) {
      const host = extractHostFromUrl(sigConn.resourcePath);
      if (host) return host;
    }
  }

  // Priority 3: sessionControlInfo.ip
  const controlIp = response.session.sessionControlInfo?.ip;
  if (controlIp && controlIp.length > 0) {
    return Array.isArray(controlIp) ? controlIp[0] : controlIp;
  }

  return null;
}

/**
 * Extract host from a URL string (handles rtsps://, rtsp://, wss://, https://).
 * Matches Rust's extract_host_from_url().
 */
function extractHostFromUrl(url: string): string | null {
  const prefixes = ["rtsps://", "rtsp://", "wss://", "https://"];
  let afterProto: string | null = null;
  for (const prefix of prefixes) {
    if (url.startsWith(prefix)) {
      afterProto = url.slice(prefix.length);
      break;
    }
  }
  if (!afterProto) return null;

  // Get host (before port or path)
  const host = afterProto.split(":")[0]?.split("/")[0];
  if (!host || host.length === 0 || host.startsWith(".")) return null;
  return host;
}

/**
 * Check if a given IP/hostname is a CloudMatch zone load balancer hostname
 * (not a real game server IP). Zone hostnames look like:
 *   np-ams-06.cloudmatchbeta.nvidiagrid.net
 */
function isZoneHostname(ip: string): boolean {
  return ip.includes("cloudmatchbeta.nvidiagrid.net") || ip.includes("cloudmatch.nvidiagrid.net");
}

function resolveSignaling(response: CloudMatchResponse): {
  serverIp: string;
  signalingServer: string;
  signalingUrl: string;
  mediaConnectionInfo?: { ip: string; port: number };
} {
  const connections = response.session.connectionInfo ?? [];
  const signalingConnection =
    connections.find((conn) => conn.usage === 14 && conn.ip) ?? connections.find((conn) => conn.ip);

  // Use the Rust-matching priority chain for server IP
  const serverIp = streamingServerIp(response);
  if (!serverIp) {
    throw new Error("CloudMatch response did not include a signaling host");
  }

  const resourcePath = signalingConnection?.resourcePath ?? "/nvst/";

  // Build signaling URL matching Rust's build_signaling_url() behavior:
  // - rtsps://host:port -> extract host, convert to wss://host/nvst/
  // - wss://... -> use as-is
  // - /path -> wss://serverIp:443/path
  // - fallback -> wss://serverIp:443/nvst/
  const { signalingUrl, signalingHost } = buildSignalingUrl(resourcePath, serverIp);

  // Use the resolved signaling host (which may differ from serverIp if extracted from rtsps:// URL)
  const effectiveHost = signalingHost ?? serverIp;
  const signalingServer = effectiveHost.includes(":")
    ? effectiveHost
    : `${effectiveHost}:443`;

  return {
    serverIp,
    signalingServer,
    signalingUrl,
    mediaConnectionInfo: resolveMediaConnectionInfo(connections, serverIp),
  };
}

/**
 * Resolve the media connection endpoint (IP + port) from the session's connectionInfo array.
 * Matches Rust's media_connection_info() priority chain:
 *   1. usage=2 (Primary media path, UDP)
 *   2. usage=17 (Alternative media path)
 *   3. usage=14 with highest port (Alliance fallback — distinguishes media port from signaling port)
 *   4. Fallback: use serverIp with the highest port from any usage=14 entry
 *
 * For each entry, IP is extracted from:
 *   a. The .ip field directly
 *   b. The hostname in .resourcePath (e.g. rtsps://80-250-97-40.server.net:48322)
 *   c. Fallback to serverIp (only for usage=14 Alliance fallback)
 */
function resolveMediaConnectionInfo(
  connections: Array<{ ip?: string; port: number; usage: number; protocol?: number; resourcePath?: string }>,
  serverIp: string,
): { ip: string; port: number } | undefined {
  // Helper: extract IP from a connection entry
  const extractIp = (conn: { ip?: string; resourcePath?: string }): string | null => {
    // Try direct IP field
    const rawIp = conn.ip;
    const directIp = Array.isArray(rawIp) ? rawIp[0] : rawIp;
    if (directIp && directIp.length > 0) return directIp;

    // Try hostname from resourcePath
    if (conn.resourcePath) {
      const host = extractHostFromUrl(conn.resourcePath);
      if (host) return host;
    }

    return null;
  };

  // Helper: extract port from a connection entry (fallback to resourcePath URL port)
  const extractPort = (conn: { port: number; resourcePath?: string }): number => {
    if (conn.port > 0) return conn.port;

    // Try extracting port from resourcePath URL
    if (conn.resourcePath) {
      try {
        const url = new URL(conn.resourcePath.replace("rtsps://", "https://").replace("rtsp://", "http://"));
        const portStr = url.port;
        if (portStr) return parseInt(portStr, 10);
      } catch {
        // Ignore
      }
    }

    return 0;
  };

  // Priority 1: usage=2 (Primary media path, UDP)
  const primary = connections.find((c) => c.usage === 2);
  if (primary) {
    const ip = extractIp(primary);
    const port = extractPort(primary);
    console.log(`[CloudMatch] resolveMediaConnectionInfo: usage=2 candidate: ip=${ip}, port=${port}`);
    if (ip && port > 0) return { ip, port };
  }

  // Priority 2: usage=17 (Alternative media path)
  const alt = connections.find((c) => c.usage === 17);
  if (alt) {
    const ip = extractIp(alt);
    const port = extractPort(alt);
    console.log(`[CloudMatch] resolveMediaConnectionInfo: usage=17 candidate: ip=${ip}, port=${port}`);
    if (ip && port > 0) return { ip, port };
  }

  // Priority 3: usage=14 with highest port (Alliance fallback)
  const alliance = connections
    .filter((c) => c.usage === 14)
    .sort((a, b) => b.port - a.port);

  for (const conn of alliance) {
    const ip = extractIp(conn) ?? serverIp;
    const port = extractPort(conn);
    console.log(`[CloudMatch] resolveMediaConnectionInfo: usage=14 candidate: ip=${ip}, port=${port} (serverIp fallback=${serverIp})`);
    if (ip && port > 0) return { ip, port };
  }

  console.log("[CloudMatch] resolveMediaConnectionInfo: NO valid media connection info found");
  return undefined;
}

/**
 * Build signaling WSS URL from the resourcePath, matching Rust implementation.
 * Returns the URL and optionally the extracted host (if different from serverIp).
 */
function buildSignalingUrl(
  raw: string,
  serverIp: string,
): { signalingUrl: string; signalingHost: string | null } {
  if (raw.startsWith("rtsps://") || raw.startsWith("rtsp://")) {
    // Extract hostname from RTSP URL, convert to wss://
    const withoutScheme = raw.startsWith("rtsps://")
      ? raw.slice("rtsps://".length)
      : raw.slice("rtsp://".length);
    const host = withoutScheme.split(":")[0]?.split("/")[0];
    if (host && host.length > 0 && !host.startsWith(".")) {
      return {
        signalingUrl: `wss://${host}/nvst/`,
        signalingHost: host,
      };
    }
    return {
      signalingUrl: `wss://${serverIp}:443/nvst/`,
      signalingHost: null,
    };
  }

  if (raw.startsWith("wss://")) {
    // Already a full WSS URL, use as-is; extract host
    const withoutScheme = raw.slice("wss://".length);
    const host = withoutScheme.split("/")[0] ?? null;
    return { signalingUrl: raw, signalingHost: host };
  }

  if (raw.startsWith("/")) {
    // Relative path
    return {
      signalingUrl: `wss://${serverIp}:443${raw}`,
      signalingHost: null,
    };
  }

  // Fallback
  return {
    signalingUrl: `wss://${serverIp}:443/nvst/`,
    signalingHost: null,
  };
}

function safeHeaders(headers: Record<string, string>): Record<string, string> {
  const safe: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === "authorization") {
      safe[k] = v.slice(0, 20) + "...";
    } else {
      safe[k] = v;
    }
  }
  return safe;
}

function isAndroidPlatform(): boolean {
  // Capacitor injects window.Capacitor in native apps. This is more reliable
  // than checking navigator.userAgent, which can vary across WebView configs.
  return typeof window !== "undefined" &&
    typeof (window as any).Capacitor !== "undefined" &&
    ((window as any).Capacitor.platform === "android" ||
     (window as any).Capacitor.isNativePlatform?.());
}

function requestHeaders(token: string): Record<string, string> {
  const clientId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  // Use the shared device header builder so Android and desktop stay in sync.
  return buildDeviceHeaders(token, clientId, deviceId, isAndroidPlatform());
}

function parseResolution(input: string): { width: number; height: number } {
  const [rawWidth, rawHeight] = input.split("x");
  const width = Number.parseInt(rawWidth ?? "", 10);
  const height = Number.parseInt(rawHeight ?? "", 10);

  if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) {
    return { width: 1920, height: 1080 };
  }

  return { width, height };
}

function timezoneOffsetMs(): number {
  return -new Date().getTimezoneOffset() * 60 * 1000;
}

function isEnhancedStreamModeEnabled(): boolean {
  try {
    if (typeof localStorage !== "undefined") {
      return localStorage.getItem("opennow:enhancedStream") === "true";
    }
  } catch {}
  return false;
}

function buildSessionRequestBody(input: SessionCreateRequest): Record<string, unknown> {
  const requestedZoneAddress = input.requestedZoneAddress?.trim() || undefined;
  const deviceHashId = crypto.randomUUID();
  const subSessionId = crypto.randomUUID();

  // Resolution from user settings (fallback to 1080p@60)
  const { width, height } = parseResolution(input.settings?.resolution ?? "1920x1080");
  const fps = input.settings?.fps ?? 60;
  const hdrEnabled = false; // HDR is negotiated only on claim/resume, not on create
  const enhancedStream = isEnhancedStreamModeEnabled();

  const timezoneMs = timezoneOffsetMs();

  // Build streaming features matching what the server needs for instance allocation
  const chromaFormat = input.settings?.colorQuality
    ? colorQualityChromaFormat(input.settings.colorQuality)
    : 0;

  return {
    sessionRequestData: {
      appId: input.appId,
      internalTitle: input.internalTitle ?? null,
      deviceHashId,
      clientIdentification: "GFN-PC",
      clientPlatformName: isAndroidPlatform() ? "android" : "windows",
      clientVersion: "2.0.80.173",
      sdkVersion: "1.0",
      streamerVersion: 1,
      useOps: true,
      audioMode: 2,
      appLaunchMode: 1,
      accountLinked: input.accountLinked ?? true,
      userAge: 26,
      sdrHdrMode: hdrEnabled ? 1 : 0,
      clientDisplayHdrCapabilities: null,
      surroundAudioInfo: 0,
      remoteControllersBitmap: 0,
      clientTimezoneOffset: timezoneMs,
      enhancedStreamMode: enhancedStream ? 1 : 0,
      secureRTSPSupported: false,
      partnerCustomData: "",
      enablePersistingInGameSettings: true,
      availableSupportedControllers: [],
      networkTestSessionId: null,
      parentSessionId: null,
      requestedStreamingFeatures: {
        reflex: fps >= 120,
        bitDepth: 0,
        cloudGsync: false,
        enabledL4S: false,
        profile: 0,
        fallbackToLogicalResolution: false,
        chromaFormat,
        prefilterMode: 0,
        hudStreamingMode: 0,
      },
      metaData: [
        { key: "SubSessionId", value: subSessionId },
        { key: "wssignaling", value: "1" },
      ],
      clientRequestMonitorSettings: [
        {
          widthInPixels: width,
          heightInPixels: height,
          framesPerSecond: fps,
          sdrHdrMode: hdrEnabled ? 1 : 0,
          displayData: {
            desiredContentMaxLuminance: 0,
            desiredContentMinLuminance: 0,
            desiredContentMaxFrameAverageLuminance: 0,
          },
          dpi: 0,
        },
      ],
      ...(requestedZoneAddress ? { requestedZoneAddress } : {}),
    },
  };
}

function cloudmatchUrl(zone: string): string {
  return `https://${zone}.cloudmatchbeta.nvidiagrid.net`;
}

function resolveStreamingBaseUrl(zone: string, provided?: string): string {
  if (provided && provided.trim()) {
    const trimmed = provided.trim();
    return trimmed.endsWith("/") ? trimmed.slice(0, -1) : trimmed;
  }
  return cloudmatchUrl(zone);
}

function shouldUseServerIp(baseUrl: string): boolean {
  return baseUrl.includes("cloudmatchbeta.nvidiagrid.net");
}

function resolvePollStopBase(zone: string, provided?: string, serverIp?: string): string {
  const base = resolveStreamingBaseUrl(zone, provided);
  // Only use serverIp if it's a real server IP (not a zone hostname).
  // The Rust version checks: if we're NOT an alliance partner AND we have a server_ip, use it.
  // But if the "serverIp" is actually the zone hostname (from an early poll when connectionInfo
  // was empty), using it is circular and doesn't help.
  if (serverIp && shouldUseServerIp(base) && !isZoneHostname(serverIp)) {
    return `https://${serverIp}`;
  }
  return base;
}

function toPositiveInt(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    const normalized = Math.trunc(value);
    return normalized > 0 ? normalized : undefined;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
  }
  return undefined;
}

function extractQueuePosition(payload: CloudMatchResponse): number | undefined {
  // Primary: seatSetupInfo (official client reads seatSetupInfo.queuePosition when seatSetupStep==1)
  const seat = payload.session.seatSetupInfo;
  if (seat?.seatSetupStep === 1) {
    const pos = toPositiveInt(seat.queuePosition);
    if (pos !== undefined) return pos;
  }

  // Fallback: direct field
  const direct = toPositiveInt(payload.session.queuePosition);
  if (direct !== undefined) return direct;

  // Fallback: sessionProgress
  const nestedSessionProgress = payload.session.sessionProgress;
  if (nestedSessionProgress) {
    const nested = toPositiveInt(nestedSessionProgress.queuePosition);
    if (nested !== undefined) return nested;
  }

  // Fallback: progressInfo
  const nestedProgressInfo = payload.session.progressInfo;
  if (nestedProgressInfo) {
    const nested = toPositiveInt(nestedProgressInfo.queuePosition);
    if (nested !== undefined) return nested;
  }

  return undefined;
}

function extractQueueEta(payload: CloudMatchResponse): number | undefined {
  // Primary: seatSetupInfo.seatSetupEta (seconds)
  const seat = payload.session.seatSetupInfo;
  if (seat?.seatSetupStep === 1 && typeof seat.seatSetupEta === "number" && seat.seatSetupEta > 0) {
    return seat.seatSetupEta;
  }

  // Fallback: direct eta
  if (typeof payload.session.eta === "number" && payload.session.eta > 0) {
    return payload.session.eta;
  }

  // Fallback: sessionProgress.eta
  const eta1 = payload.session.sessionProgress?.eta;
  if (typeof eta1 === "number" && eta1 > 0) return eta1;

  // Fallback: progressInfo.eta
  const eta2 = payload.session.progressInfo?.eta;
  if (typeof eta2 === "number" && eta2 > 0) return eta2;

  return undefined;
}

function toSessionInfo(zone: string, streamingBaseUrl: string, payload: CloudMatchResponse): SessionInfo {
  if (payload.requestStatus.statusCode !== 1) {
    // Use SessionError for parsing error responses
    const errorJson = JSON.stringify(payload);
    throw SessionError.fromResponse(200, errorJson);
  }

  const signaling = resolveSignaling(payload);
  const queuePosition = extractQueuePosition(payload);
  const queueEta = extractQueueEta(payload);

  // Debug logging to trace signaling resolution
  const connections = payload.session.connectionInfo ?? [];
  console.log(
    `[CloudMatch] toSessionInfo: status=${payload.session.status}, ` +
    `queuePosition=${queuePosition ?? "n/a"}, ` +
    `connectionInfo=${connections.length} entries, ` +
    `serverIp=${signaling.serverIp}, ` +
    `signalingServer=${signaling.signalingServer}, ` +
    `signalingUrl=${signaling.signalingUrl}`,
  );
  for (const conn of connections) {
    console.log(
      `[CloudMatch]   conn: usage=${conn.usage} ip=${conn.ip ?? "null"} port=${conn.port} ` +
      `resourcePath=${conn.resourcePath ?? "null"}`,
    );
  }

  return {
    sessionId: payload.session.sessionId,
    status: payload.session.status,
    queuePosition,
    queueEta,
    zone,
    streamingBaseUrl,
    serverIp: signaling.serverIp,
    signalingServer: signaling.signalingServer,
    signalingUrl: signaling.signalingUrl,
    gpuType: payload.session.gpuType,
    iceServers: normalizeIceServers(payload),
    mediaConnectionInfo: signaling.mediaConnectionInfo,
  };
}

export async function createSession(input: SessionCreateRequest): Promise<SessionInfo> {
  if (!input.token) {
    throw new Error("Missing token for session creation");
  }

  if (!/^\d+$/.test(input.appId)) {
    throw new Error(`Invalid launch appId '${input.appId}' (must be numeric)`);
  }

  const body = buildSessionRequestBody(input);
  const headers = requestHeaders(input.token);

  log("info", "createSession", "Sending request", {
    zone: input.zone,
    streamingBaseUrl: input.streamingBaseUrl,
    appId: input.appId,
    url: `${resolveStreamingBaseUrl(input.zone, input.streamingBaseUrl)}/v2/session`,
    headers: safeHeaders(headers),
    body: body,
  });

  const base = resolveStreamingBaseUrl(input.zone, input.streamingBaseUrl);
  const url = `${base}/v2/session?keyboardLayout=en-US&languageCode=en_US`;
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  const text = await response.text();
  log("info", "createSession", `Response: HTTP ${response.status}`, {
    status: response.status,
    bodyPreview: text.slice(0, 2000),
  });

  if (!response.ok) {
    throw SessionError.fromResponse(response.status, text);
  }

  const payload = JSON.parse(text) as CloudMatchResponse;
  return toSessionInfo(input.zone, base, payload);
}

export async function pollSession(input: SessionPollRequest): Promise<SessionInfo> {
  if (!input.token) {
    throw new Error("Missing token for session polling");
  }

  const base = resolvePollStopBase(input.zone, input.streamingBaseUrl, input.serverIp);
  const url = `${base}/v2/session/${input.sessionId}`;
  const headers = requestHeaders(input.token);
  log("debug", "pollSession", `Polling session ${input.sessionId}`, {
    url,
    serverIp: input.serverIp,
    headers: safeHeaders(headers),
  });

  const response = await fetch(url, {
    method: "GET",
    headers,
  });

  const text = await response.text();
  log("debug", "pollSession", `Response: HTTP ${response.status}`, {
    status: response.status,
    bodyPreview: text.slice(0, 1000),
  });

  if (!response.ok) {
    throw SessionError.fromResponse(response.status, text);
  }

  const payload = JSON.parse(text) as CloudMatchResponse;

  // Match Rust behavior: if the poll was routed through the zone load balancer
  // and the response now contains a real server IP in connectionInfo, re-poll
  // directly via the real server IP. This ensures the signaling data and
  // connection info are correct (the zone LB may return different data than
  // a direct server poll).
  const realServerIp = streamingServerIp(payload);
  const polledViaZone = isZoneHostname(new URL(base).hostname);
  const realIpDiffers =
    realServerIp &&
    realServerIp.length > 0 &&
    !isZoneHostname(realServerIp) &&
    realServerIp !== input.serverIp;

  // Log poll response when session becomes ready (status 2 or 3) so we can check assigned zone
  if (payload.session.status === 2 || payload.session.status === 3) {
    console.log("[DEBUG] pollSession ready response:", JSON.stringify(payload, null, 2));
  }

  if (polledViaZone && realIpDiffers && (payload.session.status === 2 || payload.session.status === 3)) {
    log("debug", "pollSession", `Re-polling via real server IP ${realServerIp}`);
    const directBase = `https://${realServerIp}`;
    const directUrl = `${directBase}/v2/session/${input.sessionId}`;
    try {
      const directResponse = await fetch(directUrl, {
        method: "GET",
        headers,
      });
      if (directResponse.ok) {
        const directText = await directResponse.text();
        const directPayload = JSON.parse(directText) as CloudMatchResponse;
        if (directPayload.requestStatus.statusCode === 1) {
          log("debug", "pollSession", "Direct re-poll succeeded");
          return toSessionInfo(input.zone, directBase, directPayload);
        }
      }
    } catch (e) {
      log("warn", "pollSession", "Direct re-poll failed, using zone LB response", { error: String(e) });
    }
  }

  return toSessionInfo(input.zone, base, payload);
}

export async function stopSession(input: SessionStopRequest): Promise<void> {
  if (!input.token) {
    throw new Error("Missing token for session stop");
  }

  const base = resolvePollStopBase(input.zone, input.streamingBaseUrl, input.serverIp);
  const url = `${base}/v2/session/${input.sessionId}`;
  const headers = requestHeaders(input.token);
  log("info", "stopSession", `Stopping session ${input.sessionId}`, { url });

  const response = await fetch(url, {
    method: "DELETE",
    headers,
  });

  if (!response.ok) {
    const text = await response.text();
    log("warn", "stopSession", `Stop failed HTTP ${response.status}`, {
      body: text.slice(0, 500),
    });
    throw SessionError.fromResponse(response.status, text);
  }
}

/**
 * Get list of active sessions (status 2 or 3)
 * Returns sessions that are Ready or Streaming
 */
export async function getActiveSessions(
  token: string,
  streamingBaseUrl: string,
): Promise<ActiveSessionInfo[]> {
  if (!token) {
    throw new Error("Missing token for getting active sessions");
  }

  const deviceId = crypto.randomUUID();
  const clientId = crypto.randomUUID();

  const base = streamingBaseUrl.trim().endsWith("/")
    ? streamingBaseUrl.trim().slice(0, -1)
    : streamingBaseUrl.trim();
  const url = `${base}/v2/session`;

  const headers = buildDeviceHeaders(token, clientId, deviceId, isAndroidPlatform());

  log("debug", "getActiveSessions", "Fetching active sessions", {
    url,
    headers: safeHeaders(headers),
  });

  const response = await fetch(url, {
    method: "GET",
    headers,
  });

  const text = await response.text();

  if (!response.ok) {
    log("warn", "getActiveSessions", `Failed HTTP ${response.status}`, {
      body: text.slice(0, 500),
    });
    return [];
  }

  let sessionsResponse: GetSessionsResponse;
  try {
    sessionsResponse = JSON.parse(text) as GetSessionsResponse;
  } catch {
    log("warn", "getActiveSessions", "Failed to parse response JSON", {
      preview: text.slice(0, 500),
    });
    return [];
  }

  if (sessionsResponse.requestStatus.statusCode !== 1) {
    console.warn(`Get sessions API error: ${sessionsResponse.requestStatus.statusDescription}`);
    return [];
  }

  // Filter active sessions (status 2 = Ready, status 3 = Streaming)
  const activeSessions: ActiveSessionInfo[] = sessionsResponse.sessions
    .filter((s) => s.status === 2 || s.status === 3)
    .map((s) => {
      // Extract appId from sessionRequestData
      const appId = s.sessionRequestData?.appId ? Number(s.sessionRequestData.appId) : 0;

      // Get server IP from sessionControlInfo
      const serverIp = s.sessionControlInfo?.ip;

      // Build signaling URL from connection info
      const connInfo = s.connectionInfo?.find((conn) => conn.usage === 14 && conn.ip);
      const connIp = connInfo?.ip;
      const signalingUrl = Array.isArray(connIp)
        ? connIp.map((ip: string) => `wss://${ip}:443/nvst/`)
        : typeof connIp === "string"
          ? [`wss://${connIp}:443/nvst/`]
          : Array.isArray(serverIp)
            ? serverIp.map((ip: string) => `wss://${ip}:443/nvst/`)
            : typeof serverIp === "string"
              ? [`wss://${serverIp}:443/nvst/`]
              : undefined;

      // Extract resolution and fps from monitor settings
      const monitorSettings = s.monitorSettings?.[0];
      const resolution = monitorSettings
        ? `${monitorSettings.widthInPixels ?? 0}x${monitorSettings.heightInPixels ?? 0}`
        : undefined;
      const fps = monitorSettings?.framesPerSecond ?? undefined;

      return {
        sessionId: s.sessionId,
        appId,
        gpuType: s.gpuType,
        status: s.status,
        serverIp,
        signalingUrl: Array.isArray(signalingUrl) ? signalingUrl[0] : signalingUrl,
        resolution,
        fps,
      };
    });

  return activeSessions;
}

/**
 * Build claim/resume request payload
 */
function buildClaimRequestBody(sessionId: string, appId: string, settings: StreamSettings): unknown {
  const { width, height } = parseResolution(settings.resolution);
  const cq = settings.colorQuality;
  const chromaFormat = colorQualityChromaFormat(cq);
  // Claim/resume uses SDR mode (matching Rust: hdr_enabled defaults false for claims).
  // HDR is only negotiated on the initial session create.
  const hdrEnabled = false;
  const deviceId = crypto.randomUUID();
  const subSessionId = crypto.randomUUID();
  const timezoneMs = timezoneOffsetMs();

  // Build HDR capabilities if enabled
  const hdrCapabilities = hdrEnabled
    ? {
        version: 1,
        hdrEdrSupportedFlagsInUint32: 3, // 1=HDR10, 2=EDR, 3=both
        staticMetadataDescriptorId: 0,
        displayData: {
          maxLuminance: 1000,
          minLuminance: 0.01,
          maxFrameAverageLuminance: 500,
        },
      }
    : null;

  return {
    action: 2,
    data: "RESUME",
    sessionRequestData: {
      audioMode: 2,
      remoteControllersBitmap: 0,
      sdrHdrMode: hdrEnabled ? 1 : 0,
      networkTestSessionId: null,
      availableSupportedControllers: [],
      clientVersion: "30.0",
      deviceHashId: deviceId,
      internalTitle: null,
      clientPlatformName: isAndroidPlatform() ? "android" : "windows",
      metaData: [
        { key: "SubSessionId", value: subSessionId },
        { key: "wssignaling", value: "1" },
        { key: "GSStreamerType", value: "WebRTC" },
        { key: "networkType", value: "Unknown" },
        { key: "ClientImeSupport", value: "0" },
        {
          key: "clientPhysicalResolution",
          value: JSON.stringify({ horizontalPixels: width, verticalPixels: height }),
        },
        { key: "surroundAudioInfo", value: "2" },
      ],
      surroundAudioInfo: 0,
      clientTimezoneOffset: timezoneMs,
      clientIdentification: isAndroidPlatform() ? "GFN-ANDROID" : "GFN-PC",
      parentSessionId: null,
      appId,
      streamerVersion: 1,
      clientRequestMonitorSettings: [
        {
          widthInPixels: width,
          heightInPixels: height,
          framesPerSecond: settings.fps,
          sdrHdrMode: hdrEnabled ? 1 : 0,
          displayData: {
            desiredContentMaxLuminance: hdrEnabled ? 1000 : 0,
            desiredContentMinLuminance: 0,
            desiredContentMaxFrameAverageLuminance: hdrEnabled ? 500 : 0,
          },
          dpi: 0,
        },
      ],
      appLaunchMode: 1,
      sdkVersion: "1.0",
      enhancedStreamMode: 1,
      useOps: true,
      clientDisplayHdrCapabilities: hdrCapabilities,
      accountLinked: true,
      partnerCustomData: "",
      enablePersistingInGameSettings: true,
      secureRTSPSupported: false,
      userAge: 26,
      requestedStreamingFeatures: {
        reflex: settings.fps >= 120,
        bitDepth: 0,
        cloudGsync: false,
        enabledL4S: false,
        profile: 0,
        fallbackToLogicalResolution: false,
        chromaFormat,
        prefilterMode: 0,
        hudStreamingMode: 0,
      },
    },
    metaData: [],
  };
}

/**
 * Claim/Resume an existing session
 * Required before connecting to an existing session
 */
export async function claimSession(input: SessionClaimRequest): Promise<SessionInfo> {
  if (!input.token) {
    throw new Error("Missing token for session claim");
  }

  const deviceId = crypto.randomUUID();
  const clientId = crypto.randomUUID();

  const claimUrl = `https://${input.serverIp}/v2/session/${input.sessionId}?keyboardLayout=en-US&languageCode=en_US`;

  // Provide default values for optional parameters
  const appId = input.appId ?? "0";
  const settings = input.settings ?? {
    resolution: "1920x1080",
    fps: 60,
    maxBitrateMbps: 75,
    codec: "H264",
    colorQuality: "8bit_420",
  };

  const payload = buildClaimRequestBody(input.sessionId, appId, settings);
  const headers = buildDeviceHeaders(input.token, clientId, deviceId, isAndroidPlatform());

  log("info", "claimSession", `Claiming session ${input.sessionId}`, {
    url: claimUrl,
    serverIp: input.serverIp,
    headers: safeHeaders(headers),
  });

  const response = await fetch(claimUrl, {
    method: "PUT",
    headers,
    body: JSON.stringify(payload),
  });

  const text = await response.text();
  log("info", "claimSession", `Claim response HTTP ${response.status}`, {
    status: response.status,
    bodyPreview: text.slice(0, 2000),
  });

  if (!response.ok) {
    throw SessionError.fromResponse(response.status, text);
  }

  const apiResponse = JSON.parse(text) as CloudMatchResponse;

  if (apiResponse.requestStatus.statusCode !== 1) {
    throw SessionError.fromResponse(200, text);
  }

  // Poll until session is ready (status 2 or 3)
  const getUrl = `https://${input.serverIp}/v2/session/${input.sessionId}`;
  const maxAttempts = 60;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (attempt > 1) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    // Build headers without Origin/Referer for polling
    const pollHeaders: Record<string, string> = { ...headers };
    delete pollHeaders["Origin"];
    delete pollHeaders["Referer"];

    log("debug", "claimSession", `Poll attempt ${attempt}/${maxAttempts}`, { url: getUrl });
    const pollResponse = await fetch(getUrl, {
      method: "GET",
      headers: pollHeaders,
    });

    if (!pollResponse.ok) {
      log("debug", "claimSession", `Poll attempt ${attempt} failed HTTP ${pollResponse.status}`);
      continue;
    }

    const pollText = await pollResponse.text();
    let pollApiResponse: CloudMatchResponse;

    try {
      pollApiResponse = JSON.parse(pollText) as CloudMatchResponse;
    } catch {
      continue;
    }

    const sessionData = pollApiResponse.session;

    if (sessionData.status === 2 || sessionData.status === 3) {
      // Session is ready
      const signaling = resolveSignaling(pollApiResponse);
      const queuePosition = extractQueuePosition(pollApiResponse);

      return {
        sessionId: sessionData.sessionId,
        status: sessionData.status,
        queuePosition,
        zone: "", // Zone not applicable for claimed sessions
        streamingBaseUrl: `https://${input.serverIp}`,
        serverIp: signaling.serverIp,
        signalingServer: signaling.signalingServer,
        signalingUrl: signaling.signalingUrl,
        gpuType: sessionData.gpuType,
        iceServers: normalizeIceServers(pollApiResponse),
        mediaConnectionInfo: signaling.mediaConnectionInfo,
      };
    }

    // If status is not "cleaning up" (6), break early
    if (sessionData.status !== 6) {
      break;
    }
  }

  throw new Error("Session did not become ready after claiming");
}
