const VT_API_BASE = "https://www.virustotal.com/api/v3";
const SUPPORTED_PROTOCOLS = new Set(["http:", "https:"]);

function toBase64Url(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";

  for (let index = 0; index < bytes.length; index += 0x8000) {
    const chunk = bytes.subarray(index, index + 0x8000);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function delay(durationMs) {
  return new Promise((resolve) => {
    setTimeout(resolve, durationMs);
  });
}

async function parseJsonResponse(response) {
  const text = await response.text();

  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function request(path, { apiKey, method = "GET", headers = {}, body } = {}) {
  if (!apiKey) {
    throw new Error("Missing VirusTotal API key.");
  }

  const response = await fetch(`${VT_API_BASE}${path}`, {
    method,
    headers: {
      "x-apikey": apiKey,
      ...headers
    },
    body
  });

  const payload = await parseJsonResponse(response);

  if (!response.ok) {
    const error = new Error(payload?.error?.message ?? `VirusTotal returned HTTP ${response.status}.`);
    error.status = response.status;
    error.code = payload?.error?.code ?? null;
    throw error;
  }

  return payload;
}

export function normalizePageUrl(candidate) {
  if (!candidate) {
    return null;
  }

  try {
    const url = new URL(candidate);

    if (!SUPPORTED_PROTOCOLS.has(url.protocol)) {
      return null;
    }

    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

export function buildUrlId(url) {
  return toBase64Url(url);
}

export async function getUrlReport(apiKey, url) {
  return request(`/urls/${buildUrlId(url)}`, { apiKey });
}

export async function scanUrl(apiKey, url) {
  const body = new URLSearchParams({ url });

  return request("/urls", {
    apiKey,
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
}

export async function rescanUrl(apiKey, url) {
  return request(`/urls/${buildUrlId(url)}/analyse`, {
    apiKey,
    method: "POST"
  });
}

export async function getAnalysis(apiKey, analysisId) {
  return request(`/analyses/${analysisId}`, { apiKey });
}

export async function waitForCompletedAnalysis(
  apiKey,
  analysisId,
  { timeoutMs = 20000, intervalMs = 2500 } = {}
) {
  const deadline = Date.now() + timeoutMs;
  let latest = null;

  while (Date.now() < deadline) {
    latest = await getAnalysis(apiKey, analysisId);

    if (latest?.data?.attributes?.status === "completed") {
      return latest;
    }

    await delay(intervalMs);
  }

  return latest;
}

export function getVerdict(stats = {}) {
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const harmless = stats.harmless ?? 0;
  const undetected = stats.undetected ?? 0;

  if (malicious > 0) {
    return {
      tone: "danger",
      title: "Flagged as malicious",
      detail: `${malicious} engine${malicious === 1 ? "" : "s"} marked this URL malicious.`
    };
  }

  if (suspicious > 0) {
    return {
      tone: "warning",
      title: "Flagged as suspicious",
      detail: `${suspicious} engine${suspicious === 1 ? "" : "s"} marked this URL suspicious.`
    };
  }

  if (harmless > 0 || undetected > 0) {
    return {
      tone: "safe",
      title: "No direct detections",
      detail: `${harmless} harmless, ${undetected} undetected.`
    };
  }

  return {
    tone: "neutral",
    title: "Limited data",
    detail: "VirusTotal does not have a clear verdict for this URL yet."
  };
}

export function getDetections(report, limit = 6) {
  const results = report?.data?.attributes?.last_analysis_results ?? {};

  return Object.values(results)
    .filter((entry) => entry?.category === "malicious" || entry?.category === "suspicious")
    .sort((left, right) => {
      if (left.category === right.category) {
        return (left.engine_name ?? "").localeCompare(right.engine_name ?? "");
      }

      return left.category === "malicious" ? -1 : 1;
    })
    .slice(0, limit);
}

export function buildReportUrl(report) {
  const id = report?.data?.id;
  return id ? `https://www.virustotal.com/gui/url/${encodeURIComponent(id)}` : null;
}
