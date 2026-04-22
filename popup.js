import {
  getActiveTab,
  getStorage,
  openOptionsPage
} from "./lib/extension-api.js";
import {
  getDetections,
  getUrlReport,
  getVerdict,
  normalizePageUrl,
  rescanUrl,
  scanUrl,
  waitForCompletedAnalysis
} from "./lib/virustotal.js";

const pageHost = document.querySelector("#pageHost");
const pageUrl = document.querySelector("#pageUrl");
const verdictCard = document.querySelector("#verdictCard");
const verdictTitle = document.querySelector("#verdictTitle");
const verdictDetail = document.querySelector("#verdictDetail");
const messageText = document.querySelector("#messageText");
const facts = document.querySelector("#facts");
const detections = document.querySelector("#detections");
const detectionList = document.querySelector("#detectionList");
const rescanButton = document.querySelector("#rescanButton");
const openOptionsButton = document.querySelector("#openOptionsButton");

const state = {
  apiKey: "",
  currentUrl: null,
  report: null,
  notFound: false,
  busy: false,
  canAnalyze: false
};

function formatEpoch(value) {
  if (!value) {
    return "Unknown";
  }

  return new Date(value * 1000).toLocaleString();
}

function formatCategories(categories = {}) {
  const values = Object.values(categories).filter(Boolean);

  if (!values.length) {
    return "Unknown";
  }

  return values.slice(0, 2).join(", ");
}

function setMessage(text) {
  messageText.textContent = text ?? "";
}

function syncActionButtons() {
  rescanButton.disabled = state.busy || !state.canAnalyze || (!state.report && !state.notFound);
  rescanButton.textContent = state.notFound ? "Request analysis" : "Request fresh analysis";
}

function setBusy(isBusy) {
  state.busy = isBusy;
  syncActionButtons();
}

function resetReportPanels() {
  verdictCard.className = "verdict-card is-hidden";
  facts.classList.add("is-hidden");
  detections.classList.add("is-hidden");
  facts.replaceChildren();
  detectionList.replaceChildren();
}

function createFact(label, value) {
  const article = document.createElement("article");
  article.className = "fact";

  const labelNode = document.createElement("p");
  labelNode.className = "fact-label";
  labelNode.textContent = label;

  const valueNode = document.createElement("p");
  valueNode.className = "fact-value";
  valueNode.textContent = value;

  article.append(labelNode, valueNode);
  return article;
}

function createDetectionItem(item) {
  const listItem = document.createElement("li");
  listItem.className = "detection-item";

  const details = document.createElement("div");
  const engine = document.createElement("p");
  engine.className = "detection-engine";
  engine.textContent = item.engine_name ?? "Unknown engine";

  const result = document.createElement("p");
  result.className = "detection-result";
  result.textContent = item.result || item.category || "Unknown";

  details.append(engine, result);

  const pill = document.createElement("span");
  pill.className = item.category === "malicious" ? "pill pill-danger" : "pill pill-warning";
  pill.textContent = item.category === "malicious" ? "Malicious" : "Suspicious";

  listItem.append(details, pill);
  return listItem;
}

function renderFacts(report) {
  const attributes = report?.data?.attributes ?? {};
  const stats = attributes.last_analysis_stats ?? {};
  const votes = attributes.total_votes ?? {};
  const items = [
    {
      label: "Detections",
      value: `${stats.malicious ?? 0} malicious / ${stats.suspicious ?? 0} suspicious`
    },
    {
      label: "Last analysis",
      value: formatEpoch(attributes.last_analysis_date ?? attributes.last_modification_date)
    },
    {
      label: "Times submitted",
      value: `${attributes.times_submitted ?? 0}`
    },
    {
      label: "Community votes",
      value: `${votes.harmless ?? 0} harmless / ${votes.malicious ?? 0} malicious`
    },
    {
      label: "Categories",
      value: formatCategories(attributes.categories)
    },
    {
      label: "HTTP status",
      value: attributes.last_http_response_code ? `${attributes.last_http_response_code}` : "Unknown"
    }
  ];

  facts.replaceChildren(...items.map((item) => createFact(item.label, item.value)));
  facts.classList.remove("is-hidden");
}

function renderDetections(report) {
  const detectionItems = getDetections(report);

  if (!detectionItems.length) {
    detections.classList.add("is-hidden");
    detectionList.replaceChildren();
    return;
  }

  detectionList.replaceChildren(...detectionItems.map((item) => createDetectionItem(item)));
  detections.classList.remove("is-hidden");
}

function renderVerdict(report) {
  const stats = report?.data?.attributes?.last_analysis_stats ?? {};
  const verdict = getVerdict(stats);

  verdictCard.className = `verdict-card ${verdict.tone}`;
  verdictTitle.textContent = verdict.title;
  verdictDetail.textContent = verdict.detail;
}

function renderReport(report) {
  state.report = report;
  state.notFound = false;
  state.canAnalyze = true;

  renderVerdict(report);
  renderFacts(report);
  renderDetections(report);
  syncActionButtons();

  const analysisDate = report?.data?.attributes?.last_analysis_date;
  setMessage(
    analysisDate
      ? `VirusTotal data loaded. Last updated ${formatEpoch(analysisDate)}.`
      : "VirusTotal data loaded."
  );
}

function renderMissingKey() {
  state.report = null;
  state.notFound = false;
  state.canAnalyze = false;
  resetReportPanels();
  setMessage("Add your VirusTotal API key in settings before checking URLs.");
  syncActionButtons();
}

function renderUnsupportedPage() {
  state.report = null;
  state.notFound = false;
  state.canAnalyze = false;
  resetReportPanels();
  setMessage("This tab is not an http or https page, so there is nothing to check.");
  syncActionButtons();
}

function renderNotFound() {
  state.report = null;
  state.notFound = true;
  state.canAnalyze = true;
  resetReportPanels();
  setMessage("VirusTotal does not have a URL object for this page yet. Request an analysis to submit it.");
  syncActionButtons();
}

function renderError(error) {
  state.report = null;
  state.notFound = false;
  resetReportPanels();
  syncActionButtons();
  setMessage(error);
}

async function refreshUrlContext() {
  const tab = await getActiveTab();
  state.currentUrl = normalizePageUrl(tab?.url ?? null);

  if (!state.currentUrl) {
    state.canAnalyze = false;
    pageHost.textContent = "Unsupported page";
    pageUrl.textContent = tab?.url ?? "";
    return false;
  }

  state.canAnalyze = true;
  const url = new URL(state.currentUrl);
  pageHost.textContent = url.hostname;
  pageUrl.textContent = state.currentUrl;
  return true;
}

async function loadReport() {
  if (!state.apiKey) {
    renderMissingKey();
    return;
  }

  const hasSupportedUrl = await refreshUrlContext();

  if (!hasSupportedUrl) {
    renderUnsupportedPage();
    return;
  }

  setBusy(true);
  resetReportPanels();
  setMessage("Checking VirusTotal...");

  try {
    const report = await getUrlReport(state.apiKey, state.currentUrl);
    renderReport(report);
  } catch (error) {
    if (error.status === 404 || error.code === "NotFoundError") {
      renderNotFound();
      return;
    }

    if (error.status === 401 || error.status === 403) {
      renderError("VirusTotal rejected the API key. Check the key in settings.");
      return;
    }

    renderError(error.message);
  } finally {
    setBusy(false);
  }
}

async function requestAnalysis() {
  if (!state.apiKey || !state.currentUrl) {
    return;
  }

  setBusy(true);
  setMessage(state.notFound ? "Submitting URL to VirusTotal..." : "Requesting a fresh analysis...");

  try {
    const analysis = state.notFound
      ? await scanUrl(state.apiKey, state.currentUrl)
      : await rescanUrl(state.apiKey, state.currentUrl);

    const analysisId = analysis?.data?.id;

    if (analysisId) {
      setMessage("Analysis queued. Waiting for VirusTotal to finish...");
      await waitForCompletedAnalysis(state.apiKey, analysisId);
    }

    const report = await getUrlReport(state.apiKey, state.currentUrl);
    renderReport(report);
  } catch (error) {
    renderError(error.message);
  } finally {
    setBusy(false);
  }
}

async function init() {
  const stored = await getStorage({ apiKey: "" });
  state.apiKey = (stored.apiKey ?? "").trim();

  await refreshUrlContext();

  if (!state.apiKey) {
    renderMissingKey();
    return;
  }

  await loadReport();
}

rescanButton.addEventListener("click", requestAnalysis);
openOptionsButton.addEventListener("click", openOptionsPage);

init().catch((error) => {
  renderError(error.message);
});
