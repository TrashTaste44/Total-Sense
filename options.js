import { getStorage, removeStorage, setStorage } from "./lib/extension-api.js";

const form = document.querySelector("#settingsForm");
const apiKeyInput = document.querySelector("#apiKeyInput");
const clearButton = document.querySelector("#clearButton");
const statusText = document.querySelector("#statusText");
const confirmClearModal = document.querySelector("#confirmClearModal");
const confirmClearBackdrop = document.querySelector("#confirmClearBackdrop");
const confirmClearYes = document.querySelector("#confirmClearYes");
const confirmClearNo = document.querySelector("#confirmClearNo");

function setStatus(text) {
  statusText.textContent = text;
}

function openClearConfirmation() {
  confirmClearModal.classList.remove("is-hidden");
  confirmClearYes.focus();
}

function closeClearConfirmation() {
  confirmClearModal.classList.add("is-hidden");
  clearButton.focus();
}

async function loadSettings() {
  const stored = await getStorage({ apiKey: "" });
  apiKeyInput.value = stored.apiKey ?? "";
  setStatus(stored.apiKey ? "An API key is currently saved in local extension storage." : "");
}

async function saveSettings(event) {
  event.preventDefault();

  const apiKey = apiKeyInput.value.trim();

  if (!apiKey) {
    setStatus("Enter a VirusTotal API key before saving.");
    return;
  }

  await setStorage({ apiKey });
  setStatus("API key saved.");
}

async function clearSettings() {
  await removeStorage("apiKey");
  apiKeyInput.value = "";
  setStatus("Saved API key cleared.");
  closeClearConfirmation();
}

function handleDocumentKeydown(event) {
  if (event.key === "Escape" && !confirmClearModal.classList.contains("is-hidden")) {
    closeClearConfirmation();
  }
}

form.addEventListener("submit", saveSettings);
clearButton.addEventListener("click", openClearConfirmation);
confirmClearBackdrop.addEventListener("click", closeClearConfirmation);
confirmClearNo.addEventListener("click", closeClearConfirmation);
confirmClearYes.addEventListener("click", clearSettings);
document.addEventListener("keydown", handleDocumentKeydown);

loadSettings().catch((error) => {
  setStatus(error.message);
});
