export const extensionApi = globalThis.browser ?? globalThis.chrome;

if (!extensionApi) {
  throw new Error("Browser extension APIs are unavailable in this context.");
}

export async function getStorage(keys) {
  return extensionApi.storage.local.get(keys);
}

export async function setStorage(items) {
  await extensionApi.storage.local.set(items);
}

export async function removeStorage(keys) {
  await extensionApi.storage.local.remove(keys);
}

export async function getActiveTab() {
  const tabs = await extensionApi.tabs.query({
    active: true,
    currentWindow: true
  });

  return tabs[0] ?? null;
}

export async function openOptionsPage() {
  await extensionApi.runtime.openOptionsPage();
}

export async function openTab(url) {
  await extensionApi.tabs.create({ url });
}
