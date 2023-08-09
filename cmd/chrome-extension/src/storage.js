export const get = async (key) => {
    const a = chrome.storage.local.get([key])
    if (Object.keys(a).length === 0) return null
    return a;
}
export const set = async (key, value) => chrome.storage.local.set({ [key]: value })
export const getAll = async () => chrome.storage.local.get()