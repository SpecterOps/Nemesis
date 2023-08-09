import { set } from './storage.js'

const URL_KEY = "url";
const USERNAME_KEY = "username";
const PASSWORD_KEY = "password";
const AGENT_KEY = "agent_key";
const WHITELIST_KEY = "whitelist";

async function saveConfiguration() {
    async function saveElement(key, id) {
        var val = document.getElementById(id).value;
        await set(key, val)
    }
    saveElement(URL_KEY, "url");
    saveElement(USERNAME_KEY, "username");
    saveElement(PASSWORD_KEY, "password");
    saveElement(AGENT_KEY, "agent_key");

    if (document.getElementById("whitelist-toggle").checked) {
        const whitelist = document.getElementById('whitelist').value.split('\n');
        await set(WHITELIST_KEY, whitelist);
    } else {
        await set(WHITELIST_KEY, null);
    }

    alert('Saved configuration')
}

document.getElementById("nemesis-form").addEventListener("submit", e => {
    e.preventDefault();
    console.debug('Form submitted');
    const form_valid = document.getElementById("nemesis-form").reportValidity()
    if (form_valid)
        saveConfiguration();
});

document.getElementById("whitelist-toggle").addEventListener("click", async () => {
    const whitelist_checked = document.getElementById("whitelist-toggle").checked;
    if (whitelist_checked) {
        document.getElementById("whitelist-div").classList.toggle("hidden");
    } else {
        document.getElementById("whitelist-div").classList.toggle("hidden");
        await set(WHITELIST_KEY, null);
    }
});

async function optionsGet(key) {
    const val = await chrome.storage.local.get([key]);
    if (Object.keys(val).length === 0) return null;
    if (val && val[key])
        return val[key];
    return null;
}

document.addEventListener("DOMContentLoaded", async () => {
    async function createSetter(key, id) {
        const val = await optionsGet(key);
        if (val) {
            document.getElementById(id).value = val;
        }
    }

    const whitelist = await optionsGet(WHITELIST_KEY);
    if (whitelist == null || Object.keys(whitelist).length == 0) {
        document.getElementById("whitelist-toggle").checked = false;
    } else {
        document.getElementById("whitelist-toggle").checked = true;
        document.getElementById("whitelist-div").classList.toggle("hidden");
        document.getElementById("whitelist").value = whitelist.join('\n');
    }

    await createSetter(URL_KEY, "url");
    await createSetter(USERNAME_KEY, "username");
    await createSetter(PASSWORD_KEY, "password");
    await createSetter(AGENT_KEY, "agent_key");
});