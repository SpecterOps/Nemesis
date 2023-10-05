import ipRangeCheck from "ip-range-check";
import ipaddr from "ipaddr.js";

import { getAll } from "./storage";

const AGENT_KEY = "agent_key";

const CONFIGURE_PLUGIN_ID = "configure-plugin";

// Helper functions

function addDays(date, days) {
  var result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
}

function generateRandomString(length) {
  let result = "";
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

async function fetchLocalFileEncode(path) {
  const data = await fetch(`file://${path}`);
  return await data.blob();
}

async function postFile(input, download_object) {
  const { url, username, password, agent_key } = await getAll();

  if (
    !url ||
    url === "" ||
    !username ||
    username === "" ||
    !password ||
    password === ""
  ) {
    chrome.runtime.openOptionsPage();
    throw new Error("Chrome Plugin Not Configured");
  }

  const result = await fetch(`${url}/file`, {
    method: "POST",
    body: input,
    headers: {
      "Content-Type": "application/octet-stream",
      Authorization: "Basic " + btoa(username + ":" + password),
    },
  });
  if (!result.ok) {
    throw new Error(
      `Failed to upload (${result.status}): ${result.statusText}`
    );
  }

  const r_json = await result.json();

  const expiration = addDays(new Date(download_object.startTime), 90);
  expiration.setMilliseconds(0);

  const metadata = {
    agent_id: agent_key,
    agent_type: "chrome",
    automated: true,
    data_type: "file_data",
    source: download_object.url,
    project: "chrome",
    timestamp: download_object.startTime,
    expiration: expiration.toISOString(),
  };

  const file_data = {
    path: download_object.filename,
    size: download_object.fileSize,
    object_id: r_json.object_id,
  };

  const post_data = { metadata: metadata, data: [file_data] };

  const result2 = await fetch(`${url}/data`, {
    body: JSON.stringify(post_data),
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Basic " + btoa(username + ":" + password),
    },
  });
  if (!result2.ok) {
    throw new Error(
      `Failed to upload (${result2.status}): ${result2.statusText}`
    );
  }
}

// Chrome handlers

chrome.runtime.onInstalled.addListener(async () => {
  chrome.notifications.create(CONFIGURE_PLUGIN_ID, {
    title: "Nemesis Installed",
    message: "Please configure the plugin",
    iconUrl: "/assets/img/icon128.png",
    type: "basic",
  });

  const agent_id = generateRandomString(16);
  await chrome.storage.local.set({ [AGENT_KEY]: agent_id });

  const { url, username, password } = await chrome.storage.local.get();

  if (
    !url ||
    url === "" ||
    !username ||
    username === "" ||
    !password ||
    password === ""
  ) {
    chrome.runtime.openOptionsPage();
  }
});

chrome.notifications.onClicked.addListener((notificationId) => {
  if (notificationId === CONFIGURE_PLUGIN_ID) {
    chrome.runtime.openOptionsPage();
  }
});

async function sourceMatchesWhitelist(source_url) {
  const { whitelist } = await getAll();
  console.debug("[DEBUG] Allowlist:", whitelist);
  if (whitelist) {
    const source = new URL(source_url);
    const ips = whitelist.filter((x) => {
      try {
        ipaddr.parseCIDR(x);
        return true;
      } catch (e) {
        return false;
      }
    });
    console.debug("[DEBUG] IPs:", ips);
    const domains = whitelist.filter((x) => !ipaddr.isValid(x));
    console.debug("[DEBUG] Domains:", domains);
    const matches_ip = ipRangeCheck(source.hostname, ips);
    console.debug("[DEBUG] Matches IP:", matches_ip);
    const matches_domain = domains.includes(source.hostname);
    console.debug("[DEBUG] Matches domain:", matches_domain);
    return matches_ip || matches_domain;
  }
  return true;
}

chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state && delta.state.current === "complete") {
    chrome.downloads.search({ id: delta.id }, async (downloads) => {
      console.debug("Downloaded file: " + downloads[0].filename);
      const filename = downloads[0].filename;

      const source = downloads[0].url;

      if (!(await sourceMatchesWhitelist(source))) {
        console.log("[DEBUG]: Source does not match allowlist");
        return;
      }
      console.debug("[DEBUG]: Source matches allowlist");

      const data = await fetchLocalFileEncode(filename);

      console.debug("[DEBUG]: Uploading file");

      try {
        await postFile(data, downloads[0]);
        chrome.notifications.create("", {
          title: "Nemesis",
          message: "File uploaded successfully",
          iconUrl: "/assets/img/icon128.png",
          type: "basic",
        });
      } catch (e) {
        console.error(e);
        chrome.notifications.create("", {
          title: "Nemesis",
          message: "File upload failed",
          iconUrl: "/assets/img/icon128.png",
          type: "basic",
        });
        throw e;
      }
    });
  }
});
