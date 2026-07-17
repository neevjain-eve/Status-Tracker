// Server-side OneDrive <-> repo sync. Runs only inside GitHub Actions.
// Holds the real Microsoft credentials (from Actions secrets) - never
// exposed to any browser or committed to any tracked file.
import fs from "node:fs";
import sodium from "libsodium-wrappers";

const {
  MS_CLIENT_ID,
  MS_CLIENT_SECRET,
  MS_TENANT_ID,
  MS_REFRESH_TOKEN,
  OD_DRIVE_ID,
  OD_ITEM_ID,
  GH_PAT_FOR_SECRETS,
  GITHUB_REPOSITORY,
  OP,
  TASK_ID,
  PAYLOAD,
} = process.env;

const DATA_PATH = "data/tasks.json";

function fail(msg) {
  console.error("SYNC FAILED: " + msg);
  process.exit(1);
}

async function refreshAccessToken() {
  const url = `https://login.microsoftonline.com/${MS_TENANT_ID}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: MS_CLIENT_ID,
    client_secret: MS_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: MS_REFRESH_TOKEN,
    scope: "https://graph.microsoft.com/.default offline_access",
  });
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const json = await res.json();
  if (!res.ok) {
    fail(
      "token refresh " + res.status + ": " + (json.error_description || JSON.stringify(json))
    );
  }
  return json; // { access_token, refresh_token, expires_in, ... }
}

// Microsoft rotates refresh tokens. If we got a new one, persist it as a
// GitHub Actions secret (sealed with the repo's public key) so the next
// run keeps working without any human re-authorizing anything.
async function maybeRotateSecret(newRefreshToken) {
  if (!newRefreshToken || newRefreshToken === MS_REFRESH_TOKEN) return;
  if (!GH_PAT_FOR_SECRETS) {
    console.warn("No GH_PAT_FOR_SECRETS set - cannot persist rotated refresh token.");
    return;
  }
  await sodium.ready;
  const [owner, repo] = GITHUB_REPOSITORY.split("/");
  const keyRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/actions/secrets/public-key`,
    { headers: authHeaders() }
  );
  if (!keyRes.ok) {
    console.warn("Could not fetch repo public key for secret rotation: " + keyRes.status);
    return;
  }
  const { key, key_id } = await keyRes.json();
  const messageBytes = sodium.from_string(newRefreshToken);
  const keyBytes = sodium.from_base64(key, sodium.base64_variants.ORIGINAL);
  const encryptedBytes = sodium.crypto_box_seal(messageBytes, keyBytes);
  const encrypted = sodium.to_base64(encryptedBytes, sodium.base64_variants.ORIGINAL);

  const putRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/actions/secrets/MS_REFRESH_TOKEN`,
    {
      method: "PUT",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ encrypted_value: encrypted, key_id }),
    }
  );
  if (!putRes.ok) {
    console.warn("Failed to rotate MS_REFRESH_TOKEN secret: " + putRes.status);
  } else {
    console.log("Rotated MS_REFRESH_TOKEN secret for next run.");
  }
}

function authHeaders() {
  return {
    Authorization: "token " + GH_PAT_FOR_SECRETS,
    Accept: "application/vnd.github+json",
  };
}

async function loadFromOneDrive(accessToken) {
  const res = await fetch(
    `https://graph.microsoft.com/v1.0/drives/${OD_DRIVE_ID}/items/${OD_ITEM_ID}/content`,
    { headers: { Authorization: "Bearer " + accessToken } }
  );
  if (!res.ok) fail("OneDrive read " + res.status);
  const json = await res.json();
  return Array.isArray(json) ? json : [];
}

async function saveToOneDrive(accessToken, tasks) {
  const res = await fetch(
    `https://graph.microsoft.com/v1.0/drives/${OD_DRIVE_ID}/items/${OD_ITEM_ID}/content`,
    {
      method: "PUT",
      headers: {
        Authorization: "Bearer " + accessToken,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(tasks),
    }
  );
  if (!res.ok) fail("OneDrive write " + res.status);
}

function applyOp(tasks, op, taskId, payloadStr) {
  if (op === "upsert" && taskId && payloadStr) {
    let task;
    try {
      task = JSON.parse(payloadStr);
    } catch {
      fail("payload was not valid JSON");
    }
    const idx = tasks.findIndex((t) => t.id === taskId);
    if (idx >= 0) tasks[idx] = task;
    else tasks.push(task);
  } else if (op === "delete" && taskId) {
    tasks = tasks.filter((t) => t.id !== taskId);
  }
  // op === "pull" (or unrecognized): leave tasks as loaded from OneDrive
  return tasks;
}

async function main() {
  if (!MS_CLIENT_ID || !MS_CLIENT_SECRET || !MS_TENANT_ID || !MS_REFRESH_TOKEN) {
    fail("Missing Microsoft credential secrets.");
  }
  if (!OD_DRIVE_ID || !OD_ITEM_ID) fail("Missing OneDrive drive/item id secrets.");

  const tokenJson = await refreshAccessToken();
  await maybeRotateSecret(tokenJson.refresh_token);

  let tasks = await loadFromOneDrive(tokenJson.access_token);
  const op = (OP || "pull").trim();

  if (op === "upsert" || op === "delete") {
    tasks = applyOp(tasks, op, (TASK_ID || "").trim(), PAYLOAD || "");
    await saveToOneDrive(tokenJson.access_token, tasks);
  }

  fs.mkdirSync("data", { recursive: true });
  fs.writeFileSync(DATA_PATH, JSON.stringify(tasks, null, 2) + "\n");
  console.log(`Synced ${tasks.length} tasks (op=${op}).`);
}

main().catch((e) => fail(e.message || String(e)));
