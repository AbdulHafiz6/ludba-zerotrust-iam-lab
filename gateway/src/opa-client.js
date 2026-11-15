export async function evaluatePolicy({ opaUrl, decisionPath, timeoutMs, input }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${opaUrl}${decisionPath}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ input }),
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`OPA returned HTTP ${response.status}`);
    const body = await response.json();
    if (typeof body.result !== "boolean") throw new Error("OPA returned an invalid decision document");
    return body.result;
  } finally {
    clearTimeout(timeout);
  }
}
