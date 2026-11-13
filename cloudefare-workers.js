const ALLOWED_HOSTS = new Set(["opium.best"]);
const ALLOWED_CONTENT_TYPES = new Set([
  "text/html",
  "text/plain",
  "application/json",
  "application/xml",
  "text/xml",
]);
const MAX_URL_LENGTH = 2048;
const MAX_REQUEST_BYTES = 4096;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_PREVIEW_CHARACTERS = 4000;
const MAX_REDIRECTS = 3;
const MAX_LINKS = 40;
const MAX_SCANNED_ANCHORS = 500;

export default {
  async fetch(request, env) {
    const requestUrl = new URL(request.url);

    if (request.method === "GET" && requestUrl.pathname === "/healthz") {
      return json({ status: "ok", allowedHost: "opium.best" });
    }

    if (requestUrl.pathname !== "/proxy") {
      return json({ error: "Not found." }, 404);
    }

    if (request.method !== "POST") {
      return json({ error: "Use POST for proxy requests." }, 405, {
        Allow: "POST",
      });
    }

    if (!env.PROXY_TOKEN) {
      return json({ error: "Proxy authentication is not configured." }, 503);
    }

    if (request.headers.get("Authorization") !== `Bearer ${env.PROXY_TOKEN}`) {
      return json({ error: "Unauthorized." }, 401);
    }

    const contentLength = Number(request.headers.get("Content-Length") || 0);
    if (contentLength > MAX_REQUEST_BYTES) {
      return json({ error: "Request body is too large." }, 413);
    }

    let rawBody;
    try {
      rawBody = request.body
        ? await readTextLimited(request.body, MAX_REQUEST_BYTES)
        : "";
    } catch {
      return json({ error: "Request body is too large." }, 413);
    }
    let input;
    try {
      input = JSON.parse(rawBody);
    } catch {
      return json({ error: "Send a valid JSON request." }, 400);
    }

    if (!input || typeof input !== "object" || Array.isArray(input)) {
      return json({ error: "Send a JSON object." }, 400);
    }
    if (
      Object.keys(input).some((key) => !["url", "method"].includes(key))
    ) {
      return json({ error: "Only url and method are accepted." }, 400);
    }

    const method = input.method || "GET";
    if (method !== "GET" && method !== "HEAD") {
      return json({ error: "Only GET and HEAD requests are allowed." }, 405);
    }

    let target;
    try {
      target = validateTarget(input.url);
    } catch (error) {
      return json({ error: error.message }, 403);
    }

    try {
      const { response: upstream, finalUrl } = await fetchAllowedTarget(
        target,
        method,
      );
      const contentType = (upstream.headers.get("Content-Type") || "")
        .split(";")[0]
        .trim()
        .toLowerCase();

      if (!ALLOWED_CONTENT_TYPES.has(contentType)) {
        return json(
          { error: "This proxy returns text and JSON responses only." },
          415,
        );
      }

      const upstreamLength = Number(
        upstream.headers.get("Content-Length") || 0,
      );
      if (upstreamLength > MAX_RESPONSE_BYTES) {
        return json({ error: "The upstream response exceeds 1 MB." }, 413);
      }

      let body = "";
      if (method !== "HEAD" && upstream.body) {
        try {
          body = await readTextLimited(upstream.body, MAX_RESPONSE_BYTES);
        } catch (error) {
          if (error.message === "RESPONSE_TOO_LARGE") {
            return json({ error: "The upstream response exceeds 1 MB." }, 413);
          }
          throw error;
        }
      }

      return json({
        upstreamStatus: upstream.status,
        contentType,
        finalUrl,
        body: body.slice(0, MAX_PREVIEW_CHARACTERS),
        links:
          contentType === "text/html"
            ? extractAllowedLinks(body, finalUrl)
            : [],
        truncated: body.length > MAX_PREVIEW_CHARACTERS,
      });
    } catch (error) {
      return json(
        {
          error:
            error instanceof Error
              ? error.message
              : "The upstream request failed.",
        },
        502,
      );
    }
  },
};

function validateTarget(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("Enter an HTTPS URL on opium.best.");
  }
  if (value.length > MAX_URL_LENGTH) {
    throw new Error("The URL is too long.");
  }

  let target;
  try {
    target = new URL(value);
  } catch {
    throw new Error("Enter a valid HTTPS URL on opium.best.");
  }

  if (target.protocol !== "https:") {
    throw new Error("Only HTTPS destinations are allowed.");
  }
  if (target.username || target.password) {
    throw new Error("URLs containing user information are not allowed.");
  }
  if (target.port && target.port !== "443") {
    throw new Error("Only the standard HTTPS port is allowed.");
  }
  if (!ALLOWED_HOSTS.has(target.hostname.toLowerCase())) {
    throw new Error("This destination is not on the authorized host list.");
  }
  if (target.hash) {
    target.hash = "";
  }

  return target;
}

async function fetchAllowedTarget(initialTarget, method) {
  let target = initialTarget;

  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount++) {
    const response = await fetch(target.toString(), {
      method,
      redirect: "manual",
      headers: {
        Accept: "text/html, application/json, text/plain, application/xml",
        "User-Agent": "StudyProxy/1.0",
      },
      signal: AbortSignal.timeout(12000),
    });

    if (![301, 302, 303, 307, 308].includes(response.status)) {
      return { response, finalUrl: target.toString() };
    }

    const location = response.headers.get("Location");
    if (!location || redirectCount === MAX_REDIRECTS) {
      throw new Error("The upstream redirect could not be followed safely.");
    }

    let redirectedTarget;
    try {
      redirectedTarget = validateTarget(new URL(location, target).toString());
    } catch {
      throw new Error("The upstream redirected outside the authorized host.");
    }
    target = redirectedTarget;
  }

  throw new Error("Too many upstream redirects.");
}

function extractAllowedLinks(html, baseUrl) {
  const anchorPattern = /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi;
  const links = [];
  const seen = new Set();
  let match;
  let scanned = 0;

  while (
    scanned < MAX_SCANNED_ANCHORS &&
    links.length < MAX_LINKS &&
    (match = anchorPattern.exec(html))
  ) {
    scanned++;
    const attributes = match[1];
    const hrefMatch = attributes.match(
      /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i,
    );
    if (!hrefMatch) continue;

    const rawHref = decodeHtmlEntities(
      hrefMatch[1] ?? hrefMatch[2] ?? hrefMatch[3] ?? "",
    ).trim();
    if (!rawHref) continue;

    try {
      const target = validateTarget(new URL(rawHref, baseUrl).toString());
      const href = target.toString();
      if (seen.has(href) || href === new URL(baseUrl).toString()) continue;
      seen.add(href);

      const label = decodeHtmlEntities(
        match[2]
          .replace(/<!--[\s\S]*?-->/g, " ")
          .replace(/<[^>]*>/g, " "),
      )
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 120);

      links.push({
        href,
        label: label || target.pathname || "Open link",
      });
    } catch {
      // Exclude malformed, non-HTTPS, and off-host links.
    }
  }

  return links;
}

function decodeHtmlEntities(value) {
  return value.replace(
    /&(#(?:x[0-9a-f]+|\d+)|amp|quot|apos|lt|gt);/gi,
    (entity, name) => {
      const normalized = name.toLowerCase();
      if (normalized === "amp") return "&";
      if (normalized === "quot") return '"';
      if (normalized === "apos") return "'";
      if (normalized === "lt") return "<";
      if (normalized === "gt") return ">";

      const codePoint = normalized.startsWith("#x")
        ? Number.parseInt(normalized.slice(2), 16)
        : Number.parseInt(normalized.slice(1), 10);
      if (
        !Number.isInteger(codePoint) ||
        codePoint < 0 ||
        codePoint > 0x10ffff ||
        (codePoint >= 0xd800 && codePoint <= 0xdfff)
      ) {
        return entity;
      }
      return String.fromCodePoint(codePoint);
    },
  );
}

async function readTextLimited(stream, maxBytes) {
  const reader = stream.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new Error("RESPONSE_TOO_LARGE");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}
