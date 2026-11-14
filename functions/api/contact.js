// Cloudflare Pages Function: /api/contact
// Hardened with Cloudflare Turnstile verification, honeypot, payload limits, and origin validation.

const MAX_PAYLOAD_BYTES = 64 * 1024; // 64 KB limit
const MAX_FIELD_LENGTHS = {
  name: 100,
  email: 254,
  organization: 100,
  service: 100,
  message: 5000
};

export async function onRequestPost({ request, env }) {
  try {
    // 1. Origin / Referer validation (Defense-in-depth against unauthorized cross-site POSTs)
    const origin = request.headers.get("origin");
    const host = request.headers.get("host");
    if (origin && host) {
      try {
        const originUrl = new URL(origin);
        if (originUrl.host !== host) {
          return new Response(JSON.stringify({ success: false, error: "Cross-origin request forbidden." }), {
            status: 403,
            headers: { "Content-Type": "application/json" }
          });
        }
      } catch {
        return new Response(JSON.stringify({ success: false, error: "Invalid Origin header." }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    // 2. Payload size bounding
    const contentLength = parseInt(request.headers.get("content-length") || "0", 10);
    if (contentLength > MAX_PAYLOAD_BYTES) {
      return new Response(JSON.stringify({ success: false, error: "Payload exceeds size limit." }), {
        status: 413,
        headers: { "Content-Type": "application/json" }
      });
    }

    const contentType = request.headers.get("content-type") || "";
    let body = {};

    if (contentType.includes("application/json")) {
      body = await request.json();
    } else if (contentType.includes("application/x-www-form-urlencoded")) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries());
    } else {
      return new Response(JSON.stringify({ success: false, error: "Unsupported Media Type." }), {
        status: 415,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (!body || typeof body !== "object") {
      return new Response(JSON.stringify({ success: false, error: "Invalid request body." }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Extract, trim, and type-guard fields
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const organization = typeof body.organization === "string" ? body.organization.trim() : "";
    const service = typeof body.service === "string" ? body.service.trim() : "";
    const message = typeof body.message === "string" ? body.message.trim() : "";
    const honeypot = typeof body.honeypot === "string" ? body.honeypot.trim() : body.honeypot;
    const rawToken = body["cf-turnstile-response"] || body.turnstileToken;
    const turnstileToken = typeof rawToken === "string" ? rawToken.trim() : "";

    // 3. Spam Honeypot Check
    if (honeypot) {
      return new Response(JSON.stringify({ success: true, note: "Ignored spam" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 4. Field Validation & Length Bounds
    if (!name || !email || !message) {
      return new Response(JSON.stringify({ 
        success: false, 
        error: "Name, email, and message are required." 
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (
      name.length > MAX_FIELD_LENGTHS.name ||
      email.length > MAX_FIELD_LENGTHS.email ||
      organization.length > MAX_FIELD_LENGTHS.organization ||
      service.length > MAX_FIELD_LENGTHS.service ||
      message.length > MAX_FIELD_LENGTHS.message
    ) {
      return new Response(JSON.stringify({ 
        success: false, 
        error: "Field length exceeds permitted limits." 
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Email format check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return new Response(JSON.stringify({ 
        success: false, 
        error: "Please provide a valid work email address." 
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 5. Cloudflare Turnstile Verification (Fail-closed)
    const secretKey = env?.TURNSTILE_SECRET_KEY;
    if (!secretKey) {
      console.error("[Configuration Error] TURNSTILE_SECRET_KEY is not configured.");
      return new Response(JSON.stringify({ 
        success: false, 
        error: "Server configuration error. Please contact administrator." 
      }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (!turnstileToken) {
      return new Response(JSON.stringify({ 
        success: false, 
        error: "Security verification required. Please complete the verification checkbox." 
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    try {
      const ip = request.headers.get("cf-connecting-ip");
      const verifyFormData = new FormData();
      verifyFormData.append("secret", secretKey);
      verifyFormData.append("response", turnstileToken);
      if (ip) verifyFormData.append("remoteip", ip);

      const verifyRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        body: verifyFormData,
        signal: AbortSignal.timeout(5000)
      });
      const verifyOutcome = await verifyRes.json();
      
      if (!verifyOutcome.success) {
        console.warn("[Turnstile Failed]", {
          errorCodes: verifyOutcome["error-codes"],
          timestamp: new Date().toISOString()
        });
        return new Response(JSON.stringify({ 
          success: false, 
          error: "Security verification failed. Please try again." 
        }), {
          status: 403,
          headers: { "Content-Type": "application/json" }
        });
      }

      // Hostname verification check
      if (verifyOutcome.hostname && host && !host.includes(verifyOutcome.hostname) && !verifyOutcome.hostname.includes("nanok.consulting") && verifyOutcome.hostname !== "localhost") {
        console.warn("[Turnstile Hostname Mismatch]", { expected: host, received: verifyOutcome.hostname });
        return new Response(JSON.stringify({ 
          success: false, 
          error: "Verification validation error." 
        }), {
          status: 403,
          headers: { "Content-Type": "application/json" }
        });
      }
    } catch (e) {
      console.error("[Turnstile Error]", e?.message || e);
      return new Response(JSON.stringify({ 
        success: false, 
        error: "Verification service temporarily unavailable. Please try again shortly." 
      }), {
        status: 502,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Safe operational telemetry logging (NO PII or message content)
    console.log(`[Contact Form Received] Timestamp: ${new Date().toISOString()} | Service: ${service || 'General'} | MsgLength: ${message.length}`);

    return new Response(JSON.stringify({
      success: true,
      message: "Thank you for reaching out. Your message has been received."
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });

  } catch (err) {
    console.error("[Contact Error]", err?.message || err);
    return new Response(JSON.stringify({ 
      success: false, 
      error: "An unexpected error occurred. Please try again." 
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
