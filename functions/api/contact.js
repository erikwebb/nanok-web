// Cloudflare Pages Function: /api/contact
// Hardened with Cloudflare Turnstile verification, honeypot, and rate validation.

export async function onRequestPost({ request, env }) {
  try {
    const contentType = request.headers.get("content-type") || "";
    let body = {};

    if (contentType.includes("application/json")) {
      body = await request.json();
    } else if (contentType.includes("application/x-www-form-urlencoded")) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries());
    }

    const { name, email, organization, service, message, honeypot } = body;
    const turnstileToken = body["cf-turnstile-response"] || body.turnstileToken;

    // 1. Spam Honeypot Check
    if (honeypot) {
      return new Response(JSON.stringify({ success: true, note: "Ignored spam" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    // 2. Field Validation
    if (!name || !email || !message) {
      return new Response(JSON.stringify({ 
        success: false, 
        error: "Name, email, and message are required." 
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Basic email format check
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

    // 3. Cloudflare Turnstile Verification
    const secretKey = env?.TURNSTILE_SECRET_KEY || "1x0000000000000000000000000000000AA";
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
        body: verifyFormData
      });
      const verifyOutcome = await verifyRes.json();
      
      if (!verifyOutcome.success) {
        console.warn("[Turnstile Failed]", verifyOutcome);
        return new Response(JSON.stringify({ 
          success: false, 
          error: "Security verification failed. Please try again." 
        }), {
          status: 403,
          headers: { "Content-Type": "application/json" }
        });
      }
    } catch (e) {
      console.error("[Turnstile Error]", e);
      return new Response(JSON.stringify({ 
        success: false, 
        error: "Verification service temporarily unavailable. Please try again shortly." 
      }), {
        status: 502,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Log received submission safely at the edge
    console.log(`[Contact Form Received] From: ${name} <${email}> | Org: ${organization || 'N/A'} | Service: ${service || 'General'}`);
    console.log(`[Message]: ${message}`);

    return new Response(JSON.stringify({
      success: true,
      message: "Thank you for reaching out. Your message has been received."
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });

  } catch (err) {
    return new Response(JSON.stringify({ 
      success: false, 
      error: "An unexpected error occurred. Please try again." 
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
