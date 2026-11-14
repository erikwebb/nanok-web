// Cloudflare Pages Function: /api/contact
// Receives contact form submissions and processes them at the edge.

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

    // Spam honeypot check
    if (honeypot) {
      return new Response(JSON.stringify({ success: true, note: "Ignored spam" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Basic validation
    if (!name || !email || !message) {
      return new Response(JSON.stringify({ 
        success: false, 
        error: "Name, email, and message are required." 
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    // In Cloudflare, if an environment secret like DISCORD_WEBHOOK or RESEND_API_KEY
    // or NOTIFICATION_EMAIL is configured, we can forward it here.
    // For now, log and acknowledge successful receipt.
    console.log(`[Contact Form] From: ${name} <${email}> | Org: ${organization || 'N/A'} | Service: ${service || 'General'}`);
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
