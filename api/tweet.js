import crypto from "crypto";
import OAuth from "oauth-1.0a";

const oauth = OAuth({
  consumer: {
    key: process.env.TWITTER_API_KEY,
    secret: process.env.TWITTER_API_SECRET,
  },
  signature_method: "HMAC-SHA1",
  hash_function(baseString, key) {
    return crypto.createHmac("sha1", key).update(baseString).digest("base64");
  },
});

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

    const secret = req.headers["x-webhook-secret"];
    if (!secret || secret !== process.env.WEBHOOK_SECRET) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const text = (body.text || "").toString();
    const media_ids = Array.isArray(body.media_ids) ? body.media_ids.filter(Boolean) : [];
    if (!text) return res.status(400).json({ error: "Missing text" });

    const url = "https://api.twitter.com/2/tweets";
    const token = {
      key: process.env.TWITTER_ACCESS_TOKEN,
      secret: process.env.TWITTER_ACCESS_SECRET,
    };
    const payload = media_ids.length ? { text, media: { media_ids } } : { text };

    const requestData = { url, method: "POST" };
    const authHeader = oauth.toHeader(oauth.authorize(requestData, token));

    const resp = await fetch(url, {
      method: "POST",
      headers: { ...authHeader, "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await resp.json();
    if (!resp.ok) return res.status(resp.status).json({ error: data });
    return res.status(200).json(data);
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Unknown error" });
  }
}
