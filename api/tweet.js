// api/tweet.js  (Vercel Serverless Function)
const crypto = require("crypto");
const OAuth = require("oauth-1.0a");

// Build OAuth1 signer
const oauth = OAuth({
  consumer: {
    key: process.env.TWITTER_API_KEY,      // API Key (Consumer Key)
    secret: process.env.TWITTER_API_SECRET // API Secret Key (Consumer Secret)
  },
  signature_method: "HMAC-SHA1",
  hash_function(baseString, key) {
    return crypto.createHmac("sha1", key).update(baseString).digest("base64");
  }
});

module.exports = async (req, res) => {
  try {
    if (req.method !== "POST") {
      res.statusCode = 405;
      return res.json({ error: "Method not allowed" });
    }

    // Simple shared-secret check so only Make can call this
    const secret = req.headers["x-webhook-secret"];
    if (!secret || secret !== process.env.WEBHOOK_SECRET) {
      res.statusCode = 401;
      return res.json({ error: "Unauthorized" });
    }

    // Parse JSON body
    const bodyJson = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const text = (bodyJson.text || "").toString();
    const media_ids = Array.isArray(bodyJson.media_ids) ? bodyJson.media_ids.filter(Boolean) : [];

    if (!text) {
      res.statusCode = 400;
      return res.json({ error: "Missing text" });
    }

    const url = "https://api.twitter.com/2/tweets";
    const requestData = { url, method: "POST" };

    const token = {
      key: process.env.TWITTER_ACCESS_TOKEN,     // Access Token
      secret: process.env.TWITTER_ACCESS_SECRET  // Access Token Secret
    };

    const payload = media_ids.length ? { text, media: { media_ids } } : { text };
    const authHeader = oauth.toHeader(oauth.authorize(requestData, token));

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        ...authHeader,
        "content-type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const data = await resp.json();

    if (!resp.ok) {
      res.statusCode = resp.status;
      return res.json({ error: data });
    }

    res.statusCode = 200;
    return res.json(data);
  } catch (err) {
    res.statusCode = 500;
    return res.json({ error: err?.message || "Unknown error" });
  }
};
