require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');

const app = express();
const port = process.env.PORT || 4000;

// --- CORS middleware ---
const allowedOrigins = [
  'https://api-testengine.netlify.app'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  console.log(`[DEBUG] Incoming request: ${req.method} ${req.url} from origin: ${origin}`);
  
  if (allowedOrigins.includes(origin)) {
    console.log(`[DEBUG] CORS allowed for origin: ${origin}`);
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  } else {
    console.log(`[DEBUG] CORS blocked for origin: ${origin}`);
  }

  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json());
console.log("[DEBUG] JSON middleware enabled");

// --- Firebase Admin SDK ---
console.log("[DEBUG] Initializing Firebase Admin SDK");
const serviceAccount = JSON.parse(Buffer.from(process.env.FIREBASE_JSON, "base64").toString("utf8"));
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
console.log("[DEBUG] Firebase Admin SDK initialized");

// --- Nodemailer ---
console.log("[DEBUG] Setting up Nodemailer transporter");
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: { 
    user: process.env.EMAIL_USER, 
    pass: process.env.EMAIL_PASS 
  },
  logger: true,
  debug: true,
  tls: { rejectUnauthorized: false }
});

async function sendEmail(to, subject, html) {
  console.log(`[DEBUG] sendEmail() called with to=${to}, subject=${subject}`);
  try {
    const info = await transporter.sendMail({ from: `"StudyBuddy" <${process.env.EMAIL_USER}>`, to, subject, html });
    console.log(`[DEBUG] Email sent successfully to ${to}: messageId=${info.messageId}`);
    console.log(`[DEBUG] Full Nodemailer info:`, info);
    return info;
  } catch (err) {
    console.log(`[DEBUG] Email send error: ${err.message}`);
    throw err;
  }
}

// --- Firebase token middleware ---
async function verifyToken(req, res, next) {
  console.log(`[DEBUG] verifyToken() called`);
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.log("[DEBUG] No Authorization header found");
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  console.log(`[DEBUG] Token extracted: ${token}`);

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    console.log("[DEBUG] Firebase token verified successfully:", decodedToken);
    req.user = decodedToken;
    next();
  } catch (err) {
    console.log("[DEBUG] Firebase token verification failed:", err.message);
    res.status(403).json({ error: 'Invalid Firebase token', details: err.message });
  }
}

// --- Routes ---

// Signup
app.post("/signup", async (req, res) => {
  console.log("[DEBUG] /signup called with body:", req.body);
  const { email, password } = req.body;
  if (!email || !password) {
    console.log("[DEBUG] Missing email or password");
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const user = await admin.auth().createUser({ email, password });
    console.log("[DEBUG] Firebase user created:", user.uid);
    res.json({ message: "User created", uid: user.uid });
  } catch (err) {
    console.log("[DEBUG] Signup error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Login (server-side Firebase)
app.post("/login", async (req, res) => {
  console.log("[DEBUG] /login called with body:", req.body);
  const { email, password } = req.body;
  if (!email || !password) {
    console.log("[DEBUG] Missing email or password for login");
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY;
    if (!FIREBASE_API_KEY) throw new Error("Missing FIREBASE_API_KEY in .env");

    // Sign in via REST API
    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true })
      }
    );

    const data = await response.json();
    if (!response.ok) {
      console.log("[DEBUG] Login failed:", data);
      return res.status(400).json({ error: data.error.message || "Login failed" });
    }

    console.log("[DEBUG] Login successful:", data);

    // Get UID from Admin SDK
    const userRecord = await admin.auth().getUserByEmail(email);

    // Send both UID and ID token
    res.json({
      message: "Login successful",
      uid: userRecord.uid,      // for your DB queries
      idToken: data.idToken,    // for AI API requests
      refreshToken: data.refreshToken
    });

  } catch (err) {
    console.log("[DEBUG] Login error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Reset password
app.post("/reset-password", async (req, res) => {
  console.log("[DEBUG] /reset-password called with body:", req.body);
  const { email } = req.body;
  if (!email) {
    console.log("[DEBUG] No email provided");
    return res.status(400).json({ error: 'Email required' });
  }

  try {
    const link = await admin.auth().generatePasswordResetLink(email);
    console.log("[DEBUG] Password reset link generated:", link);
    const info = await sendEmail(email, "Reset your password", `<p>Click here to reset password:</p><a href="${link}">${link}</a>`);
    res.json({ message: "Password reset link sent!", debug: { link, emailInfo: info } });
  } catch (err) {
    console.log("[DEBUG] Reset password error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Protected route
app.get("/profile", verifyToken, (req, res) => {
  console.log("[DEBUG] /profile accessed by user:", req.user);
  res.json({ message: "Profile access works", user: req.user });
});

// Start server
app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));
