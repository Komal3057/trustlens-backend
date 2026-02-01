const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());

// 1) Mongo connect
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected ✅"))
  .catch((err) => console.log("Mongo error:", err));

// 2) Models
const UserSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true },
    passwordHash: String,
    trustScore: { type: Number, default: 80 },
    knownDevices: { type: [String], default: [] },
  },
  { timestamps: true },
);

const EventSchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,
    type: String, // LOGIN_FAIL, OTP_REQUEST, LOGIN_SUCCESS
    ip: String,
    deviceId: String,
  },
  { timestamps: true },
);

const User = mongoose.model("User", UserSchema);
const EventLog = mongoose.model("EventLog", EventSchema);

// 3) Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// 4) Trust score logic (simple rules)
async function updateTrustScore(user, event) {
  let delta = 0;

  // Rule A: New device = -10
  if (event.deviceId && !user.knownDevices.includes(event.deviceId)) {
    user.knownDevices.push(event.deviceId);
    delta -= 10;
  }

  // Rule B: 3+ OTP requests in last 10 min = -25
  if (event.type === "OTP_REQUEST") {
    const tenMinAgo = new Date(Date.now() - 10 * 60 * 1000);
    const countOtp = await EventLog.countDocuments({
      userId: user._id,
      type: "OTP_REQUEST",
      createdAt: { $gte: tenMinAgo },
    });
    if (countOtp >= 3) delta -= 25;
  }

  // Rule C: 3+ login fails in last 5 min = -20
  if (event.type === "LOGIN_FAIL") {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
    const countFail = await EventLog.countDocuments({
      userId: user._id,
      type: "LOGIN_FAIL",
      createdAt: { $gte: fiveMinAgo },
    });
    if (countFail >= 3) delta -= 20;
  }

  // Rule D: Login success = +2 (small reward)
  if (event.type === "LOGIN_SUCCESS") delta += 2;

  // apply delta
  user.trustScore = Math.max(0, Math.min(100, user.trustScore + delta));
  await user.save();

  return { delta, trustScore: user.trustScore };
}

// ✅ Health check
app.get("/health", (req, res) => res.json({ ok: true }));

// ✅ Register
app.post("/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "email/password required" });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = await User.create({ email, passwordHash });

  res.json({ message: "Registered ✅", userId: user._id });
});

// ✅ Login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const deviceId = req.headers["x-device-id"] || "unknown-device";
  const ip = req.headers["x-ip"] || "127.0.0.1";

  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);

  // log login event
  await EventLog.create({
    userId: user._id,
    type: ok ? "LOGIN_SUCCESS" : "LOGIN_FAIL",
    ip,
    deviceId,
  });

  // update trust score
  const result = await updateTrustScore(user, {
    type: ok ? "LOGIN_SUCCESS" : "LOGIN_FAIL",
    ip,
    deviceId,
  });

  if (!ok)
    return res
      .status(401)
      .json({ error: "Wrong password", trustScore: result.trustScore });

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
  res.json({ message: "Login ✅", token, trustScore: result.trustScore });
});

// ✅ Add event (OTP_REQUEST etc.)
app.post("/events", auth, async (req, res) => {
  const { type, deviceId, ip } = req.body;
  if (!type) return res.status(400).json({ error: "type required" });

  const user = await User.findById(req.user.userId);
  if (!user) return res.status(404).json({ error: "User not found" });

  const event = await EventLog.create({
    userId: user._id,
    type,
    deviceId: deviceId || "unknown-device",
    ip: ip || "127.0.0.1",
  });

  const result = await updateTrustScore(user, event);
  res.json({ message: "Event saved ✅", ...result });
});

// ✅ See my trust score
app.get("/trust/me", auth, async (req, res) => {
  const user = await User.findById(req.user.userId);
  res.json({
    trustScore: user.trustScore,
    risk: user.trustScore < 40 ? "HIGH" : "NORMAL",
  });
});

// Start server
app.listen(process.env.PORT, () =>
  console.log("Server running ✅ on port", process.env.PORT),
);
