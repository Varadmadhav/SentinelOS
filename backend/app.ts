import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import linkRoutes from "./routes/linkRoutes";
import callRoutes from "./routes/callRoutes";
import upiRoutes    from "./routes/upiRoutes";
import screenRoutes from "./routes/screenRoutes";
import appRoutes    from "./routes/appRoutes";

dotenv.config();

const app = express();

// Middlewares
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/api/call", callRoutes);
app.use("/api/link",   linkRoutes);
app.use("/api/call",   callRoutes);
app.use("/api/upi",    upiRoutes);
app.use("/api/screen", screenRoutes);
app.use("/api/app",    appRoutes);

// Health check
app.get("/", (req, res) => {
  res.send("SentinelOS Backend Running 🚀");
});

// ML Routes
app.use("/api/link", linkRoutes);

// Error handler (basic)
app.use((err: any, req: any, res: any, next: any) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong" });
});

// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🔥 Server running on http://localhost:${PORT}`);
});
