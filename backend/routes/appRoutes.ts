import express from "express";
import { checkApp } from "../controllers/appController";

const router = express.Router();

router.post("/check", checkApp);

export default router;