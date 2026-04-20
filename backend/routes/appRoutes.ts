import express from "express";
import { checkApp, getThreats, dismissThreat } from "../controllers/appController";

const router = express.Router();

router.post("/check", checkApp);
router.get("/threats", getThreats);
router.delete("/threats/:package_name", dismissThreat);

export default router;