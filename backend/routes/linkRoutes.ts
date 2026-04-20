import express from "express";
import { checkUrl } from "../controllers/linkController";

const router = express.Router();

router.post("/check", checkUrl);

export default router;