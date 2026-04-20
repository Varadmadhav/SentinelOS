import express from "express";
import { checkUpi } from "../controllers/upiController";

const router = express.Router();

router.post("/check", checkUpi);

export default router;