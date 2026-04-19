import { createBrowserRouter } from "react-router";
import { Root } from "./components/Root";
import { Home } from "./components/Home";
import { Activity } from "./components/Activity";
import { Shield } from "./components/Shield";
import { Reports } from "./components/Reports";
import { Settings } from "./components/Settings";
import { CallShield } from "./components/shields/CallShield";
import { LinkShield } from "./components/shields/LinkShield";
import { UpiShield } from "./components/shields/UpiShield";
import { ScreenShield } from "./components/shields/ScreenShield";
import { AppShield } from "./components/shields/AppShield";
import { ThreatDetail } from "./components/ThreatDetail";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Root,
    children: [
      { index: true, Component: Home },
      { path: "activity", Component: Activity },
      { path: "activity/:id", Component: ThreatDetail },
      { path: "shield", Component: Shield },
      { path: "shield/call", Component: CallShield },
      { path: "shield/link", Component: LinkShield },
      { path: "shield/upi", Component: UpiShield },
      { path: "shield/screen", Component: ScreenShield },
      { path: "shield/app", Component: AppShield },
      { path: "reports", Component: Reports },
      { path: "settings", Component: Settings },
    ],
  },
]);
