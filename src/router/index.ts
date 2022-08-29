import { createRouter, createWebHistory, RouteRecordRaw } from "vue-router";
import HomeView from "../views/HomeView.vue";
import BrokenAccessControl from "../views/BrokenAccessControl.vue";
import CryptographicFailures from "../views/CryptographicFailures.vue";
import InjectionVulnerability from "../views/InjectionVulnerability.vue";
import InsecureDesign from "../views/InsecureDesign.vue";
import SecurityMisconfiguration from "../views/SecurityMisconfiguration.vue";
import VulnerableAndOutdatedComponents from "../views/VulnerableAndOutdatedComponents.vue";
import IdentificationAndAuthentificationFailures from "../views/IdentificationAndAuthentificationFailures.vue";
import SoftwareAndDataIntegrityFailures from "../views/SoftwareAndDataIntegrityFailures.vue";
import SecurityLoggingAndMonitoringFailures from "../views/SecurityLoggingAndMonitoringFailures.vue";
import ServerSideRequestForgery from "../views/ServerSideRequestForgery.vue";

const routes: Array<RouteRecordRaw> = [
  {
    path: "/",
    name: "home",
    component: HomeView,
  },
  {
    path: "/BrokenAccessControl",
    name: "BrokenAccessControl",
    component: BrokenAccessControl,
  },
  {
    path: "/CryptographicFailures",
    name: "CryptographicFailures",
    component: CryptographicFailures,
  },
  {
    path: "/InjectionVulnerability",
    name: "InjectionVulnerability",
    component: InjectionVulnerability,
  },
  {
    path: "/InsecureDesign",
    name: "InsecureDesign",
    component: InsecureDesign,
  },
  {
    path: "/SecurityMisconfiguration",
    name: "SecurityMisconfiguration",
    component: SecurityMisconfiguration,
  },
  {
    path: "/VulnerableAndOutdatedComponents",
    name: "VulnerableAndOutdatedComponents",
    component: VulnerableAndOutdatedComponents,
  },
  {
    path: "/IdentificationAndAuthentificationFailures",
    name: "IdentificationAndAuthentificationFailures",
    component: IdentificationAndAuthentificationFailures,
  },
  {
    path: "/SoftwareAndDataIntegrityFailures",
    name: "SoftwareAndDataIntegrityFailures",
    component: SoftwareAndDataIntegrityFailures,
  },
  {
    path: "/SecurityLoggingAndMonitoringFailures",
    name: "SecurityLoggingAndMonitoringFailures",
    component: SecurityLoggingAndMonitoringFailures,
  },
  {
    path: "/ServerSideRequestForgery",
    name: "ServerSideRequestForgery",
    component: ServerSideRequestForgery,
  },
];

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes,
});

export default router;
