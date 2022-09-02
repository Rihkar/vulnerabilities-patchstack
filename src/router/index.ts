import { createRouter, createWebHistory, RouteRecordRaw } from "vue-router";
import HomeView from "../views/HomeView.vue";
import CreateVulnerability from "../views/CreateVulnerability.vue";
import DetailedVulnerabilityInfo from "../views/DetailedVulnerabilityInfo.vue";
import EditVulnerability from "../views/EditVulnerability.vue";

const routes: Array<RouteRecordRaw> = [
  {
    path: "/",
    name: "home",
    component: HomeView,
  },
  {
    path: "/create-vulnerability",
    name: "create-vulnerability",
    component: CreateVulnerability,
  },
  {
    path: "/detailed-vulnerability-info/:vulnerability",
    name: "detailed-vulnerability-info",
    component: DetailedVulnerabilityInfo,
  },
  {
    path: "/edit-vulnerability/:vulnerability",
    name: "edit-vulnerability",
    component: EditVulnerability,
  },
];

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes,
});

export default router;
