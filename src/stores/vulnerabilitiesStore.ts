import { defineStore } from "pinia";
import vulnerabilitiesData from "@/components/data/vulnerabilitesData";
import { VulnerabilitesDataType } from "@/Models/models";

export const useVulnerabilitiesStore = defineStore("characters", {
  state: () => ({
    vulnerability: vulnerabilitiesData,
    headlines: ["Overview", "Description", "How to Prevent"],
    buttonBack: "back",
    currentView: {} as VulnerabilitesDataType | undefined,
    newVulnerability: {} as VulnerabilitesDataType,
  }),
  getters: {},
  actions: {
    changeVulnerabilityView(id: string) {
      this.currentView = this.vulnerability.find((vulnerability) => {
        return vulnerability.id === id;
      });
      console.log(this.currentView);
    },
    addVulnerability(newVulnerability: VulnerabilitesDataType) {
      this.vulnerability = [...this.vulnerability, { ...newVulnerability }];
      this.newVulnerability = {} as VulnerabilitesDataType;
    },
    link(title: string) {
      return title.slice(9).toLowerCase().replace(/\s+/g, "-");
    },
  },
});
