<template>
  <h1 class="title">List of Vulnerabilities</h1>
  <div class="nav-bar">
    <div class="single-nav" v-for="nav in vulnerability" :key="nav.title">
      <router-link
        class="nav-link"
        @click="changeVulnerabilityView(nav.id)"
        :to="infoBaseLink + link(nav.title)"
        >{{ nav.title.slice(9) }}</router-link
      >
    </div>
  </div>

  <div class="main-page-container">
    <div
      class="vulnerability-list-box"
      v-for="truncatedVulnerability in vulnerability"
      :key="truncatedVulnerability.title"
    >
      <ul>
        <li class="truncated-vulnerability">
          <router-link
            class="truncated-vulnerability-link"
            @click="changeVulnerabilityView(truncatedVulnerability.id)"
            :to="infoBaseLink + link(truncatedVulnerability.title)"
          >
            {{ truncatedVulnerability.title }}</router-link
          >
          {{ truncatedVulnerability.truncatedDescription }}
          <button class="btn-edit">
            <router-link
              @click="changeVulnerabilityView(truncatedVulnerability.id)"
              :to="editBaseLink + link(truncatedVulnerability.title)"
            >
              <img
                class="img-edit"
                src="https://cdn-icons-png.flaticon.com/512/45/45706.png"
                alt="edit"
            /></router-link>
          </button>
        </li>
      </ul>
    </div>
    <router-link to="/create-vulnerability"
      ><button class="btn-create-vulnerability">
        Create new vulnerability
      </button></router-link
    >
  </div>
</template>

<script setup lang="ts">
import { useVulnerabilitiesStore } from "@/stores/vulnerabilitiesStore";
const { vulnerability, changeVulnerabilityView, link } =
  useVulnerabilitiesStore();
const infoBaseLink = "/detailed-vulnerability-info/";
const editBaseLink = "/edit-vulnerability/";
</script>
