<template>
  <h1>Vulnerable and outdated components</h1>
  <h3>Overview</h3>
  <div>
    It was #2 from the Top 10 community survey but also had enough data to make
    the Top 10 via data. Vulnerable Components are a known issue that we
    struggle to test and assess risk and is the only category to not have any
    Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, so a
    default exploits/impact weight of 5.0 is used. Notable CWEs included are
    CWE-1104: Use of Unmaintained Third-Party Components and the two CWEs from
    Top 10 2013 and 2017.
  </div>
  <h3>Description</h3>
  <div>
    <div>You are likely vulnerable:</div>
    <div>
      <ul>
        <li>
          If you do not know the versions of all components you use (both
          client-side and server-side). This includes components you directly
          use as well as nested dependencies.
        </li>
        <li>
          If the software is vulnerable, unsupported, or out of date. This
          includes the OS, web/application server, database management system
          (DBMS), applications, APIs and all components, runtime environments,
          and libraries.
        </li>
        <li>
          If you do not scan for vulnerabilities regularly and subscribe to
          security bulletins related to the components you use.
        </li>
        <li>
          If you do not fix or upgrade the underlying platform, frameworks, and
          dependencies in a risk-based, timely fashion. This commonly happens in
          environments when patching is a monthly or quarterly task under change
          control, leaving organizations open to days or months of unnecessary
          exposure to fixed vulnerabilities.
        </li>
        <li>
          If software developers do not test the compatibility of updated,
          upgraded, or patched libraries.
        </li>
        <li>If you do not secure the components’ configurations</li>
      </ul>
    </div>
  </div>
  <h3>How to Prevent</h3>
  <div>
    <div>There should be a patch management process in place to:</div>
    <div>
      <ul>
        <li>
          Remove unused dependencies, unnecessary features, components, files,
          and documentation.
        </li>
        <li>
          Continuously inventory the versions of both client-side and
          server-side components (e.g., frameworks, libraries) and their
          dependencies using tools like versions, OWASP Dependency Check,
          retire.js, etc. Continuously monitor sources like Common Vulnerability
          and Exposures (CVE) and National Vulnerability Database (NVD) for
          vulnerabilities in the components. Use software composition analysis
          tools to automate the process. Subscribe to email alerts for security
          vulnerabilities related to components you use.
        </li>
        <li>
          Only obtain components from official sources over secure links. Prefer
          signed packages to reduce the chance of including a modified,
          malicious component
        </li>
        <li>
          Monitor for libraries and components that are unmaintained or do not
          create security patches for older versions. If patching is not
          possible, consider deploying a virtual patch to monitor, detect, or
          protect against the discovered issue.
        </li>
      </ul>
    </div>
    <div>
      Every organization must ensure an ongoing plan for monitoring, triaging,
      and applying updates or configuration changes for the lifetime of the
      application or portfolio.
    </div>
  </div>
  <router-link to="/"><button>back</button></router-link>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "VulnerableAndOutdatedComponents",
});
</script>
