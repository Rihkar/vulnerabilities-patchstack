<template>
  <h1>Software and data integrity failures</h1>
  <h3>Overview</h3>
  <div>
    A new category for 2021 focuses on making assumptions related to software
    updates, critical data, and CI/CD pipelines without verifying integrity. One
    of the highest weighted impacts from Common Vulnerability and
    Exposures/Common Vulnerability Scoring System (CVE/CVSS) data. Notable
    Common Weakness Enumerations (CWEs) include CWE-829: Inclusion of
    Functionality from Untrusted Control Sphere, CWE-494: Download of Code
    Without Integrity Check, and CWE-502: Deserialization of Untrusted Data.
  </div>
  <h3>Description</h3>
  <div>
    Software and data integrity failures relate to code and infrastructure that
    does not protect against integrity violations. An example of this is where
    an application relies upon plugins, libraries, or modules from untrusted
    sources, repositories, and content delivery networks (CDNs). An insecure
    CI/CD pipeline can introduce the potential for unauthorized access,
    malicious code, or system compromise. Lastly, many applications now include
    auto-update functionality, where updates are downloaded without sufficient
    integrity verification and applied to the previously trusted application.
    Attackers could potentially upload their own updates to be distributed and
    run on all installations. Another example is where objects or data are
    encoded or serialized into a structure that an attacker can see and modify
    is vulnerable to insecure deserialization.
  </div>
  <h3>How to Prevent</h3>
  <div>
    <ul>
      <li>
        Use digital signatures or similar mechanisms to verify the software or
        data is from the expected source and has not been altered.
      </li>
      <li>
        Ensure libraries and dependencies, such as npm or Maven, are consuming
        trusted repositories. If you have a higher risk profile, consider
        hosting an internal known-good repository that's vetted.
      </li>
      <li>
        Ensure that a software supply chain security tool, such as OWASP
        Dependency Check or OWASP CycloneDX, is used to verify that components
        do not contain known vulnerabilities
      </li>
      <li>
        Ensure that there is a review process for code and configuration changes
        to minimize the chance that malicious code or configuration could be
        introduced into your software pipeline.
      </li>
      <li>
        Ensure that your CI/CD pipeline has proper segregation, configuration,
        and access control to ensure the integrity of the code flowing through
        the build and deploy processes.
      </li>
      <li>
        Ensure that unsigned or unencrypted serialized data is not sent to
        untrusted clients without some form of integrity check or digital
        signature to detect tampering or replay of the serialized data
      </li>
    </ul>
  </div>
  <router-link to="/"><button>back</button></router-link>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "SoftwareAndDataIntegrityFailures",
});
</script>
