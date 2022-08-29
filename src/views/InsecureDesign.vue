<template>
  <h1>Insecure design</h1>
  <h3>Overview</h3>
  <div>
    A new category for 2021 focuses on risks related to design and architectural
    flaws, with a call for more use of threat modeling, secure design patterns,
    and reference architectures. As a community we need to move beyond
    "shift-left" in the coding space to pre-code activities that are critical
    for the principles of Secure by Design. Notable Common Weakness Enumerations
    (CWEs) include CWE-209: Generation of Error Message Containing Sensitive
    Information, CWE-256: Unprotected Storage of Credentials, CWE-501: Trust
    Boundary Violation, and CWE-522: Insufficiently Protected Credentials.
  </div>
  <h3>Description</h3>
  <div>
    Insecure design is a broad category representing different weaknesses,
    expressed as “missing or ineffective control design.” Insecure design is not
    the source for all other Top 10 risk categories. There is a difference
    between insecure design and insecure implementation. We differentiate
    between design flaws and implementation defects for a reason, they have
    different root causes and remediation. A secure design can still have
    implementation defects leading to vulnerabilities that may be exploited. An
    insecure design cannot be fixed by a perfect implementation as by
    definition, needed security controls were never created to defend against
    specific attacks. One of the factors that contribute to insecure design is
    the lack of business risk profiling inherent in the software or system being
    developed, and thus the failure to determine what level of security design
    is required.
  </div>
  <h3>How to Prevent</h3>
  <div>
    <ul>
      <li>
        Establish and use a secure development lifecycle with AppSec
        professionals to help evaluate and design security and privacy-related
        controls
      </li>
      <li>
        Establish and use a library of secure design patterns or paved road
        ready to use components
      </li>
      <li>
        Use threat modeling for critical authentication, access control,
        business logic, and key flows
      </li>
      <li>Integrate security language and controls into user stories</li>
      <li>
        Integrate plausibility checks at each tier of your application (from
        frontend to backend)
      </li>
      <li>
        Write unit and integration tests to validate that all critical flows are
        resistant to the threat model. Compile use-cases and misuse-cases for
        each tier of your application.
      </li>
      <li>
        Segregate tier layers on the system and network layers depending on the
        exposure and protection needs
      </li>
      <li>Segregate tenants robustly by design throughout all tiers</li>
      <li>Limit resource consumption by user or service</li>
    </ul>
  </div>
  <router-link to="/"><button>back</button></router-link>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "InsecureDesign",
});
</script>
