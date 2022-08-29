<template>
  <h1>Security misconfiguration</h1>
  <h3>Overview</h3>
  <div>
    Moving up from #6 in the previous edition, 90% of applications were tested
    for some form of misconfiguration, with an average incidence rate of 4.%,
    and over 208k occurences of a Common Weakness Enumeration (CWE) in this risk
    category. With more shifts into highly configurable software, it's not
    surprising to see this category move up. Notable CWEs included are CWE-16
    Configuration and CWE-611 Improper Restriction of XML External Entity
    Reference.
  </div>
  <h3>Description</h3>
  <div>
    <div>The application might be vulnerable if the application is:</div>
    <div>
      <ul>
        <li>
          Missing appropriate security hardening across any part of the
          application stack or improperly configured permissions on cloud
          services.
        </li>
        <li>
          Unnecessary features are enabled or installed (e.g., unnecessary
          ports, services, pages, accounts, or privileges).
        </li>
        <li>
          Default accounts and their passwords are still enabled and unchanged.
        </li>
        <li>
          Error handling reveals stack traces or other overly informative error
          messages to users.
        </li>
        <li>
          For upgraded systems, the latest security features are disabled or not
          configured securely.
        </li>
        <li>
          The security settings in the application servers, application
          frameworks (e.g., Struts, Spring, ASP.NET), libraries, databases,
          etc., are not set to secure values.
        </li>
        <li>
          The server does not send security headers or directives, or they are
          not set to secure values.
        </li>
        <li>The software is out of date or vulnerable</li>
      </ul>
    </div>
    <div>
      Without a concerted, repeatable application security configuration
      process, systems are at a higher risk.
    </div>
  </div>
  <h3>How to Prevent</h3>
  <div>
    <div>Secure installation processes should be implemented, including:</div>
    <div>
      <ul>
        <li>
          A repeatable hardening process makes it fast and easy to deploy
          another environment that is appropriately locked down. Development,
          QA, and production environments should all be configured identically,
          with different credentials used in each environment. This process
          should be automated to minimize the effort required to set up a new
          secure environment.
        </li>
        <li>
          A minimal platform without any unnecessary features, components,
          documentation, and samples. Remove or do not install unused features
          and frameworks.
        </li>
        <li>
          A task to review and update the configurations appropriate to all
          security notes, updates, and patches as part of the patch management
          process
        </li>
        <li>
          A segmented application architecture provides effective and secure
          separation between components or tenants, with segmentation,
          containerization, or cloud security groups (ACLs).
        </li>
        <li>Sending security directives to clients, e.g., Security Headers.</li>
        <li>
          An automated process to verify the effectiveness of the configurations
          and settings in all environments.
        </li>
      </ul>
    </div>
  </div>
  <router-link to="/"><button>back</button></router-link>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "SecurityMisconfiguration",
});
</script>
