<template>
  <h1>A01:2021 – Broken Access Control</h1>
  <h3>Overview</h3>
  <div>
    Moving up from the fifth position, 94% of applications were tested for some
    form of broken access control with the average incidence rate of 3.81%, and
    has the most occurrences in the contributed dataset with over 318k. Notable
    Common Weakness Enumerations (CWEs) included are CWE-200: Exposure of
    Sensitive Information to an Unauthorized Actor, CWE-201: Insertion of
    Sensitive Information Into Sent Data, and CWE-352: Cross-Site Request
    Forgery.
  </div>
  <h3>Description</h3>
  <div>
    <div>
      Access control enforces policy such that users cannot act outside of their
      intended permissions. Failures typically lead to unauthorized information
      disclosure, modification, or destruction of all data or performing a
      business function outside the user's limits. Common access control
      vulnerabilities include:
    </div>
    <div>
      <ul>
        <li>
          Violation of the principle of least privilege or deny by default,
          where access should only be granted for particular capabilities,
          roles, or users, but is available to anyone.
        </li>
        <li>
          Bypassing access control checks by modifying the URL (parameter
          tampering or force browsing), internal application state, or the HTML
          page, or by using an attack tool modifying API requests.
        </li>
        <li>
          Permitting viewing or editing someone else's account, by providing its
          unique identifier (insecure direct object references)
        </li>
        <li>
          Accessing API with missing access controls for POST, PUT and DELETE.
        </li>
        <li>
          Elevation of privilege. Acting as a user without being logged in or
          acting as an admin when logged in as a user.
        </li>
        <li>
          Metadata manipulation, such as replaying or tampering with a JSON Web
          Token (JWT) access control token, or a cookie or hidden field
          manipulated to elevate privileges or abusing JWT invalidation.
        </li>
        <li>
          CORS misconfiguration allows API access from unauthorized/untrusted
          origins.
        </li>
        <li>
          Force browsing to authenticated pages as an unauthenticated user or to
          privileged pages as a standard user.
        </li>
      </ul>
    </div>
  </div>
  <h3>How to Prevent</h3>
  <div>
    <div>
      Access control is only effective in trusted server-side code or
      server-less API, where the attacker cannot modify the access control check
      or metadata.
    </div>
    <div>
      <ul>
        <li>Except for public resources, deny by default.</li>
        <li>
          Implement access control mechanisms once and re-use them throughout
          the application, including minimizing Cross-Origin Resource Sharing
          (CORS) usage.
        </li>
        <li>
          Model access controls should enforce record ownership rather than
          accepting that the user can create, read, update, or delete any
          record.
        </li>
        <li>
          Unique application business limit requirements should be enforced by
          domain models.
        </li>
        <li>
          Disable web server directory listing and ensure file metadata (e.g.,
          .git) and backup files are not present within web roots.
        </li>
        <li>
          Log access control failures, alert admins when appropriate (e.g.,
          repeated failures).
        </li>
        <li>
          Rate limit API and controller access to minimize the harm from
          automated attack tooling.
        </li>
        <li>
          Stateful session identifiers should be invalidated on the server after
          logout. Stateless JWT tokens should rather be short-lived so that the
          window of opportunity for an attacker is minimized. For longer lived
          JWTs it's highly recommended to follow the OAuth standards to revoke
          access.
        </li>
      </ul>
    </div>
  </div>
  <router-link to="/"><button>back</button></router-link>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "BrokenAccessControl",
});
</script>
