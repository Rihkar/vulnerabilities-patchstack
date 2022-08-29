<template>
  <h1>Identification and authentification failures</h1>
  <h3>Overview</h3>
  <div>
    Previously known as Broken Authentication, this category slid down from the
    second position and now includes Common Weakness Enumerations (CWEs) related
    to identification failures. Notable CWEs included are CWE-297: Improper
    Validation of Certificate with Host Mismatch, CWE-287: Improper
    Authentication, and CWE-384: Session Fixation.
  </div>
  <h3>Description</h3>
  <div>
    <div>
      Confirmation of the user's identity, authentication, and session
      management is critical to protect against authentication-related attacks.
      There may be authentication weaknesses if the application:
    </div>
    <div>
      <ul>
        <li>
          Permits automated attacks such as credential stuffing, where the
          attacker has a list of valid usernames and passwords.
        </li>
        <li>Permits brute force or other automated attacks.</li>
        <li>
          Permits default, weak, or well-known passwords, such as "Password1" or
          "admin/admin".
        </li>
        <li>
          Uses weak or ineffective credential recovery and forgot-password
          processes, such as "knowledge-based answers," which cannot be made
          safe.
        </li>
        <li>
          Uses plain text, encrypted, or weakly hashed passwords data stores
        </li>
        <li>Has missing or ineffective multi-factor authentication.</li>
        <li>Exposes session identifier in the URL.</li>
        <li>Reuse session identifier after successful login.</li>
        <li>
          Does not correctly invalidate Session IDs. User sessions or
          authentication tokens (mainly single sign-on (SSO) tokens) aren't
          properly invalidated during logout or a period of inactivity.
        </li>
      </ul>
    </div>
  </div>
  <h3>How to Prevent</h3>
  <div>
    <ul>
      <li>
        Where possible, implement multi-factor authentication to prevent
        automated credential stuffing, brute force, and stolen credential reuse
        attacks.
      </li>
      <li>
        Do not ship or deploy with any default credentials, particularly for
        admin users.
      </li>
      <li>
        Implement weak password checks, such as testing new or changed passwords
        against the top 10,000 worst passwords list.
      </li>
      <li>
        Align password length, complexity, and rotation policies with National
        Institute of Standards and Technology (NIST) 800-63b's guidelines in
        section 5.1.1 for Memorized Secrets or other modern, evidence-based
        password policies.
      </li>
      <li>
        Ensure registration, credential recovery, and API pathways are hardened
        against account enumeration attacks by using the same messages for all
        outcomes.
      </li>
      <li>
        Limit or increasingly delay failed login attempts, but be careful not to
        create a denial of service scenario. Log all failures and alert
        administrators when credential stuffing, brute force, or other attacks
        are detected.
      </li>
      <li>
        Use a server-side, secure, built-in session manager that generates a new
        random session ID with high entropy after login. Session identifier
        should not be in the URL, be securely stored, and invalidated after
        logout, idle, and absolute timeouts.
      </li>
    </ul>
  </div>
  <router-link to="/"><button>back</button></router-link>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "IdentificationAndAuthentificationFailures",
});
</script>
