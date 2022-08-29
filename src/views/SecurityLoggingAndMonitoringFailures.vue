<template>
  <h1>Security logging and monitoring failures</h1>
  <h3>Overview</h3>
  <div>
    Security logging and monitoring came from the Top 10 community survey (#3),
    up slightly from the tenth position in the OWASP Top 10 2017. Logging and
    monitoring can be challenging to test, often involving interviews or asking
    if attacks were detected during a penetration test. There isn't much
    CVE/CVSS data for this category, but detecting and responding to breaches is
    critical. Still, it can be very impactful for accountability, visibility,
    incident alerting, and forensics. This category expands beyond CWE-778
    Insufficient Logging to include CWE-117 Improper Output Neutralization for
    Logs, CWE-223 Omission of Security-relevant Information, and CWE-532
    Insertion of Sensitive Information into Log File.
  </div>
  <h3>Description</h3>
  <div>
    <div>
      Returning to the OWASP Top 10 2021, this category is to help detect,
      escalate, and respond to active breaches. Without logging and monitoring,
      breaches cannot be detected. Insufficient logging, detection, monitoring,
      and active response occurs any time:
    </div>
    <div>
      <ul>
        <li>
          Auditable events, such as logins, failed logins, and high-value
          transactions, are not logged.
        </li>
        <li>
          Warnings and errors generate no, inadequate, or unclear log messages.
        </li>
        <li>
          Logs of applications and APIs are not monitored for suspicious
          activity.
        </li>
        <li>Logs are only stored locally.</li>
        <li>
          Appropriate alerting thresholds and response escalation processes are
          not in place or effective.
        </li>
        <li>
          Penetration testing and scans by dynamic application security testing
          (DAST) tools (such as OWASP ZAP) do not trigger alerts.
        </li>
        <li>
          The application cannot detect, escalate, or alert for active attacks
          in real-time or near real-time.
        </li>
      </ul>
    </div>
    <div>
      You are vulnerable to information leakage by making logging and alerting
      events visible to a user or an attacker
    </div>
  </div>
  <h3>How to Prevent</h3>
  <div>
    <div>
      Developers should implement some or all the following controls, depending
      on the risk of the application:
    </div>
    <div>
      <ul>
        <li>
          Ensure all login, access control, and server-side input validation
          failures can be logged with sufficient user context to identify
          suspicious or malicious accounts and held for enough time to allow
          delayed forensic analysis.
        </li>
        <li>
          Ensure that logs are generated in a format that log management
          solutions can easily consume.
        </li>
        <li>
          Ensure log data is encoded correctly to prevent injections or attacks
          on the logging or monitoring systems.
        </li>
        <li>
          Ensure high-value transactions have an audit trail with integrity
          controls to prevent tampering or deletion, such as append-only
          database tables or similar.
        </li>
        <li>
          DevSecOps teams should establish effective monitoring and alerting
          such that suspicious activities are detected and responded to quickly.
        </li>
        <li>
          Establish or adopt an incident response and recovery plan, such as
          National Institute of Standards and Technology (NIST) 800-61r2 or
          later.
        </li>
      </ul>
    </div>
    <div>
      There are commercial and open-source application protection frameworks
      such as the OWASP ModSecurity Core Rule Set, and open-source log
      correlation software, such as the Elasticsearch, Logstash, Kibana (ELK)
      stack, that feature custom dashboards and alerting.
    </div>
  </div>
  <router-link to="/"><button>back</button></router-link>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "SecurityLoggingAndMonitoringFailures",
});
</script>
