<template>
  <h1>Server side request forgery</h1>
  <h3>Overview</h3>
  <div>
    This category is added from the Top 10 community survey (#1). The data shows
    a relatively low incidence rate with above average testing coverage and
    above-average Exploit and Impact potential ratings. As new entries are
    likely to be a single or small cluster of Common Weakness Enumerations
    (CWEs) for attention and awareness, the hope is that they are subject to
    focus and can be rolled into a larger category in a future edition.
  </div>
  <h3>Description</h3>
  <div>
    <div>
      SSRF flaws occur whenever a web application is fetching a remote resource
      without validating the user-supplied URL. It allows an attacker to coerce
      the application to send a crafted request to an unexpected destination,
      even when protected by a firewall, VPN, or another type of network access
      control list (ACL).
    </div>
    <div>
      As modern web applications provide end-users with convenient features,
      fetching a URL becomes a common scenario. As a result, the incidence of
      SSRF is increasing. Also, the severity of SSRF is becoming higher due to
      cloud services and the complexity of architectures.
    </div>
  </div>
  <h3>How to Prevent</h3>
  <div>
    <div>
      <h5>From Network layer:</h5>
      <div>
        <ul>
          <li>
            Segment remote resource access functionality in separate networks to
            reduce the impact of SSRF
          </li>
          <li>
            Enforce “deny by default” firewall policies or network access
            control rules to block all but essential intranet traffic.
            <br />
            <i>Hints:</i>
            <br />
            <i
              >~ Establish an ownership and a lifecycle for firewall rules based
              on applications.</i
            >
            <br />
            <i>~ Log all accepted and blocked network flows on firewalls</i>
          </li>
        </ul>
      </div>
    </div>
    <div>
      <h5>From Application layer:</h5>
      <div>
        <ul>
          <li>Sanitize and validate all client-supplied input data</li>
          <li>
            Enforce the URL schema, port, and destination with a positive allow
            list
          </li>
          <li>Do not send raw responses to clients</li>
          <li>Disable HTTP redirections</li>
          <li>
            Be aware of the URL consistency to avoid attacks such as DNS
            rebinding and “time of check, time of use” (TOCTOU) race conditions
          </li>
        </ul>
      </div>
      <div>
        Do not mitigate SSRF via the use of a deny list or regular expression.
        Attackers have payload lists, tools, and skills to bypass deny lists.
      </div>
    </div>
    <div>
      <h5>Additional Measures to consider:</h5>
      <div>
        <ul>
          <li>
            Don't deploy other security relevant services on front systems (e.g.
            OpenID). Control local traffic on these systems (e.g. localhost)
          </li>
          <li>
            For frontends with dedicated and manageable user groups use network
            encryption (e.g. VPNs) on independent systems to consider very high
            protection needs
          </li>
        </ul>
      </div>
    </div>
  </div>
  <router-link to="/"><button>back</button></router-link>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "ServerSideRequestForgery",
});
</script>
