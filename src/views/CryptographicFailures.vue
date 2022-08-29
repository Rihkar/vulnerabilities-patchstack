<template>
  <h1>Cryptographic Failures</h1>
  <h3>Overview</h3>
  <div>
    Shifting up one position to #2, previously known as Sensitive Data Exposure,
    which is more of a broad symptom rather than a root cause, the focus is on
    failures related to cryptography (or lack thereof). Which often lead to
    exposure of sensitive data. Notable Common Weakness Enumerations (CWEs)
    included are CWE-259: Use of Hard-coded Password, CWE-327: Broken or Risky
    Crypto Algorithm, and CWE-331 Insufficient Entropy.
  </div>
  <h3>Description</h3>
  <div>
    <div>
      The first thing is to determine the protection needs of data in transit
      and at rest. For example, passwords, credit card numbers, health records,
      personal information, and business secrets require extra protection,
      mainly if that data falls under privacy laws, e.g., EU's General Data
      Protection Regulation (GDPR), or regulations, e.g., financial data
      protection such as PCI Data Security Standard (PCI DSS). For all such
      data:
    </div>
    <div>
      <ul>
        <li>
          Is any data transmitted in clear text? This concerns protocols such as
          HTTP, SMTP, FTP also using TLS upgrades like STARTTLS. External
          internet traffic is hazardous. Verify all internal traffic, e.g.,
          between load balancers, web servers, or back-end systems.
        </li>
        <li>
          Are any old or weak cryptographic algorithms or protocols used either
          by default or in older code?
        </li>
        <li>
          Are default crypto keys in use, weak crypto keys generated or re-used,
          or is proper key management or rotation missing? Are crypto keys
          checked into source code repositories?
        </li>
        <li>
          Is encryption not enforced, e.g., are any HTTP headers (browser)
          security directives or headers missing?
        </li>
        <li>
          Is the received server certificate and the trust chain properly
          validated?
        </li>
        <li>
          Are initialization vectors ignored, reused, or not generated
          sufficiently secure for the cryptographic mode of operation? Is an
          insecure mode of operation such as ECB in use? Is encryption used when
          authenticated encryption is more appropriate?
        </li>
        <li>
          Are passwords being used as cryptographic keys in absence of a
          password base key derivation function?
        </li>
        <li>
          Is randomness used for cryptographic purposes that was not designed to
          meet cryptographic requirements? Even if the correct function is
          chosen, does it need to be seeded by the developer, and if not, has
          the developer over-written the strong seeding functionality built into
          it with a seed that lacks sufficient entropy/unpredictability?
        </li>
        <li>
          Are deprecated hash functions such as MD5 or SHA1 in use, or are
          non-cryptographic hash functions used when cryptographic hash
          functions are needed?
        </li>
        <li>
          Are deprecated cryptographic padding methods such as PKCS number 1
          v1.5 in use?
        </li>
        <li>
          Are cryptographic error messages or side channel information
          exploitable, for example in the form of padding oracle attacks?
        </li>
      </ul>
    </div>
  </div>
  <h3>How to Prevent</h3>
  <div>
    <div>Do the following, at a minimum, and consult the references:</div>
    <div>
      <ul>
        <li>
          Classify data processed, stored, or transmitted by an application.
          Identify which data is sensitive according to privacy laws, regulatory
          requirements, or business needs.
        </li>
        <li>
          Don't store sensitive data unnecessarily. Discard it as soon as
          possible or use PCI DSS compliant tokenization or even truncation.
          Data that is not retained cannot be stolen.
        </li>
        <li>Make sure to encrypt all sensitive data at rest.</li>
        <li>
          Ensure up-to-date and strong standard algorithms, protocols, and keys
          are in place; use proper key management.
        </li>
        <li>
          Encrypt all data in transit with secure protocols such as TLS with
          forward secrecy (FS) ciphers, cipher prioritization by the server, and
          secure parameters. Enforce encryption using directives like HTTP
          Strict Transport Security (HSTS).
        </li>
        <li>Disable caching for response that contain sensitive data.</li>
        <li>
          Apply required security controls as per the data classification.
        </li>
        <li>
          Do not use legacy protocols such as FTP and SMTP for transporting
          sensitive data.
        </li>
        <li>
          Store passwords using strong adaptive and salted hashing functions
          with a work factor (delay factor), such as Argon2, scrypt, bcrypt or
          PBKDF2.
        </li>
        <li>
          Initialization vectors must be chosen appropriate for the mode of
          operation. For many modes, this means using a CSPRNG
          (cryptographically secure pseudo random number generator). For modes
          that require a nonce, then the initialization vector (IV) does not
          need a CSPRNG. In all cases, the IV should never be used twice for a
          fixed key.
        </li>
        <li>Always use authenticated encryption instead of just encryption.</li>
        <li>
          Keys should be generated cryptographically randomly and stored in
          memory as byte arrays. If a password is used, then it must be
          converted to a key via an appropriate password base key derivation
          function.
        </li>
        <li>
          Ensure that cryptographic randomness is used where appropriate, and
          that it has not been seeded in a predictable way or with low entropy.
          Most modern APIs do not require the developer to seed the CSPRNG to
          get security.
        </li>
        <li>
          Avoid deprecated cryptographic functions and padding schemes, such as
          MD5, SHA1, PKCS number 1 v1.5 .
        </li>
        <li>
          Verify independently the effectiveness of configuration and settings.
        </li>
      </ul>
    </div>
  </div>
  <router-link to="/"><button>back</button></router-link>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "CryptographicFailures",
});
</script>
