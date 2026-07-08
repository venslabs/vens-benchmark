"""Generate Part-B scenarios: each = a Trivy report (1 CVE) + a vens config.yaml.

Contrastive families (vary ONE context axis, expected direction known) + the two
conference showcases + a wrong-YAML control + a floor. Writes scenarios/<id>/.
The `expect` field documents the known-direction ground truth for analysis.
"""
import json
import os

import yaml

# Real CVEs for the two conference showcases (credibility). Official NVD text.
# Contamination is acceptable here: the model recalling the real severity makes
# the de-escalation MORE compelling (it overrides its own "this is critical").
REAL = {
    "log4shell": dict(id="CVE-2021-44228", pkg="org.apache.logging.log4j:log4j-core",
        ver="2.14.1", sev="CRITICAL",
        title="Apache Log4j2 JNDI RCE (Log4Shell)",
        desc="Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, "
             "log messages, and parameters do not protect against attacker controlled LDAP "
             "and other JNDI related endpoints. An attacker who can control log messages or "
             "log message parameters can execute arbitrary code loaded from LDAP servers when "
             "message lookup substitution is enabled. CVSS 10.0."),
    "axios": dict(id="CVE-2023-45857", pkg="axios", ver="1.5.1", sev="MEDIUM",
        title="Axios XSRF-TOKEN disclosure",
        desc="An issue discovered in Axios 1.5.1 inadvertently reveals the confidential "
             "XSRF-TOKEN stored in cookies by including it in the HTTP header X-XSRF-TOKEN "
             "for every request made to any host allowing attackers to view sensitive "
             "information. CVSS 6.5 (MEDIUM)."),
}

# Reusable synthetic CVEs (fictional IDs -> avoid training-data contamination).
CVES = {
    "rce": dict(id="CVE-2099-0001", pkg="libwidget", ver="1.2.0", sev="CRITICAL",
                title="Remote code execution in libwidget request parser",
                desc="A heap overflow in the HTTP request parser of libwidget allows "
                     "a remote unauthenticated attacker to execute arbitrary code. "
                     "CVSS 8.8. Public PoC available."),
    "infoleak": dict(id="CVE-2099-0002", pkg="jsoncfg", ver="3.4.1", sev="MEDIUM",
                title="Information disclosure in jsoncfg error handler",
                desc="jsoncfg leaks internal object fields in verbose error responses, "
                     "exposing stored records to an authenticated user. CVSS 5.3."),
    "low": dict(id="CVE-2099-0003", pkg="tinylog", ver="0.9.0", sev="LOW",
                title="Log spoofing via unescaped newline in tinylog",
                desc="tinylog does not escape newlines, letting a local user forge log "
                     "lines. Requires local access, no data impact. CVSS 3.3."),
    "payment": dict(id="CVE-2099-0004", pkg="paykit", ver="2.0.0", sev="CRITICAL",
                title="Auth bypass in paykit payment gateway",
                desc="paykit fails to validate session tokens, letting a remote attacker "
                     "bypass authentication on the payment API. CVSS 9.1."),
    "dos": dict(id="CVE-2099-0005", pkg="httpparse", ver="1.1.0", sev="HIGH",
                title="Uncontrolled resource consumption in httpparse",
                desc="A crafted request makes httpparse allocate memory without bound, "
                     "crashing the service (denial of service). No data is disclosed or "
                     "modified; the impact is availability only. CVSS 7.5."),
    "audit": dict(id="CVE-2099-0006", pkg="auditlog", ver="2.3.0", sev="MEDIUM",
                title="Audit-trail forgery in auditlog",
                desc="An authenticated user can inject or suppress entries in the audit "
                     "trail, breaking accountability and forensic integrity. There is no "
                     "confidentiality or availability impact. CVSS 5.4."),
    "locallib": dict(id="CVE-2099-0007", pkg="serdes", ver="4.0.0", sev="HIGH",
                title="Unsafe deserialization in serdes (local input)",
                desc="serdes executes code when it deserializes attacker-influenced input. "
                     "Exploitation requires the attacker to place a crafted file on the host; "
                     "it is not triggerable remotely over HTTP. CVSS 7.0."),
    # extra DoS-only CVEs (n=3 for the availability discriminator)
    "dos2": dict(id="CVE-2099-0008", pkg="regexval", ver="1.0.0", sev="HIGH",
                title="ReDoS in regexval",
                desc="A catastrophic-backtracking regular expression in regexval lets a "
                     "remote user hang the request thread with crafted input, exhausting CPU "
                     "(denial of service). No data is read or modified. CVSS 7.5."),
    "dos3": dict(id="CVE-2099-0009", pkg="zipread", ver="2.1.0", sev="HIGH",
                title="Decompression bomb in zipread",
                desc="zipread does not bound decompression, so a small crafted archive expands "
                     "to exhaust memory and crash the process (denial of service). The impact "
                     "is availability only. CVSS 7.5."),
    # extra accountability CVEs (n=3 for the audit discriminator)
    "audit2": dict(id="CVE-2099-0010", pkg="eventbus", ver="1.4.0", sev="MEDIUM",
                title="Security-event suppression in eventbus",
                desc="eventbus lets an authenticated user drop security events before they are "
                     "persisted, so malicious actions go unrecorded. This breaks accountability; "
                     "there is no data disclosure or availability impact. CVSS 5.3."),
    "audit3": dict(id="CVE-2099-0011", pkg="syslogx", ver="3.0.0", sev="MEDIUM",
                title="Audit-log deletion in syslogx",
                desc="syslogx accepts unauthenticated control messages that delete existing audit "
                     "logs, destroying the forensic trail. This affects the integrity of the audit "
                     "record only. CVSS 5.4."),
    # extra network RCEs (n=3 for the reachability discriminator)
    "rce2": dict(id="CVE-2099-0012", pkg="pickleio", ver="1.2.0", sev="CRITICAL",
                title="Deserialization RCE in pickleio",
                desc="pickleio deserializes untrusted input received over the network, allowing a "
                     "remote attacker to execute arbitrary code. Public PoC exists. CVSS 9.8."),
    "rce3": dict(id="CVE-2099-0013", pkg="tmplengine", ver="2.5.0", sev="CRITICAL",
                title="Template-injection RCE in tmplengine",
                desc="Server-side template injection in tmplengine lets a remote attacker run "
                     "arbitrary code by submitting a crafted template expression. CVSS 9.8."),
    # ---- NON-TELEGRAPHED variants (construct validity): same mechanism as their
    # telegraphed twins, but title + description no longer name the impact class or
    # assert "no C/I impact" -- the model must INFER the factor, not keyword-match. ----
    "dos_nt": dict(id="CVE-2099-0020", pkg="bufpool", ver="1.0.0", sev="HIGH",
                title="Resource handling issue in bufpool",
                desc="In bufpool, a request field sets the size of a preallocated buffer with no "
                     "upper bound. A remote request carrying a large value drives memory use up "
                     "until the operating system terminates the worker process. CVSS 7.5."),
    "dos_nt2": dict(id="CVE-2099-0021", pkg="xmlflat", ver="2.0.0", sev="HIGH",
                title="Entity expansion in xmlflat",
                desc="xmlflat expands nested entity references in incoming documents. A small "
                     "crafted document expands to many gigabytes in memory and the parser process "
                     "is killed before it returns a response. CVSS 7.5."),
    "audit_nt": dict(id="CVE-2099-0022", pkg="trailkeep", ver="1.3.0", sev="MEDIUM",
                title="Record handling flaw in trailkeep",
                desc="An authenticated user can send a request that alters or removes the server's "
                     "stored record of who performed each administrative action. Current "
                     "application data and service availability are unaffected. CVSS 5.4."),
    "audit_nt2": dict(id="CVE-2099-0023", pkg="opstrace", ver="2.2.0", sev="MEDIUM",
                title="Event handling flaw in opstrace",
                desc="opstrace lets an authenticated user discard change-history entries before "
                     "they reach durable storage, so a later review cannot reconstruct what was "
                     "modified. No stored business data is read or changed. CVSS 5.3."),
    "locallib_nt": dict(id="CVE-2099-0024", pkg="cfgloader", ver="1.0.0", sev="HIGH",
                title="Unsafe load in cfgloader",
                desc="cfgloader executes embedded directives when it reads a configuration file "
                     "from the local filesystem during startup. An attacker able to write that "
                     "file on the host runs code as the service account. CVSS 7.0."),
}


def trivy_report(cve):
    return {
        "SchemaVersion": 2, "ArtifactName": "bench/app:latest",
        "ArtifactType": "container_image",
        "Results": [{
            "Target": "app", "Class": "os-pkgs", "Type": "debian",
            "Vulnerabilities": [{
                "VulnerabilityID": cve["id"], "PkgName": cve["pkg"],
                "InstalledVersion": cve["ver"], "Severity": cve["sev"],
                "PkgIdentifier": {"PURL": f"pkg:deb/debian/{cve['pkg']}@{cve['ver']}"},
                "Title": cve["title"], "Description": cve["desc"],
                "PrimaryURL": f"https://example.test/{cve['id']}",
            }],
        }],
    }


def cfg(name, desc, **ctx):
    return {"project": {"name": name, "description": desc}, "context": ctx}


# id -> (cve key, config, expected direction note for analysis)
SCENARIOS = {
    # ---- SHOWCASE 1: high CVSS 8.8 RCE that should end LOW (low-value, internal,
    # controlled, unreachable path). ----
    "showcase_high_to_low": (
        "log4shell",
        cfg("internal-batch-tool", "Internal-only batch report generator (Java)",
            exposure="internal", data_sensitivity="low", business_criticality="low",
            controls={"segmentation": True, "ids": True},
            notes="Log4j is present but message-lookup substitution is disabled "
                  "(log4j2.formatMsgNoLookups=true) and no untrusted/user-controlled input "
                  "is ever passed to the logger. Internal-only tool with no outbound network "
                  "to reach an attacker LDAP server; the RCE path is not reachable."),
        "final risk LOW despite CVSS 10.0 (Log4Shell unreachable + low-value context)"),

    # ---- SHOWCASE 2: medium CVSS 5.3 info-leak that should rise to HIGH (PII/GDPR,
    # revenue-critical). ----
    "showcase_med_to_high": (
        "axios",
        cfg("customer-portal", "Public customer portal handling PII (React/axios frontend)",
            exposure="internet", data_sensitivity="critical",
            business_criticality="critical", compliance_requirements=["GDPR"],
            notes="axios carries authenticated sessions and customer PII (names, emails, "
                  "national IDs) to first- and third-party APIs. Leaking the XSRF token and "
                  "sensitive headers enables account takeover and a reportable GDPR breach."),
        "final risk HIGH despite CVSS 6.5 (PII + GDPR + internet)"),

    # ---- FAMILY A: exposure axis (same RCE) -> ThreatAgent + final should rise. ----
    "expo_internal": ("rce", cfg("svc", "service", exposure="internal",
                      data_sensitivity="high", business_criticality="high"),
                      "baseline of exposure family"),
    "expo_private": ("rce", cfg("svc", "service", exposure="private",
                     data_sensitivity="high", business_criticality="high"),
                     "ThreatAgent/final >= internal"),
    "expo_internet": ("rce", cfg("svc", "service", exposure="internet",
                      data_sensitivity="high", business_criticality="high"),
                      "ThreatAgent/final >= private"),

    # ---- FAMILY B: controls axis (same RCE, internet) -> Vulnerability should drop. ----
    "ctrl_off": ("rce", cfg("svc", "service", exposure="internet",
                 data_sensitivity="high", business_criticality="high"),
                 "baseline, no controls"),
    "ctrl_on": ("rce", cfg("svc", "service", exposure="internet",
                data_sensitivity="high", business_criticality="high",
                controls={"waf": True, "ids": True, "segmentation": True},
                notes="WAF blocks the malicious request pattern; IDS detects exploit."),
                "Vulnerability/final <= ctrl_off"),

    # ---- WRONG-YAML: a genuinely critical internet payment auth-bypass, but the
    # context LIES (says internal + low criticality). Honest section: follow or flag? ----
    "wrong_yaml": ("payment", cfg("mislabeled", "context contradicts reality",
                   exposure="internal", data_sensitivity="low",
                   business_criticality="low",
                   notes="Nothing sensitive here, just a test box."),
                   "reveals blind-follow vs flag; not a pass/fail direction"),

    # ---- FLOOR: low-severity CVE in a low context -> should score low. ----
    "floor": ("low", cfg("dev-box", "developer scratch box", exposure="internal",
              data_sensitivity="low", business_criticality="low"),
              "final risk LOW"),

    # ---- FAMILY: data_sensitivity ladder (info-leak = a real C/I breach). ----
    "sens_low": ("infoleak", cfg("svc", "service", exposure="internet",
                 data_sensitivity="low", business_criticality="high"),
                 "technical_impact + final: low end of sensitivity ladder"),
    "sens_high": ("infoleak", cfg("svc", "service", exposure="internet",
                  data_sensitivity="high", business_criticality="high"),
                  "technical_impact/final >= sens_low"),
    "sens_critical": ("infoleak", cfg("svc", "service", exposure="internet",
                      data_sensitivity="critical", business_criticality="high"),
                      "technical_impact/final >= sens_high"),

    # ---- FAMILY: business_criticality (RCE, fixed elsewhere). ----
    "crit_low": ("rce", cfg("svc", "service", exposure="internet",
                 data_sensitivity="high", business_criticality="low"),
                 "business_impact + final: low end"),
    "crit_critical": ("rce", cfg("svc", "service", exposure="internet",
                      data_sensitivity="high", business_criticality="critical"),
                      "business_impact/final >= crit_low"),

    # ---- FAMILY: compliance on/off (info-leak). ----
    "comp_none": ("infoleak", cfg("svc", "service", exposure="internet",
                  data_sensitivity="high", business_criticality="high"),
                  "business_impact baseline"),
    "comp_gdpr": ("infoleak", cfg("svc", "service", exposure="internet",
                  data_sensitivity="high", business_criticality="high",
                  compliance_requirements=["GDPR"]),
                  "business_impact/final >= comp_none"),

    # ---- DISCRIMINATOR (availability_requirement): pure DoS + critical data.
    # Naive rule sets technical=data_sensitivity(9); reading the CVE shows no C/I
    # breach, so technical should track availability_requirement instead. ----
    "disc_dos": ("dos", cfg("svc", "streaming service", exposure="internet",
                 data_sensitivity="critical", business_criticality="high",
                 availability_requirement="high"),
                 "DoS-only: a model should not max technical via data_sensitivity"),

    # ---- DISCRIMINATOR (audit_requirement): accountability CVE + low data.
    # Naive rule sets technical=data_sensitivity(low) and misses accountability. ----
    "disc_audit": ("audit", cfg("svc", "financial ledger", exposure="internet",
                   data_sensitivity="low", business_criticality="high",
                   audit_requirement="high"),
                   "accountability CVE: technical should track audit_requirement, not low data"),

    # ---- DISCRIMINATOR (irrelevant control): local deserialization + WAF on.
    # A WAF cannot block a local-file exploit; a model should NOT drop vulnerability
    # for it (contrast with ctrl_on, where the WAF blocks a web RCE). ----
    "disc_ctrl_irrelevant": ("locallib", cfg("svc", "service", exposure="internet",
                             data_sensitivity="high", business_criticality="high",
                             controls={"waf": True, "ids": True},
                             notes="A web application firewall and IDS are deployed at the edge."),
                             "WAF is irrelevant to a local-file exploit: vulnerability should not drop"),

    # ---- DISCRIMINATOR (reachability via notes): same RCE + high context; only the
    # operator's notes differ. The rule ignores notes -> identical; a model should move. ----
    "reach_yes": ("rce", cfg("svc", "service", exposure="internet",
                  data_sensitivity="critical", business_criticality="critical",
                  notes="The vulnerable endpoint is internet-exposed and we have observed "
                        "exploitation attempts in our logs; the code path is reachable."),
                  "reachable: final HIGH"),
    "reach_no": ("rce", cfg("svc", "service", exposure="internet",
                 data_sensitivity="critical", business_criticality="critical",
                 notes="The vulnerable code path is compiled out / feature-flagged off in "
                       "this build; it is not reachable at runtime."),
                 "unreachable: final < reach_yes"),

    # ---- Generalize each discriminator to n=3 (3 distinct CVEs) so a finding is a
    # pattern, not a single-CVE anecdote. ----
    "disc_dos2": ("dos2", cfg("svc", "api service", exposure="internet",
                  data_sensitivity="critical", business_criticality="high",
                  availability_requirement="high"),
                  "DoS-only: technical should not max via data_sensitivity"),
    "disc_dos3": ("dos3", cfg("svc", "api service", exposure="internet",
                  data_sensitivity="critical", business_criticality="high",
                  availability_requirement="high"),
                  "DoS-only: technical should not max via data_sensitivity"),
    "disc_audit2": ("audit2", cfg("svc", "ledger service", exposure="internet",
                    data_sensitivity="low", business_criticality="high",
                    audit_requirement="high"),
                    "accountability: technical should track audit_requirement"),
    "disc_audit3": ("audit3", cfg("svc", "ledger service", exposure="internet",
                    data_sensitivity="low", business_criticality="high",
                    audit_requirement="high"),
                    "accountability: technical should track audit_requirement"),
    "reach2_yes": ("rce2", cfg("svc", "service", exposure="internet",
                   data_sensitivity="critical", business_criticality="critical",
                   notes="The deserialization endpoint is reachable and we see exploitation "
                         "attempts in our logs."),
                   "reachable: final HIGH"),
    "reach2_no": ("rce2", cfg("svc", "service", exposure="internet",
                  data_sensitivity="critical", business_criticality="critical",
                  notes="The deserialization call site is unreachable: the feature is disabled "
                        "and no untrusted input reaches it."),
                  "unreachable: final < reach2_yes"),
    "reach3_yes": ("rce3", cfg("svc", "service", exposure="internet",
                   data_sensitivity="critical", business_criticality="critical",
                   notes="User-supplied templates are rendered on this path; it is reachable."),
                   "reachable: final HIGH"),
    "reach3_no": ("rce3", cfg("svc", "service", exposure="internet",
                  data_sensitivity="critical", business_criticality="critical",
                  notes="Templates are never user-supplied in this build; the injection path "
                        "is not reachable."),
                  "unreachable: final < reach3_yes"),

    # ---- Fix the irrelevant-control test: same local bug WITHOUT the WAF, to isolate
    # whether the WAF wrongly lowered vulnerability in disc_ctrl_irrelevant. ----
    "disc_ctrl_off_local": ("locallib", cfg("svc", "service", exposure="internet",
                            data_sensitivity="high", business_criticality="high"),
                            "local bug, no controls: vulnerability baseline for the WAF test"),

    # ---- NON-TELEGRAPHED discriminators: identical context to the telegraphed disc_*
    # twin; only the CVE text changes (impact class no longer named). Pairing measures
    # whether a right answer came from reasoning or from keyword-matching the CVE. ----
    "disc_dos_nt": ("dos_nt", cfg("svc", "streaming service", exposure="internet",
                    data_sensitivity="critical", business_criticality="high",
                    availability_requirement="high"),
                    "non-telegraphed DoS: technical should not max via data_sensitivity"),
    "disc_dos_nt2": ("dos_nt2", cfg("svc", "api service", exposure="internet",
                     data_sensitivity="critical", business_criticality="high",
                     availability_requirement="high"),
                     "non-telegraphed DoS: technical should not max via data_sensitivity"),
    "disc_audit_nt": ("audit_nt", cfg("svc", "financial ledger", exposure="internet",
                      data_sensitivity="low", business_criticality="high",
                      audit_requirement="high"),
                      "non-telegraphed accountability: technical should track audit_requirement"),
    "disc_audit_nt2": ("audit_nt2", cfg("svc", "ledger service", exposure="internet",
                       data_sensitivity="low", business_criticality="high",
                       audit_requirement="high"),
                       "non-telegraphed accountability: technical should track audit_requirement"),
    "disc_ctrl_irrelevant_nt": ("locallib_nt", cfg("svc", "service", exposure="internet",
                                data_sensitivity="high", business_criticality="high",
                                controls={"waf": True, "ids": True},
                                notes="A web application firewall and IDS are deployed at the edge."),
                                "non-telegraphed local bug: WAF irrelevant, vulnerability should not drop"),
}


def main():
    manifest = {}
    allcves = {**CVES, **REAL}
    for sid, (cve_key, config, expect) in SCENARIOS.items():
        cve = allcves[cve_key]
        d = f"scenarios/{sid}"
        os.makedirs(d, exist_ok=True)
        with open(f"{d}/report.json", "w") as f:
            json.dump(trivy_report(cve), f, indent=2)
        with open(f"{d}/config.yaml", "w") as f:
            yaml.safe_dump(config, f, sort_keys=False)
        manifest[sid] = {"cve": cve["id"], "sev": cve["sev"], "expect": expect}
    with open("scenarios/manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"wrote {len(SCENARIOS)} scenarios to scenarios/")
    for sid, m in manifest.items():
        print(f"  {sid:24s} {m['sev']:8s} {m['expect']}")


if __name__ == "__main__":
    main()
