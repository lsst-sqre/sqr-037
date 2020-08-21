:tocdepth: 1

.. sectnum::

.. _abstract:

Abstract
========

SQuaRE runs project infrastructure and multiple security-sensitive services, and SQuaRE team members have substantial access permissions.
This tech note proposes a threat model for analyzing SQuaRE-related security risks (excluding the RSP and public APIs), catalogs known gaps under that threat model, and recommends mitigations for those gaps.

.. _scope:

Scope
=====

This security risk assessment covers SQuaRE general infrastructure services internal to the project and the technical practices of SQuaRE staff.
It does not cover the Rubin Science Platform (RSP) or public-facing science APIs for LSST data.
For the corresponding review of the RSP, see `SQR-041`_.

.. _SQR-041: https://sqr-041.lsst.io/

.. _summary:

Summary
=======

SQuaRE should focus security efforts on closing known vulnerabilities and defending against attackers doing mass vulnerability scans or using off-the-shelf exploit toolkits.
Within that framework, the security gaps that pose the highest risk are:

- :ref:`Kubernetes hardening <gap-kubernetes>`
- :ref:`Security logging and alerting <gap-logging-alerting>`

The top recommendations for improving SQuaRE's security posture are:

- Create a Google Cloud Identity domain with mandatory two-factor authentication for access to SQuaRE services running at Google
- Apply all of the Kubernetes cluster hardening measures recommended by Google
- Add a ``PodSecurityPolicy`` and hardening configuration to SQuaRE services
- Consolidate application hosting environments
- Ingest security logs from cloud hosting providers
- Define normal administrative activity and begin alerting on unexpected privileged actions
- Require two-factor authentication for administrative access to cloud hosting providers
- Automate or regularly schedule patching and upgrades of SQuaRE services

See :ref:`Accepted Risks <accepted-risks>` for discussion of apparent security risks that should not be a focus of time or resources.
See :ref:`Glossary <glossary>` for some possibly-unfamiliar security terms.

.. _threat-model:

Threat model
============

.. _threat-model-targets:

Targets
-------

Expected attacker targets for SQuaRE services and practices are primarily the standard targets of opportunity for general Internet attackers:

- Theft of compute resources (Bitcoin mining, bot networks)
- Extortion via ransomware (CryptoLocker)
- Web site hosting for further phishing or malware distribution
- Exfiltration of confidential data such as password databases

Additionally, since the project is prominent (receives news media coverage) and is associated with the US government, some attackers may want to embarrass the project or claim credit for hacking a well-known site.
Those attackers are likely to attempt web site defacement or release of non-public data that would embarrass the project.

SQuaRE staff and services have only limited access to data of value to sophisticated attackers.
The project does not have large stores of valuable personal data (for example, credit card numbers or :abbr:`SSNs (US Social Security Numbers)`) or valuable confidential data (for example, classified information or commercial trade secrets).
Therefore, targeted attacks by sophisticated attackers looking for data of monetary or political value are unlikely.

.. _threat-model-attackers:

Attacker profile
----------------

SQuaRE should expect attacks from, and defend against:

- Viruses, worms, and other automatically-spreading attacks
- Phishing via mass spam or unsophisticated spear-phishing
- Unsophisticated scanning of stolen endpoints for credentials
- Automated exploits based on mass scanning and opportunistic exploitation
- Targeted attacks by people with off-the-shelf exploit toolkits

The most likely attack pattern is mass scanning of all Internet-facing resources for known flaws, followed by automated or toolkit-based manual follow-up on discovered flaws.
The second most likely attack pattern is interactive exploration of public-facing web sites and resources looking for software and web security vulnerabilities with known exploits.
It is distantly possible that an endpoint stolen from a SQuaRE employee might be scanned for useful credentials before being wiped and reused.

SQuaRE should therefore focus security efforts on patching known security vulnerabilities, avoiding obvious web security problems, taking reasonable precautions with endpoints, and detecting obvious attacker activity.

SQuaRE should not attempt to defend against :abbr:`APTs (Advanced Persistent Threats)`, state actors, or sophisticated organized crime.
Therefore, SQuaRE should not attempt to defend against attackers with the capability to develop or purchase unknown zero-day exploits, construct novel exploit toolkits, implant hardware into endpoints, or pursue careful and sophisticated targeted phishing attacks.
Defense against this level of attacker would not be a good use of project resources given the extremely high cost of defense and the relatively low likelihood of interest in SQuaRE services by well-funded attackers.

SQuaRE should also not attempt to implement technical defenses against insider attacks.
Insider threats are the most difficult type of attack to defend against, and require the most intrusive and disruptive security controls.
SQuaRE should accept the technical security risk of a malicious employee and mitigate that risk through management, legal, and HR policies and awareness.

.. _threat-model-discussion:

Discussion
----------

Defending against security threats costs resources in the form of time, money, and staff.
As with any other aspect of a project, there is a budget for security, and exceeding that budget would undermine the success of other parts of the project.
Therefore, that budget should be spent wisely on the most effective security measures, not on defending against any conceivable security threat.

A security budget poses some special challenges because it is distributed.
Many security measures impose small and hard-to-quantify costs on large numbers of people, instead of a large but known cost on a single budget.
Security measures therefore need to be carefully chosen to avoid large hidden costs spread throughout the organization and death of other project goals by a thousand cuts.

A threat model is a tool to analyze how to spend a security budget.
It serves two primary purposes in a security risk assessment:

#. Focus security efforts on the most likely attackers and attack paths, where the work will achieve the most benefits for the cost.
#. Explicitly accept the risk of attacks and attackers for which defense is not a realistic goal.
   This avoids spending scarce security resources on problems that are not solvable within the project security budget.

The cost of defense is generally proportional to the sophistication of attack.
Defending against the most sophisticated attackers requires a dedicated security response team and resources beyond the budget of nearly all organizations.
The project needs to be realistic about both what sophistication of attacks is likely given the data and resources entrusted to the project and what defense is feasible given the available budget.
Attempting to defend against every possible attack is a waste of both project resources and project member good will.

If the project is attacked by a particularly sophisticated attacker, that attacker will probably be successful.
That is an acceptable risk for the project to take.

This threat model is based on the following assumptions about project security resources:

- Primary responsibility for security work will be distributed among everyone maintaining project services and needs to consume a small and bounded portion of their time.
- Dedicated security resources are limited.
  Some security-critical services may be run by dedicated security staff, but otherwise the role of a security team will be limited to standards, frameworks, consultation, and advice.
- The project does not have resources for a dedicated detection and response team.
  Detection and response will be done by general project staff in the course of normal service operations.
- The project does not have resources for a dedicated red team (offensive security testing), and at best limited resources for penetration testing.
- Centralized security management of endpoints (laptops, desktops, and mobile devices for project staff) is cost-prohibitive in both distributed and centralized costs and contrary to the culture and work style of the project.
  This is discussed further in :ref:`Endpoints <gaps-endpoints>`.

This rules out effective defense against state actors, sophisticated organized crime, or insider threats.
Thankfully, as explained in :ref:`Threat Model: Targets <threat-model-targets>`, it is also unlikely that such attackers would spend resources attempting to compromise SQuaRE services given the lack of (to them) interesting targets.

.. _gaps:

Known gaps
==========

Summary
-------

.. _table-summary:

.. table:: Summary of gaps

   +------------------+------------------------------+--------+
   | Class            | Gap                          | Risk   |
   +==================+==============================+========+
   | Infrastructure   | :ref:`gap-kubernetes`        | High   |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-logging-alerting`  | High   |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-patching`          | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-scattered`         | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-service-perms`     | Low    |
   +------------------+------------------------------+--------+
   | Web Security     | :ref:`gap-csp`               | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-domain-takeover`   | Low    |
   +------------------+------------------------------+--------+
   | Data Stores      | :ref:`gap-sql-public-ip`     | Low    |
   +------------------+------------------------------+--------+
   | Endpoints        | :ref:`gap-laptop-compromise` | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-laptop-theft`      | Low    |
   +------------------+------------------------------+--------+
   | Authentication   | :ref:`gap-two-factor`        | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-google-auth`       | Medium |
   +------------------+------------------------------+--------+

.. _gaps-infra:

Infrastructure services
-----------------------

.. _gap-kubernetes:

Kubernetes hardening
^^^^^^^^^^^^^^^^^^^^

**Risk: High**

Currently, SQuaRE has not done much to harden Kubernetes deployments outside of what upstream Helm charts and :abbr:`GKE (Google Kubernetes Engine)` does by default.
This increases the risk that a compromised container will lead to a deeper infrastructure compromise.
The SQuaRE Kubernetes clusters on GKE have their nodes and control plane accessible from the Internet, which is convenient for management but which significantly increases the attack surface.
Traffic between pods is unrestricted, increasing the chances of lateral movement inside each cluster.
The current cluster configurations do not follow the `Google recommended security practices <https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster>`__.

The pod configurations maintained by SQuaRE do not have security hardening settings and are not scanned for Kubernetes best practices.
Pods may therefore be running with more privileges than they need.

Mitigations
"""""""""""

- All SQuaRE internal clusters (setting aside the Rubin Science Platform, which is not covered in this document) are hosted on GKE using Container-Optimized OS, so benefit from the cluster and node hardening that Google does by default.
- All SQuaRE internal clusters are enrolled in release channels and are therefore automatically upgraded for Kubernetes security vulnerabilities.

Recommendations
"""""""""""""""

Most of these recommendations come from the Google recommended hardening practices.

- Create a Google Cloud Identity organization and restrict access to members of that organization.
  This will enable access to the Google Security Command Center to monitor the security configuration of the Kubernetes clusters.
  See :ref:`Google authentication <gap-google-auth>`.
- Enable shielded GKE nodes with secure boot.
- Use the ``cos_containerd`` image for all node pools.
- Enable Workload Identity and ensure all services that need access to Google Cloud services work properly with it.
  This will also block unwanted access to Google Compute Engine metadata services.
- Restrict cluster discovery permissions to only service accounts plus the Google Cloud Identity organization.
- Restrict traffic between pods.
  Istio is the most comprehensive solution here, but Kubernetes network policies may be sufficient.
  Kubernetes network policy support has to be enabled at the cluster level.
- Restrict network access to the control plane and nodes.
  This is challenging because the recommended way to do this is to use a VPN to link the Kubernetes network with a corporate network, which poses various challenges.
  However, exposing the cluster to the Internet is a significant increase in attack surface and therefore risk.
  The easiest approach may be a bastion hosted in :abbr:`GCE (Google Compute Engine)`.
- Disable legacy ABAC access control on all clusters.
  Some older clusters still have this enabled.
- Add a cluster-wide pod security policy that enables the generally-desirable hardening options, and enable the Pod Security Policy admission controller.
  This should disable privileged containers, use a read-only root file system, disable privilege escalation, disable running containers as root, and restrict capabilities.
  See the `Kubernetes recommended restricted policy <https://kubernetes.io/docs/concepts/security/pod-security-standards/>`__.
- Enable the GKE sandbox for services not run by SQuaRE and that don't require high performance (such as Slack bots).
- Set ``automountServiceAccountToken`` to ``false`` for all service accounts or pods by default, leaving it enabled only for those pods that need to talk to Kubernetes.
- Separate applications into their own namespaces in the Roundtable cluster.
  This requires fixing how they talk to Kafka, which is currently forcing them all into the ``events`` namespace.
- Specify resource limits for all pods.
- Add periodic scanning of SQuaRE Kubernetes clusters for missing security best practices.

See `Google's hardening recommendations <https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster>`__ for more details.
Also see :ref:`Service account permissions <gap-service-perms>`.

.. _gap-logging-alerting:

Logging and alerting
^^^^^^^^^^^^^^^^^^^^

**Risk: High**

Logs of privileged actions and unusual events are vital for security incident response, root cause analysis, recovery after an incident, and alerting for suspicious events.
SQuaRE has only partly consolidated them into a single system, and does not yet have alerts on unexpected activity.

Ideally, all application and infrastructure logs would be consolidated into a single searchable log store.
The most vital logs to centralize and make available for alerting are administrative actions, such as manual Argo CD, Helm, and Kubernetes actions by cluster administrators, and security logs from cloud hosting platforms.
The next most important target is application logs from security-sensitive applications, such as Vault audit logs and Argo CD logs.

Currently, logs are being ingested by Fluentd from qserv and Kubernetes pods in the LDF prod and int environments and in Roundtable.
The Roundtable instance is not yet available without port forwarding pending an authentication and authorization strategy.
Logs from other Kubernetes clusters are not yet ingested.

Recommendations
"""""""""""""""

- Ingest logs from all hosting environments.
  The best way to do this may be to consolidate environments into Roundtable and the LDF.
- Make the ELK cluster for Roundtable more accessible and thus easier to use.
- Ingest AWS and GCP security logs from their native services into this framework.
- Write alerts for unexpected administrative actions and other signs of compromise.
  One possible alerting strategy is to route unexpected events to a Slack bot that will query the person who supposedly took that action for confirmation that they indeed took that action, with two-factor authentication confirmation.
  If this is done only for discouraged paths for admin actions, such as direct Kubernetes commands instead of using Argo CD, it doubles as encouragement to use the standard configuration management system.

.. _gap-patching:

Security patching
^^^^^^^^^^^^^^^^^

**Risk: Medium**

Due to the use of cloud services and distributed data centers, many SQuaRE services are Internet-accessible by design.
This means there is a substantial Internet-facing attack surface, which increases the risk of vulnerabilities in software used for SQuaRE services.
This is also the most likely attack vector for both opportunistic mass scanning attacks and more targeted attacks attempting to deface project web sites or to embarrass the project.

Most (although not all) SQuaRE deployments are done via Kubernetes, which reduces the risk of local compromise of a service since the attacker will be confined to the container and the security of the container host is handled by the hosting facility (such as :abbr:`GCP (Google Cloud Platform)`).
However, an attacker would still be able to intercept traffic, attack internal services and backend storage, and steal security credentials and sensitive data traveling through the compromised host.
The attacker may also be able to escalate privileges within Kubernetes (see :ref:`Kubernetes hardening <gap-kubernetes>`).

Therefore, all software that is part of a plausible attack path should be regularly patched for security vulnerabilities.
The SQuaRE services in this analysis don't have large quantities of locally-developed code or complex, multi-layered dependencies that are difficult to upgrade.
Therefore, since attack path analysis is difficult, costly, and error-prone, and since it is difficult to determine if a given upgrade has security implications, best practice is to routinely upgrade all software to the latest stable release.
This is most important for compiled binaries in non-memory-safe languages that are part of the external attack surface (such as nginx or Python Docker images).
It is less critical for underlying libraries in memory-safe languages, such as Python libraries.

Some of our software upgrades, such as Helm chart changes for Roundtable and newer SQuaRE services based on `Safir <https://safir.lsst.io/>`__, are handled via automated pull requests.
Others, such as most of the software running outside of Roundtable, are done opportunistically or as a side effect of other operational work, which means that stable services that don't need new features may be left unpatched for extended periods of time.
Even for newer Safir-based services, we don't ensure that the service is redeployed periodically to pick up the dependency updates.

Some SQuaRE services run on conventional VMs.
Those VMs are similarly not being regularly patched for operating system vulnerabilities, and are probably more vulnerable to attacks than Kubernetes pods.

This analysis would not apply to the :abbr:`RSP (Rubin Science Platform)` or to public APIs, for which regular upgrades are more disruptive and for which the security model is more complex.
See `SQR-041`_ for more details.

Known, unpatched security vulnerabilities are the most common vector for successful compromises.

Mitigations
"""""""""""

- The combination of GitHub Dependabot, WhiteSource Renovate, and `neophile <https://neophile.lsst.io/>`__ create automated PRs for updates to the Roundtable Kubernetes cluster and newer Safir-based services.
- The Internet-facing attack surface almost always passes through an nginx ingress that terminates both TLS and HTTP, which avoids TLS and HTTP protocol attacks except those against nginx.
- Cloud providers are used for many vulnerability-prone services such as DNS, reducing the attack surface.
- Nearly all SQuaRE services use memory-safe languages (Go, Python, JavaScript), avoiding many common remote vulnerabilities.
- All SQuaRE clusters are enrolled in release channels and receive automated control plane and node upgrades.

Recommendations
"""""""""""""""

- Consolidate other GKE clusters into Roundtable, which has configured automated PRs for Helm chart updates.
- Automate system patching and reboots for all VMs.
- Create a routine process for upgrading Jenkins shortly after each new upstream release.
  Jenkins is notorious for significant security vulnerabilities, and the Rubin Jenkins is an attractive target for injecting malicious code into software used by everyone in the project.
- Create a routine process for upgrading Discourse on community.lsst.org.
  This is one of the most attractive targets for an attacker wanting to deface a project web site, embarrass the project, or attempt XSS or other web site attacks.
- Identify all current SQuaRE-written services and enroll them in automated dependency pull requests.
- Alert on Internet-facing services that have not been redeployed to pick up dependency updates in more than three months.
- Clear all security issues in the GitHub security report, which reports vulnerabilities in dependencies declared in project GitHub repositories.
  If this is kept clear so that it isn't dismissed as noise, it provides a valuable feed of new vulnerability information in libraries used by SQuaRE services.
- Avoid pinning Docker images and other components in compiled, non-memory-safe languages to specific versions of third-party libraries and images when possible and instead use the latest version on each deploy.
- Upgrade dependencies, rebuild, and redeploy all services, even those that are not Internet-facing, on a regular schedule to pick up security patches.
  This is less important than Internet-facing services, but will close vulnerabilities that are indirectly exploitable, and also spreads operational load of upgrades out over time.
  This schedule can be less aggressive than the one for Internet-facing services.

.. _gap-scattered:

Scattered application hosting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

SQuaRE applications are scattered across multiple environments using multiple generations of deployment and configuration management strategies.
For example, there are twelve :abbr:`GCP (Google Cloud Platform)` Kubernetes clusters, a GCP VM, two AWS Kubernetes clusters, eight AWS EC2 instances in two separate regions, and a critical project service (community.lsst.org) at Digital Ocean.
This does not include services in Chile, the LDF, or in Tucson.

Each additional environment means another environment to secure, patch, track, and monitor for intrusion or unexpected behavior.
Proliferation of environments is therefore a security gap.
It increases the chances that some service will be left behind in a poor security state and will be compromised without being noticed.

Recommendations
"""""""""""""""

- Consolidate services into as few hosting environments and technologies as is feasible.
- Standardize the configuration management and deployment strategy for all remaining environments as much as possible, so that the same techniques can be used for upgrades and security configuration.

.. _gap-service-perms:

Service account permissions
^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Low**

Several :abbr:`GCP (Google Cloud Platform)` service accounts have excessive delegated permissions.
This increases the severity of vulnerabilities in those applications.
A compromise could quickly escalate to control over the GCP project and the other services running inside it.

Examples:

- The ``tap-async`` service account is a storage admin on all storage.
  It probably only needs access to its own bucket.
- The ``sql-proxy-service`` service account has full admin access to all Cloud SQL instances.
  This is probably excessive.
- The Cloud Build service account and service agent have full admin access to all storage.
  It's not clear if these service accounts are being used, or if they need this broad of permissions.

AWS IAM permissions for service accounts look correctly scoped.

Mitigations
"""""""""""

- The GCP project currently doesn't contain resources with wildly varying security properties, so this over-provisioning doesn't undermine significant security boundaries.
  Although some service accounts have unnecessary access to the Vault data store, it's encrypted, so this isn't too concerning.
- A running application would need to be compromised before these excessive permissions could be misused.

Recommendations
"""""""""""""""

- Restrict service account permissions to the necessary APIs and objects.
- Manage GCP permissions via configuration checked into a Git repository so that the expected permission state can be more easily analyzed, updated, and kept consistent.

.. _gaps-web-security:

Web security
------------

.. _gap-csp:

Content Security Policy
^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

SQuaRE runs internal web services with administrative access to SQuaRE services, such as Argo CD dashboards.
These services are attractive targets for XSS and other web attacks.
The primary defense is upstream security and keeping these applications patched, but a web `Content Security Policy`_ would provide valuable defense in depth.

.. _Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

Argo CD does not have a CSP.
The most valuable restrictions would be ``script-src`` and ``style-src``.

Mitigations
"""""""""""

- Keeping the applications patched is the best first line of defense.

Recommendations
"""""""""""""""

- Add Content-Security-Policy headers to the most important applications.
  There are two possible approaches, each of which may be useful in different places.
  Ideally, upstream should support CSP and present a complete CSP, and we could potentially assist via upstream pull requests.
  Alternately, either nginx or an authenticating proxy in front of the application could add a CSP in transit.

.. _gap-domain-takeover:

Domain takeover
^^^^^^^^^^^^^^^

**Risk: Low**

SQuaRE services in :abbr:`AWS (Amazon Web Services)` and :abbr:`GCP (Google Cloud Platform)` that are intended to be Internet-facing use IP addresses assigned from the general public IP pools of those services.
Those IP addresses are then given DNS entries under project domains.
If the IP address is later freed (because the service was shut down or moved, for instance), but the DNS entry is not deleted, an attacker can allocate the same IP address to their own service and then use the DNS entry to obtain TLS certificates for project domain names and serve web pages and other services under a project domain name.
This in turn can be used for phishing, to embarrass the project, or as a mechanism for web site defacement.

This may sound obscure, but it's surprisingly easy and surprisingly common if an attacker manages to guess the DNS names pointing to dangling IP addresses.
Some attackers have automated tools for finding and executing this attack.

Mitigations
"""""""""""

- The attacker has to have some way of discovering the name of the DNS entry.
- The rate at which SQuaRE retires projects and thus releases IP addresses is low.
- Domain takeover of project domains would lead, at most, to embarrassment and possibly phishing, not very high-value targets, so the most sophisticated attackers are unlikely to bother.

Recommendations
"""""""""""""""

- Periodically review (ideally via automation) all DNS entries pointing to IP addresses in project domains and confirm that those IP addresses belong to project resources.
- Manage DNS via Git configuration tied to the services that allocate the IPs, so that removing a service will automatically remove the DNS name, or at least prompt a test failure to remind a human to remove the DNS name.

.. _gaps-data:

Data Stores
-----------

.. _gap-sql-public-ip:

Public IPs for SQL databases
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Low**

SQuaRE uses several :abbr:`GCP (Google Cloud Platform)` Cloud SQL instances as data stores.
Currently, those Cloud SQL instances have public IPs, and thus are accessible (with authentication) from anywhere on the Internet.
This exposes a risk of weak passwords or (less likely) protocol vulnerabilities, leading to public exposure of any sensitive data in those databases.

Unsecured databases left accessible on cloud providers are a major source of data breaches.
Thankfully, SQuaRE is not responsible for storing the sort of data that attackers are after in typical data breaches, but since any data store is a common target of automated tools, we should still take reasonable precautions.

Mitigations
"""""""""""

- The currently-exposed databases are unlikely to contain any sensitive data.

Recommendations
"""""""""""""""

- Prefer private IPs to public IPs for data stores.
  If done systematically, this avoids the mental overhead of having to decide for each new data store whether the data may be sensitive or an interesting attack target.
  Most data stores only need to be accessed from the corresponding service running in the same cloud environment, making public IP access unnecessary.
  In the rare instance that direct administrative access to the database is required, this can be done via Kubernetes port forwarding.

.. _gaps-endpoints:

Endpoints
---------

SQuaRE staff do most work directly from work laptops and desktops, collectively referred to here as "endpoints."
In the course of that work, they create and store security tokens with administrative access to SQuaRE services and systems.
These include:

- :abbr:`AWS (Amazon Web Services)` credentials
- :abbr:`GCP (Google Cloud Platform)` credentials
- Kubernetes credentials
- GitHub tokens
- Docker Hub tokens
- Vault tokens
- SSH private keys
- Database passwords
- Other passwords, private keys, secrets downloaded temporarily while configuring applications

Compromise of the work laptop or desktop of a SQuaRE staff member therefore provides an easy path to compromise many other SQuaRE services.
There are several possible routes to compromise.

.. _gap-laptop-compromise:

Remote laptop compromise
^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

SQuaRE does not require work computers be used only for work purposes, does not centrally manage work computers, does not install intrusion detection software on work computers (or have a team to review any intrusion detection alerts), and does not limit the software that can be run on work computers.
Employee work computers are therefore vulnerable to malware via security flaws in local applications or web browsers, phishing, or file shares.

This is both one of the most common attack vectors for all organizations and one of the hardest to defend against.
A work computer is a personal tool.
Technical people, such as SQuaRE employees, configure their computers for maximum personal productivity and need substantial individual flexibility to explore new technology and customize their tools to their personal preferences.
Central management of work computers requires an IT team and help desk to run the management services, often interferes with that personal customization, and is notorious for causing disruption, outages, annoyance, and frustration.

It is possible to do central security management and application whitelisting for work computers well, but it requires a substantial investment in time and tools.
It is depressingly common to do it poorly, leading to spending more than the security budget of the entire project on distributed costs and work blockages from broken personal tools while achieving at best marginal security benefit.

Mitigations
"""""""""""

- SQuaRE is a small team of relatively sophisticated users, who are less likely than most to click on phishing or install risky programs, and more likely than most to notice strange system behavior after a compromise.
- Most malware is automated and unlikely to exploit saved credentials.
  It is more likely to be ransomware, adware, or to join the compromised system to an unsophisticated botnet to spread more malware.
  This would often allow detection and remediation before project services are compromised.
- SQuaRE team members use either macOS or Linux, which are currently less common targets for system compromise.
  (However, this is changing and shouldn't be relied upon too heavily.)

Recommendations
"""""""""""""""

SQuaRE does not have the resources available to do central device management well, and therefore should not attempt device management at all.
Instead, SQuaRE should focus on recommending caution in how staff use their work computers, and on reducing the impact of a compromise.

- SQuaRE staff should avoid using work computers for testing unknown applications or visiting suspicious web sites, instead using mobile devices (preferred) or non-work devices without access to work credentials.
- SQuaRE staff should be vigilant about phishing, particularly when using a work computer.

  - Do not click on links or attachments in suspicious messages.
  - Be suspicious of all messages telling one to visit a web site or open an attachment.
  - Avoid visiting a known web site via a link in a message unless that message was expected and triggered by a recent action.
    Instead, use a pre-saved bookmark and then navigate to the part of the web site discussed in the message.
  - Check the destination of URLs in email messages before following them.

- Prefer Git- and Slack-based work flows to direct access to services.
  To the extent a SQuaRE staff member can do their job with only GitHub and Slack credentials, fewer privileged credentials have to be stored, tracked, and rotated on each work computer.
- Build a list of credentials that SQuaRE staff tend to store locally so that there is a checklist of credentials to rotate or revoke after a compromise.
- Put expiration times on locally cached credentials where possible and where it is relatively easy to acquire new credentials so that stolen credentials cannot be used indefinitely into the future.

.. _gap-laptop-theft:

Laptop theft
^^^^^^^^^^^^

**Risk: Low**

Laptop theft from cars or unattended bags is fairly common.
The typical laptop thief is after money from reselling the system and is unlikely to look for or use security credentials stored on the system, other than the most obvious (saved bank passwords in the web browser).
However, the fence or purchaser of a stolen laptop may scan it for interesting credentials or files before reformatting it.

Mitigations
"""""""""""

- Requires physical presence, which is harder and riskier for an attacker and therefore is highly unlikely to be part of a targeted attack on the project.
  We therefore only need to worry about opportunistic attacks.
- People are aware of this risk and tend not to leave their devices unattended.
- AURA policy requires screen lock after ten minutes.

Recommendations
"""""""""""""""

- Use whole-disk encryption for all work laptops whenever possible.
  This is the best defense against stolen devices, since if the device is powered off, all data becomes inaccessible to the attacker.
  Unfortunately, it is hard to enable after the system is already in use, and it is only effective if the system is hibernated or powered off, not merely suspended.
- Use good passwords or biometrics (fingerprint reader) to unlock the screen after idle or suspend.
  Follow the AURA requirement to set a screen lock time of no more than ten minutes.
- Use a password manager that requires unlocking after a relatively short timeout, and do not let the browser directly remember work passwords.

The primary risk is through cached credentials, so some of the recommendations for remote laptop compromise also apply.

.. _gaps-authn:

Authentication
--------------

.. _gap-two-factor:

Two-Factor authentication
^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

SQuaRE uses a lot of cloud services.
Password authentication on those services is available to the general Internet and under constant attack.
Also, any password reuse allows an attacker to compromise one service and then use that data to compromise accounts at many other services.
The best defense against password attacks is to require two-factor authentication for all services.
Most critical cloud services support this, but it is not currently required by SQuaRE.

This risk applies to both individual accounts and to team shared accounts.
Some shared accounts have human-chosen, weak passwords rather than good randomly-generated ones.

Even with two-factor authentication enabled, cloud services may be vulnerable to phishing attacks that steal both factors.
The best available solution to this problem is to use WebAuthn for the second factor, which prevents phishing of that factor.
Unfortunately, this is not supported by most services and cannot be easily shared between multiple people using 1Password.

Mitigations
"""""""""""

- Use of 1Password is common, and therefore hopefully most passwords are random and strong.

Recommendations
"""""""""""""""

- Review all passwords for shared accounts and ensure they are randomly-generated by 1Password.
- Enable required two-factor authentication for at least the ``lsst-sqre`` GitHub project, and preferably for the ``lsst`` and ``lsst-dm`` projects as well.
  This requires that all project members enable two-factor authentication in order to remain in the project.
- Set an AWS IAM policy to disallow all service access unless two-factor authentication was used, and attach that policy to all IAM users.
  This effectively requires all users in an account to use two-factor authentication.
- Enable two-factor authentication for all Google accounts with GCP access.
  Also see :ref:`Google Authentication <gap-google-auth>`.
- Enable two-factor authentication for all Docker Hub accounts with access to the ``lsstsqre`` project.
  This will require moving all automated upload processes to Docker Hub tokens.
- Enable two-factor authentication for the team RubyGems account.
- Review all shared accounts in 1Password and enable two-factor authentication wherever possible.
- Consider acquiring YubiKey or other WebAuthn devices for all SQuaRE team members and requiring their use for cloud services that support it (GitHub, AWS, and Google).

.. _gap-google-auth:

Google authentication
^^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

Several critical services are hosted in :abbr:`GCP (Google Cloud Platform)` in a SQuaRE project.
The users in that project are a mix of personal and work Google accounts.
Sometimes access is granted to the same person via multiple accounts.
Even the work Google accounts aren't centrally managed; they are just normal Google accounts created with ``lsst.org`` or ``lsst.io`` email addresses.

This increases the risk that former staff or misspelled account names will be granted access to sensitive resources.
Lack of central management of the accounts also means we cannot set a security policy on all accounts with GCP access (such as requiring two-factor authentication), or quickly disable accounts that have been compromised without removing them from the project.

This access control method also does not scale to other Google services.
For instance, Google Webmaster Tools access for SQuaRE-managed domains is individually granted to a similar list of Google accounts, and off-boarding requires remembering to remove people individually from both lists.

There are two non-human, non-service accounts with access to the GCP project (``lsst.sqre@gmail.com``, an owner, and ``sqre-admin@lsst.io``, a project mover).
It's not clear who has control of these accounts or what their purpose is.
If they are intended as an emergency backup should other users get locked out of the GCP project, only one such administrative account should be necessary.

Mitigations
"""""""""""

- The number of people involved is small, and on-boarding and off-boarding are rare.

Recommendations
"""""""""""""""

- Create Google Cloud Identity accounts for everyone who needs access to GCP and delegate access to the appropriate Google Cloud Identity domain instead.
  Set two-factor authentication policy on the Google Cloud Identity domain.
- Change Google Webmaster Tools access to use the Google Cloud Identity managed accounts.
  Unfortunately, Google Webmaster Tools only supports individual Google accounts and doesn't (yet?) support Google Cloud Identity or Google Groups.
  But at least the same Google accounts managed by Google Cloud Identity could be used for Google Webmaster Tools access.
- Determine the purpose of the two non-human admin accounts and consolidate onto one account if this access is still needed.

.. _accepted-risks:

Accepted risks
==============

The following possible security gaps do not appear to be significant enough to warrant investment of project resources given the threat model.

Internet-accessible services
----------------------------

Many SQuaRE services are Internet-accessible by design and do not require a VPN.
This avoids the need to run a VPN infrastructure, makes it easier for SQuaRE staff to do their job from any location, and avoids network disruptions and other problems from VPN difficulties.
Requiring VPN would allow SQuaRE to reduce the attack surface of SQuaRE infrastructure by restricting it to VPN IP addresses, but some services (such as those in support of the RSP) would still need to be Internet-accessible.
VPN does not protect against compromised work computers, only against Internet mass scanning.

Internet-accessible services greatly ease technical collaborations between systems at the summit, the LDF, the test stands, and various cloud services.
That in turn increases project development velocity at this critical construction phase of the project.

Given that the primary attack points are restricted to nginx ingress servers, given that exposed SQuaRE services require authentication, and given the cost and complexity of maintaining IP restrictions, running a VPN service, and requiring staff to use the VPN, SQuaRE should accept the risk of Internet-accessible services for the time being.
Security resources are better spent on ensuring those services are regularly patched and upgraded, and the authentication mechanisms used are strong (such as by requiring two-factor authentication).

This can be reconsidered once the project goes into operations.

Supply-chain attacks
--------------------

Attackers are increasingly attempting to compromise widely-shared library and resource repositories, such as PyPI, NPM, and Docker Hub.
If they are successful in doing so, they can inject malicious code into many downstream users of those services.
This is particularly a risk when automatically deploying new upstream versions of dependencies.
However, this risk is very hard to defend against.

SQuaRE does not have the resources to rebuild dependencies locally or otherwise isolate itself from public code and resource repositories.
Any successful attack of this type is likely to make headlines, and SQuaRE can then take remedial action retroactively.
Attempting to defend against this attack proactively is unlikely to be successful given existing resources and is unlikely to uniquely affect the project (and thus does not pose a substantial reputational risk to the project).

We should therefore accept this risk.

Use of Slack
------------

Slack, the company, has access to the contents of all Slack workspaces and therefore potential access to any security credentials or other confidential information shared over Slack, intentionally or unintentionally.
This type of "watering hole" service has been a target of attack in the past (see `the HipChat compromise in 2017`_).

.. _the HipChat compromise in 2017: https://www.zdnet.com/article/hipchat-hacked-user-account-info-and-some-user-content-potentially-compromised/

The project does not currently have :abbr:`SSO (single sign-on)` for Slack and thus has limited central management of Slack authentication credentials.
SQuaRE also uses Slack for operations and thus trusts Slack authentication to determine the permissions of a user taking an action via a Slack bot.
This is increasingly common among many projects and companies, and thus SQuaRE is not taking unusual risks.

Completely avoiding confidential communication in Slack is difficult.

Slack's business model depends on the security of their workspaces, and they have more dedicated security resources than SQuaRE has available.
SQuaRE staff should attempt to avoid sharing security credentials in Slack, but taking stronger precautions or avoiding Slack for privileged operations is not warranted given the threat model.

Unencrypted internal connections
--------------------------------

SQuaRE practice is to terminate TLS at the nginx ingress and use unencrypted connections internal to Kubernetes clusters.
This creates a small risk of attackers who have compromised one node eavesdropping on internal cluster communications.
However, cloud Kubernetes providers already do network isolation, cluster traffic does not cross the public Internet, and only an attacker who has already compromised a service will be in position to attempt this attack.

The cost of configuring TLS between all cluster services is far higher than the marginal security benefit that would be gained.

.. _glossary:

Glossary
========

APT
    An advanced persistent threat.
    An attack aimed at achieving persistence (repeatable access to an environment) in order to steal high-value data.
    These attacks are narrowly targeted at a specific site and often involve significant research and analysis of the security practices of the target.
    They prioritize avoiding detection, in contrast to the more typical "smash and grab" attacks of less sophisticated attackers.
    An APT is a sign of well-funded attackers, either large-scale organized crime or **state actors**.

endpoint
    The device with a screen and keyboard into which one is directly typing.
    A collective term for work laptops, desktops, personal laptops and desktops, mobile devices, and any other end-user device with screen and keyboard used in the course of project work.
    An attacker with full access to an endpoint has full access to anything accessed from that endpoint, can steal authentication credentials, and can impersonate the user of that device or piggyback on their authenticated connections.
    Security of endpoints is therefore critical to the security of any overall system.

insider threat
    An attack by a trusted member of the organization being attacked.
    For example, a service maintainer using their privileged access to that service to steal data for non-work purposes.

penetration testing
    Testing services and systems for vulnerabilities that could be exploited by an attacker.
    Penetration testing comes in a wide range of levels of sophistication and effectiveness, ranging from running an off-the-shelf security scanner like Nessus to hiring a professional **red team**.
    The less-sophisticated forms of penetration testing are prone to huge numbers of false positives.

phishing
    An attempt to trick someone into revealing their security credentials or other information of value to an attacker.
    Most commonly done via email.
    A typical example is an email purporting to be from one's bank or credit card company, asking the recipient to verify their identity by providing their account credentials to a web site under the attacker's control.
    Most phishing attacks have telltale signs of forgery (misspelled words, broken images, questionable URLs, and so forth), and are sent via untargeted mass spam campaigns.
    See **spear-phishing** for the more sophisticated variation.

ransomware
    Malware that performs some reversible damage to a computer system (normally, encrypting all files with a key known only to the attacker), and then demands payment (usually in Bitcoin) in return for reversing the damage.
    CryptoLocker is the most well-known example.

red team
    A security team whose job is to simulate the actions of an attacker and attempt to compromise the systems and services of their employer or client.
    The intrusion detection and response team responsible for detecting the attack and mitigating it is often called the "blue team."
    The terminology comes from military training exercises.

security control
    Some prevention or detection measure against a security threat.
    Password authentication, second-factor authentication, alerts on unexpected administrative actions, mandatory approval steps, and automated security validation tests are all examples of security controls.

spear-phishing
    A targeted phishing attack that is customized for the recipient.
    A typical example is a message sent to a staff member in HR and forged to appear to be from a senior manager, asking for copies of employee W-2 forms or other confidential information.
    Spear-phishing from professional attackers can be quite sophisticated and nearly indistinguishable from legitimate email.

state actor
    Professional attackers who work for a government.
    The most sophisticated tier of attackers, with capabilities beyond the defensive capacity of most organizations.
    Examples include the US's :abbr:`NSA (National Security Agency)` and China's Ministry of State Security.
    See **APT**.

XSS
    Cross-site scripting.
    One of the most common web vulnerabilities and attacks.
    Takes advantage of inadequate escaping or other security flaws in a web application to trick a user's web browser into running JavaScript or other code supplied by the attacker in the user's security context.
    Can be used to steal authentication credentials such as cookies, steal other confidential data, or phish the user.

Changes
=======

2020-08-21
----------

- Add Kubernetes pod hardening recommendations to :ref:`Kubernetes hardening <gap-kubernetes>`.
- Add disabling ABAC legacy access control for Kubernetes clusters.
- Mention enabling Kubernetes network policy support at the cluster level.
- Suggest use of a bastion host to allow restricting access to the cluster control plane and nodes.

2020-08-19
----------

- Add shared accounts to the analysis in :ref:`Two-factor authentication <gap-two-factor>`.
- Add reviewing shared account passwords to the recommendations.
- Add two-factor authentication for RubyGems and a review of other shared accounts to the recommendations.
- Raise the risk of :ref:`Google authentication <gap-google-auth>` to medium due to our heavily reliance on Google services.
- Add Google Cloud Identity to the top recommendations.
- Update analysis, mitigations, and recommendations for the work that was done on :ref:`Security patching <gap-patching>`.
- Add :ref:`Kubernetes hardening <gap-kubernetes>` and mark it as one of the highest risk areas.
