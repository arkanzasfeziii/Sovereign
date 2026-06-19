# Sovereign — Windows & Active Directory Offensive Suite

> **Execute the full Active Directory kill chain: LDAP enumeration to Kerberoasting to DCSync to ACL abuse to Pass-the-Hash lateral movement — from a single domain credential.**

---

## Threat Model

Active Directory is the single point of trust for every Windows enterprise environment. A single compromised domain credential — even a low-privilege user — is the starting position for a complete AD kill chain that ends with every hash in the directory.

Sovereign models the attacker who starts with `domain\lowpriv:password` and systematically maps every privilege escalation path the Active Directory configuration has left exposed:

| Stage | What Fails | Adversary Action |
|---|---|---|
| **Domain Enumeration** | LDAP readable by any authenticated user — no read restrictions | Dump all users, groups, SPNs, delegation configs, trusts, and ACLs via LDAP bind |
| **Weak Lockout Policy** | Lockout threshold of 0 — account lockout disabled | Confirm spray safety before executing credential attacks at scale |
| **Passwords in Descriptions** | Helpdesk habit of setting temp passwords in the LDAP description attribute | Extract description field across all 300+ user objects — flag credential patterns |
| **Kerberoasting** | Service accounts (SPNs) use weak passwords; AS-REP tickets retrievable offline | Request TGS for all SPN accounts; export $krb5tgs$23$ hashes for offline cracking |
| **AS-REP Roasting** | Accounts with `DONT_REQ_PREAUTH` flag set — pre-authentication disabled | Request AS-REP without password; export $krb5asrep$23$ hashes for offline cracking |
| **DCSync** | Misconfigured ACL grants DS-Replication-Get-Changes-All rights to non-DC account | Replicate entire NTDS — dump all domain user NTLM hashes via DRSUAPI |
| **ACL Abuse** | GenericAll, ForceChangePassword, WriteSPN, WriteDACL permissions assigned to wrong principals | Exploit each: force group membership, reset password, create targeted Kerberoast SPN, modify DACL |
| **Lateral Movement** | NTLM hashes reusable without knowing cleartext password | Pass-the-Hash via Impacket; PSExec-style service creation; execute commands as SYSTEM |

**Scope:** Authorized Active Directory penetration testing and red team engagements against Windows domain environments.

---

## Why This Exists

Every major enterprise breach involving Windows environments follows the same pattern. Initial access → domain user credential → AD enumeration → privilege escalation → Domain Admin → DCSync → every password hash in the organization.

The individual components of this chain are well-documented. What Sovereign provides is the operational continuity: the LDAP enumeration identifies Kerberoastable accounts; the Kerberoast module extracts their hashes; the cracked hash drives the ACL abuse module; the compromised admin account drives DCSync; the DCSync output feeds the lateral movement module.

Sovereign is built around `EngagementContext` — a dataclass that holds the domain controller IP, domain name, current credentials, and the LDAP connection object. The same session that enumerates the domain in the Enum module is the session that modifies ACLs in the ACL abuse module. The Administrator hash extracted by DCSync is immediately available for Pass-the-Hash.

---

## Capabilities

### Domain Enumeration via LDAP

All enumeration over authenticated LDAP bind — no additional tooling required:

- **Domain baseline** — functional level, PDC emulator, domain SID, password policy (minimum length, lockout threshold, lockout observation window)
- **User enumeration** — all domain users with UAC flags (`DONT_EXPIRE_PASSWORD`, `PASSWD_NOTREQD`, `DONT_REQ_PREAUTH`), `adminCount`, `lastLogon`, `badPwgCount`; passwords in description fields flagged
- **SPN users (Kerberoastable)** — filter on `servicePrincipalName=*`; flag accounts that are also admin group members
- **AS-REP candidates** — filter on `userAccountControl:1.2.840.113556.1.4.803:=4194304`; all accounts with pre-authentication disabled
- **Computer accounts** — all machine accounts with OS version, last logon, and DNS hostname
- **Privileged groups** — 10 groups: Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Server Operators, Group Policy Creator Owners, DnsAdmins, Exchange Trusted Subsystem
- **Delegation** — unconstrained delegation (`TRUSTED_FOR_DELEGATION`) and constrained delegation (`msDS-AllowedToDelegateTo`) across computers and users
- **ACL analysis** — reads `nTSecurityDescriptor` on high-value AD objects; surface abnormal permission assignments to non-privileged users
- **Domain trusts** — enumerate forest/external/shortcut trusts with direction and transitivity
- **Password policy** — `minPwdLength`, `lockoutThreshold` (0 = spray freely), `lockoutDuration`

### Kerberoasting

- Request TGS (Ticket Granting Service) ticket for every SPN-bearing account using Impacket `getKerberosTGT` + `getKerberosTGS`
- Extract etype 23 (`$krb5tgs$23$`) or etype 17/18 (AES) from the TGS response
- Output in hashcat-compatible format: `$krb5tgs$23$*user*domain*SPN*` → crack with `-m 13100`
- Admin group members among SPN accounts flagged as critical priority for cracking

### AS-REP Roasting

- Request AS-REP ticket without password for each account with pre-authentication disabled
- Extract `$krb5asrep$23$` format from AS-REP response
- Output in hashcat-compatible format → crack with `-m 18200`
- Does not require any domain credential — works from network with zero authentication

### DCSync — Full NTDS Extraction

- Impacket `RemoteOperations` + `NTDSHashes` via DRSUAPI replication protocol
- Replicates all domain user objects and extracts NTLM hash pairs (LM:NT)
- Stores Administrator and krbtgt hashes separately — immediate privilege and golden ticket capability
- Requires DS-Replication-Get-Changes-All permission — confirmed via ACL analysis or by running as Domain Admin

### ACL Abuse

Operates on a target user/group specified by `sAMAccountName` or CN:

| ACL Right | Technique | Impacket/LDAP Method |
|---|---|---|
| `GenericAll` | Add current user to target group | LDAP `MODIFY_ADD` on `member` attribute |
| `ForceChangePassword` | Reset target account password without knowing current | LDAP `MODIFY_REPLACE` on `unicodePwd` |
| `WriteSPN` | Set SPN on target account → targeted Kerberoasting | LDAP `MODIFY_REPLACE` on `servicePrincipalName` |
| `WriteDACL` | Modify DACL on high-value object → grant self DCSync | Confirmed path; PowerView `Add-DomainObjectAcl` output generated |
| `DS-Replication-Get-Changes-All` | DCSync from any account with this right | Full NTDS extraction via DRSUAPI |

### Lateral Movement — Pass-the-Hash

- SMBConnection via Impacket with LM/NT hash pair (no cleartext password required)
- PSExec-style execution: create temporary SCMR service, execute command, retrieve output from `C$`
- Service removed after execution — minimal artifact footprint
- Accepts harvested hash from DCSync output directly

---

## Architecture

```
Domain Controller IP + Domain + Credentials/Hashes
                    │
                    ▼
           EngagementContext
  ┌──────────────────────────────────────────┐
  │  dc_ip · domain · username · password    │
  │  lm_hash · nt_hash · base_dn             │
  │  ldap_conn (shared LDAP session)         │
  └──────────────────────────────────────────┘
                    │
        ┌───────────┼────────────┐
        ▼           ▼            ▼
   EnumModule  Kerberoast   ASREPRoast
   LDAP full   TGS per SPN  AS-REP no-auth
   10 classes  etype 23/18  etype 23
        │
        ├────────────────────────┐
        ▼                        ▼
  DCsyncModule           ACLAbuseModule
  DRSUAPI replication    GenericAll/ForceChangePwd
  full NTLM dump         WriteSPN/WriteDACL
  Administrator + krbtgt  targeted Kerberoast
                               │
                               ▼
                        LateralModule
                        Pass-the-Hash
                        PSExec / SMB exec
                               │
                               ▼
                         JSON Report
                   (technique · account · hash)
```

---

## Attack Flow

1. **LDAP bind** — authenticate to domain controller via LDAP using provided credentials (or Kerberos ticket); establish session stored in `EngagementContext.ldap_conn`
2. **Domain baseline** — pull domain functional level, SID, lockout policy; confirm that lockout threshold is 0 before any spray activity
3. **Full user enumeration** — dump all domain users with UAC flags, adminCount, last logon, and description fields; flag accounts with passwords in descriptions
4. **SPN enumeration (Kerberoasting candidates)** — list all SPN-bearing accounts; flag Domain Admin members as critical targets
5. **AS-REP candidate identification** — list all accounts with pre-authentication disabled; these can be attacked without any credential
6. **Privileged group membership** — enumerate all 10 privileged groups; map full membership including nested groups
7. **ACL audit** — read `nTSecurityDescriptor` from high-value AD objects; flag non-standard permission grants to unprivileged principals; identify DCSync rights holders
8. **Kerberoast** — request TGS for each SPN account; extract etype 23 hash; write to `kerberoast.hash` in hashcat format
9. **AS-REP Roast** — request AS-REP for each no-preauth account; extract etype 23 hash; write to `asreproast.hash`
10. **ACL exploitation** — if GenericAll, ForceChangePassword, or WriteSPN is found, execute the corresponding LDAP modification
11. **DCSync** — if DS-Replication rights are confirmed (via ACL audit or after escalation), replicate NTDS; extract all hashes; store Administrator and krbtgt separately
12. **Lateral movement** — use extracted NTLM hash for Pass-the-Hash via Impacket; PSExec-style service creation; execute command on target; retrieve and display output

---

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Full domain enumeration via LDAP
python sovereign.py --dc 10.0.0.5 --domain corp.local \
  --username lowpriv --password "Found1234" --modules enum

# Kerberoast all SPN accounts
python sovereign.py --dc 10.0.0.5 --domain corp.local \
  --username lowpriv --password "Found1234" --modules kerberoast

# AS-REP roast without credentials
python sovereign.py --dc 10.0.0.5 --domain corp.local --modules asreproast

# DCSync — dump all NTLM hashes (requires replication rights)
python sovereign.py --dc 10.0.0.5 --domain corp.local \
  --username Administrator --password "Compromised!" --modules dcsync

# ACL abuse — force group membership via GenericAll
python sovereign.py --dc 10.0.0.5 --domain corp.local \
  --username lowpriv --password "Found1234" --modules aclabuse \
  --target "Domain Admins"

# Pass-the-Hash lateral movement
python sovereign.py --dc 10.0.0.5 --domain corp.local \
  --username Administrator --nt-hash aad3b435b51404eeaad3b435b51404ee \
  --modules lateral --target-host 10.0.0.20 --command "whoami"

# Full AD kill chain
python sovereign.py --dc 10.0.0.5 --domain corp.local \
  --username lowpriv --password "Found1234" --modules all \
  --output ad-engagement.json

# Non-interactive mode
python sovereign.py --dc 10.0.0.5 --domain corp.local \
  --username lowpriv --password "Found1234" --modules all --yes
```

---

## Output

```
18:44:01 [INFO]  [Enum] Domain: corp.local | Functional Level: Windows 2016
18:44:01 [WARN]  [Enum] Lockout threshold: 0 — password spraying is SAFE
18:44:02 [INFO]  [Enum] Users: 312 | Computers: 47 | Groups: 28
18:44:02 [CRIT]  [Enum] Password in description → svc-db: "InitialPass2023"
18:44:02 [CRIT]  [Enum] Password in description → helpdesk01: "Temp@1234"

18:44:03 [CRIT]  [Enum/SPNs] Kerberoastable accounts: 4
18:44:03 [CRIT]  [Enum/SPNs] svc-mssql (MSSQLSvc/db01.corp.local) → Domain Admin member!
18:44:03 [INFO]  [Enum/ASREPRoast] Pre-auth disabled: john.temp, test-account

18:44:04 [CRIT]  [Enum/ACL] GenericAll on Domain Admins → SELF (lowpriv)
18:44:04 [CRIT]  [Enum/ACL] DS-Replication-Get-Changes-All → svc-backup

18:44:05 [CRIT]  [Kerberoast] TGS extracted: svc-mssql | etype: 23
18:44:05 [INFO]  [Kerberoast] Hash: $krb5tgs$23$*svc-mssql*CORP.LOCAL*MSSQLSvc/db01*...
18:44:05 [INFO]  [Kerberoast] Crack: hashcat -m 13100 kerberoast.hash wordlist.txt

18:44:06 [CRIT]  [ASREPRoast] Hash extracted: john.temp | etype: 23
18:44:06 [INFO]  [ASREPRoast] Crack: hashcat -m 18200 asreproast.hash wordlist.txt

18:44:07 [CRIT]  [ACL] Executed GenericAll → added lowpriv to Domain Admins
18:44:08 [CRIT]  [DCSync] Replication started — extracting all NTLM hashes
18:44:09 [CRIT]  [DCSync] Administrator: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117...
18:44:09 [CRIT]  [DCSync] krbtgt: aad3b435b51404eeaad3b435b51404ee:dfb518984a7bea62...

18:44:10 [CRIT]  [Lateral] PTH success → 10.0.0.20 as CORP\Administrator
18:44:10 [INFO]  [Lateral] Command output: nt authority\system

[✓] AD engagement complete — 9 critical findings | report: ad-engagement.json
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Module |
|---|---|---|
| OS Credential Dumping: DCSync | T1003.006 | DCsyncModule |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | KerberoastModule |
| Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | ASREPRoastModule |
| Account Discovery: Domain Account | T1087.002 | EnumModule |
| Domain Policy Discovery | T1615 | EnumModule (password policy, delegation) |
| Abuse Elevation Control Mechanism | T1548 | ACLAbuseModule |
| Use Alternate Authentication Material: Pass-the-Hash | T1550.002 | LateralModule |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | LateralModule |
| Permission Groups Discovery: Domain Groups | T1069.002 | EnumModule |

**Tactics:** TA0006 Credential Access · TA0007 Discovery · TA0004 Privilege Escalation · TA0008 Lateral Movement · TA0003 Persistence

---

## CWE Coverage Exercised

| CWE | Description | Where |
|---|---|---|
| CWE-522 | Insufficiently Protected Credentials | Passwords in LDAP description fields, weak SPN account passwords |
| CWE-269 | Improper Privilege Management | ACL misconfigurations (GenericAll on privileged groups) |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | DS-Replication-Get-Changes-All on non-DC accounts |
| CWE-308 | Use of Single-Factor Authentication | NTLM hash reuse (no MFA for lateral movement) |
| CWE-284 | Improper Access Control | LDAP readable by all authenticated users |
| CWE-262 | Not Using Password Aging | `DONT_EXPIRE_PASSWORD` flag on service accounts |
| CWE-521 | Weak Password Requirements | Kerberoastable SPN accounts with crackable passwords |

---

## Legal Notice

Sovereign is designed exclusively for authorized Active Directory penetration testing and red team engagements where explicit written permission has been obtained from the domain owner. Unauthorized execution of DCSync, Kerberoasting, or Pass-the-Hash attacks against domain environments is illegal and may constitute unauthorized access to computer systems. The author assumes no liability for misuse.
