# Architecture

```
sovereign/
├── cli.py               # CLI, module dispatch
├── config.py            # Metadata, legal warning
├── models.py            # AttackResult, Credential, ADObject, EngagementContext
├── logger.py            # Colored logging
├── output.py            # Banner, results, JSON export
├── exceptions.py        # Typed exceptions
├── modules/
│   ├── base.py          # BaseModule ABC
│   ├── enum.py          # LDAP enumeration (users, SPNs, admins, trusts)
│   ├── kerberoast.py    # Kerberoasting (TGS request + hash extraction)
│   ├── asreproast.py    # AS-REP roasting (no-preauth users)
│   ├── dcsync.py        # DCSync (NTDS hash dump)
│   ├── aclabuse.py      # ACL exploitation (GenericAll, AddMember, WriteSPN)
│   └── lateral.py       # Pass-the-Hash, WMI, SMB exec
├── utils/
│   └── ldap_helpers.py  # LDAP connect, search, domain-to-DN
└── data/
    └── __init__.py      # UAC flags, ACL GUIDs, LDAP queries, priv groups
```
