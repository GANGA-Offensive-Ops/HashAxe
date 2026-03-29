# Testing Report: Batch 4

### python3 -m hashaxe --hash 4762aaa5e83ec22af033c810ef30bf29 --osint-file /home/bhanu/htb/hashaxe/manual_test_run/osint_profile.txt

**Status:** FAIL
**Execution Time:** 0s
**Root Cause / Error:** Exception during execution

```text
Command '['python3', '-m', 'hashaxe', '--hash', '4762aaa5e83ec22af033c810ef30bf29', '--osint-file', '/home/bhanu/htb/hashaxe/manual_test_run/osint_profile.txt']' timed out after 20 seconds
...
```

### python3 -m hashaxe --hash 4762aaa5e83ec22af033c810ef30bf29 --ai --candidates 50

**Status:** FAIL
**Execution Time:** 15.51s
**Root Cause / Error:** Non-zero exit

```text


           ██████╗██████╗  █████╗  ██████╗██╗  ██╗
          ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
          ██║     ██████╔╝███████║██║     █████╔╝
          ██║     ██╔══██╗██╔══██║██║     ██╔═██╗
          ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
           ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
 ──────────────────────────────────────────────────────────
          Crack V2 — Multi-Format Password Cracker
 43 Formats · SSH/PPK/Archives/Docs/DB/Network/Kerberos/DPAPI
   GPU-Accelerated · 
...
```

### python3 -m hashaxe --hash 4762aaa5e83ec22af033c810ef30bf29 --attack pcfg

**Status:** PASS
**Execution Time:** 0.42s
**Root Cause / Error:**

```text


           ██████╗██████╗  █████╗  ██████╗██╗  ██╗
          ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
          ██║     ██████╔╝███████║██║     █████╔╝
          ██║     ██╔══██╗██╔══██║██║     ██╔═██╗
          ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
           ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
 ──────────────────────────────────────────────────────────
          Crack V2 — Multi-Format Password Cracker
 43 Formats · SSH/PPK/Archives/Docs/DB/Network/Kerberos/DPAPI
   GPU-Accelerated · 
...
```

### python3 -m hashaxe --hash 4762aaa5e83ec22af033c810ef30bf29 --distributed-master --mask ?d?d

**Status:** FAIL
**Execution Time:** 0.31s
**Root Cause / Error:** Non-zero exit

```text


           ██████╗██████╗  █████╗  ██████╗██╗  ██╗
          ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
          ██║     ██████╔╝███████║██║     █████╔╝
          ██║     ██╔══██╗██╔══██║██║     ██╔═██╗
          ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
           ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
 ──────────────────────────────────────────────────────────
          Crack V2 — Multi-Format Password Cracker
 43 Formats · SSH/PPK/Archives/Docs/DB/Network/Kerberos/DPAPI
   GPU-Accelerated · 
...
```
