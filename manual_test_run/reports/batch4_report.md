# Testing Report: Batch 4

### python3 -m hashaxe --hash 4762aaa5e83ec22af033c810ef30bf29 --osint-file /home/bhanu/htb/HashAxe/manual_test_run/osint_profile.txt
**Status:** FAIL
**Execution Time:** 0.62s
**Root Cause / Error:** Non-zero exit
```text


     ██╗  ██╗ █████╗ ███████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
     ██║  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗╚██╗██╔╝██╔════╝
     ███████║███████║███████╗███████║███████║ ╚███╔╝ █████╗  
     ██╔══██║██╔══██║╚════██║██╔══██║██╔══██║ ██╔██╗ ██╔══╝  
     ██║  ██║██║  ██║███████║██║  ██║██║  ██║██╔╝ ██╗███████╗
     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
 ────────────────────────────────────────────────────────────────
              HashAxe V1  Multi-Format Hash Cracker
  43 For
...
```

### python3 -m hashaxe --hash 4762aaa5e83ec22af033c810ef30bf29 --ai --candidates 50
**Status:** FAIL
**Execution Time:** 0s
**Root Cause / Error:** Exception during execution
```text
Command '['python3', '-m', 'hashaxe', '--hash', '4762aaa5e83ec22af033c810ef30bf29', '--ai', '--candidates', '50']' timed out after 20 seconds
...
```

### python3 -m hashaxe --hash 4762aaa5e83ec22af033c810ef30bf29 --attack pcfg
**Status:** PASS
**Execution Time:** 1.43s
**Root Cause / Error:** 
```text


     ██╗  ██╗ █████╗ ███████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
     ██║  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗╚██╗██╔╝██╔════╝
     ███████║███████║███████╗███████║███████║ ╚███╔╝ █████╗  
     ██╔══██║██╔══██║╚════██║██╔══██║██╔══██║ ██╔██╗ ██╔══╝  
     ██║  ██║██║  ██║███████║██║  ██║██║  ██║██╔╝ ██╗███████╗
     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
 ────────────────────────────────────────────────────────────────
              HashAxe V1  Multi-Format Hash Cracker
  43 For
...
```

### python3 -m hashaxe --hash 4762aaa5e83ec22af033c810ef30bf29 --distributed-master --mask ?d?d
**Status:** FAIL
**Execution Time:** 0.73s
**Root Cause / Error:** Non-zero exit
```text


     ██╗  ██╗ █████╗ ███████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
     ██║  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗╚██╗██╔╝██╔════╝
     ███████║███████║███████╗███████║███████║ ╚███╔╝ █████╗  
     ██╔══██║██╔══██║╚════██║██╔══██║██╔══██║ ██╔██╗ ██╔══╝  
     ██║  ██║██║  ██║███████║██║  ██║██║  ██║██╔╝ ██╗███████╗
     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
 ────────────────────────────────────────────────────────────────
              HashAxe V1  Multi-Format Hash Cracker
  43 For
...
```

