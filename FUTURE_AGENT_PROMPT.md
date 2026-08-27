# Safe Bash Execution on This Server — Prompt Template

Copy-paste the block below into any future AI coding agent's context.
The agent will then execute all Bash safely via `safe-cli`.

---

## 📋 Copy-paste this into your coding agent:

```
OPERATING ENVIRONMENT
=====================
You are operating on a remote server reached via:
  host:     <your-server-ip>
  user:     root
  password: <your-ssh-password>
  ssh:      sshpass -p '<your-ssh-password>' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@<your-server-ip>

The server runs a Bash safety system called `safe-cli`. It is the SINGLE
command you must use for any non-trivial Bash execution.

CRITICAL RULES (do NOT bypass):
1. ALWAYS wrap multi-line or non-trivial Bash in safe-cli.
   Pattern:
     sshpass -p '<your-ssh-password>' ssh ... root@<your-server-ip> \
       'safe-cli exec "your bash snippet here"'

2. For pre-existing or multi-line scripts:
     sshpass -p '<your-ssh-password>' scp -O ... script.sh root@<your-server-ip>:/tmp/
     sshpass -p '<your-ssh-password>' ssh ... root@<your-server-ip> \
       'safe-cli run /tmp/script.sh'

3. NEVER use destructive commands on the server:
     - NO: rm, rm -rf, rmdir, find ... -delete
     - YES: mv file _temp/file.disabled-$(date +%s)
            mv dir  _temp/dir.disabled-$(date +%s)
     - Reasoning: every destructive command risks permanent data loss;
       the operator has forbidden rm usage on this server. There is
       no rm in any safe-cli path either.

4. NEVER execute a script safe-cli refused.
   safe-cli exits non-zero on verification failure. If it does,
   read the diagnostics, fix the script, retry. Do not bypass.

5. ALWAYS back up before modifying existing files on the server:
     cp script.sh _temp/script.sh.before-edit-$(date +%s).bak
     # ...then edit...
   Backups go under /opt/bash-verifier/_temp/backup/ or your own
   /tmp/_temp/ directory. They are never auto-deleted.

WHAT safe-cli DOES:
  safe-cli run <script.sh>       # verify then execute; refuses if broken
  safe-cli exec 'bash snippet'   # verify inline Bash then execute
  safe-cli verify <script.sh>    # verify only, no execution
  safe-cli fix <script.sh>       # verify + auto-repair + write back
  safe-cli doctor                # health check (must say READY)

VERIFY-AND-EXECUTE PATTERN (the canonical safe workflow):
  $ sshpass -p '<your-ssh-password>' ssh -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null root@<your-server-ip> \
      'safe-cli doctor && safe-cli exec "echo READY_AND_VERIFIED"'

WHEN THINGS FAIL:
  - safe-cli exit != 0       → read the diagnostics, fix, retry
  - bash verify complains    → read the message, fix the script
  - bash verify is slow      → use --no-sandbox for static-only check
  - Python ModuleNotFound    → safe-cli doctor (should be READY)
  - Need docs                → cat /opt/bash-verifier/AGENT_BRIEF.md
                              (or /opt/bash-verifier/CLAUDE.md or
                               /root/CLAUDE.md — same content)

THE BRIEF: /opt/bash-verifier/AGENT_BRIEF.md
Read it once at session start. It is comprehensive and includes:
- Diagnostic interpretation (every [code] means something)
- Layer-by-layer explanation of what bash_verify does
- All safety invariants (no rm, no bypassing, backup-first)
- The full filesystem map
- Common failure modes + fixes
- The /opt/bash-verifier directory layout

WORKFLOW:
1. Read /opt/bash-verifier/AGENT_BRIEF.md at the start of any task
   that involves Bash on this server.
2. For every non-trivial Bash invocation, wrap it in safe-cli.
3. If safe-cli refuses (exits non-zero), repair and retry.
4. Never bypass verification. Never use rm. Always back up first.
```

---

## ✅ How a future agent should answer when you say:

> "Use safe-cli to execute commands on the server using sshpass"

The agent should:
1. **Acknowledge the brief** — read `/opt/bash-verifier/AGENT_BRIEF.md`
2. **Always wrap** multi-line Bash in `sshpass ... safe-cli exec "..."`
3. **Never use `rm`** — use `mv` to `_temp/` instead
4. **Never bypass** `safe-cli` exit codes
5. **Back up first** with `cp` to `_temp/backup/`

Example exchange:

> **User:** Check that nginx is running and the flowsignals proxy works.
>
> **Agent:**
> ```
> # Step 1: verify-safe health check
> sshpass -p '<your-ssh-password>' ssh ... root@<your-server-ip> \
>   'safe-cli doctor'
>
> # Step 2: verify-and-execute the nginx check
> sshpass -p '<your-ssh-password>' ssh ... root@<your-server-ip> \
>   'safe-cli exec "systemctl is-active nginx && curl -s -o /dev/null -w %{http_code} https://flowsignals.io/"'
>
> # Step 3: read the brief for any unfamiliar flag
> sshpass -p '<your-ssh-password>' ssh ... root@<your-server-ip> \
>   'cat /opt/bash-verifier/AGENT_BRIEF.md | head -100'
> ```

---

## 🔒 Final safety invariant — never bypass

If `safe-cli` exits non-zero:

1. **Read the diagnostics.** Every `[code/CODE]` in the output tells you
   what failed and where.
2. **Repair the script.** Use `safe-cli fix` for auto-repairable issues,
   or manually rewrite for syntax errors / sandbox failures.
3. **Re-verify.** Run `safe-cli verify` until exit code is 0.
4. **Then execute** via `safe-cli run`.

There is **no other path**. The system exists to protect you, the
operator, and the production systems. Bypassing it has no upside.
