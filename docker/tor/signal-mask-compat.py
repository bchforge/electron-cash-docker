"""Permit glibc's process-local SIG_BLOCK when creating sandboxed workers.

glibc pthread_create saves its old mask using SIG_BLOCK, then restores it with
SIG_SETMASK. Rejecting the first call leaves the saved mask uninitialized and
can block SIGTERM permanently. Keep Sandbox=1 and every other filter unchanged.
"""
import hashlib
import sys
from pathlib import Path

source = Path(sys.argv[1])
original = source.read_bytes()
if hashlib.sha256(original).hexdigest() != 'fe79bdb50200f7a353c13d98a32938d4da53a67edf9ee6d606183b008cae5306':
    raise SystemExit('unexpected Tor sandbox source; review signal-mask compatibility')
before = b'''#if defined(ENABLE_FRAGILE_HARDENING) || \\
    defined(USE_TRACING_INSTRUMENTATION_LTTNG)
  rc = seccomp_rule_add_1(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask),
      SCMP_CMP(0, SCMP_CMP_EQ, SIG_BLOCK));
  if (rc)
    return rc;
#endif
'''
after = b'''  /* glibc pthread_create must save/restore the process-local signal mask. */
  rc = seccomp_rule_add_1(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask),
      SCMP_CMP(0, SCMP_CMP_EQ, SIG_BLOCK));
  if (rc)
    return rc;
'''
if original.count(before) != 1:
    raise SystemExit('unexpected Tor signal-mask filter structure')
source.write_bytes(original.replace(before, after, 1))
print('Applied scoped Tor/glibc SIG_BLOCK compatibility; all other sandbox rules retained')
