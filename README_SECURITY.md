# Hardened xv6 Kernel Research
This project implements a multi-layer security architecture for the RISC-V xv6 kernel.

# Features
1. *Stealth Kernel Auditor*: A ring-buffered logging system that tracks process execution (`exec`) with microsecond-accurate timestamps using kernel ticks.
2. *Stack ASLR*: Implemented Address Space Layout Randomization for the user stack. Uses a combination of hardware cycles and PID-based entropy to randomize stack placement across 16 memory pages.
3. *Active Access Control (CRITICAL POLICY)*: Implemented a kernel-level policy that identifies unauthorized access to sensitive file paths and terminates the offending process instantly.
4. *Kernel Integrity Monitoring*: Added a checksum-based sentinel that monitors the system call table for unauthorized modifications (Rootkit detection).

# How to Verify
- Run `spytree` to view the secure kernel audit log.
- Observe the varying `[SP]` addresses to verify ASLR entropy.
- Attempt to run `secret_tool` to see the Active Defense kill-switch in action.

# Commands to Run
- $ ls
- $ echo "top secret" > secret_tool
- $ secret_tool
- $ spytree