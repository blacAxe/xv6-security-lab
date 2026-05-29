# Hardened xv6 Kernel Research

## Category

Operating Systems / Security Research

---

## Overview

A research-focused operating systems project that adds multiple security hardening mechanisms to the RISC-V xv6 kernel.

The project explores how kernel-level auditing, memory randomization, access control, and integrity monitoring can be implemented inside a small educational operating system.

---

## Security Features

### Stealth Kernel Auditor

Implemented a ring-buffered kernel audit log that tracks process execution through `exec` events with timestamp information based on kernel ticks.

### Stack ASLR

Added Address Space Layout Randomization for the user stack by randomizing stack placement across multiple memory pages using PID and hardware cycle-based entropy.

### Active Access Control

Implemented a kernel-level policy that detects unauthorized access to sensitive file paths and terminates the offending process immediately.

### Kernel Integrity Monitoring

Added checksum-based monitoring for the system call table to detect unauthorized modifications similar to rootkit-style tampering.

---

## Verification
- Run `spytree` to view the secure kernel audit log.
- Observe changing stack pointer addresses to verify ASLR behavior.
- Attempt to run `secret_tool` to trigger the active access-control policy.

---

## Commands to Run

```bash
ls
echo "top secret" > secret_tool
secret_tool
spytree

```
---

## What This Demonstrates

- Operating system internals
- Kernel instrumentation and observability
- Memory layout randomization (ASLR)
- Kernel-level policy enforcement
- System call table integrity monitoring
- Security-focused kernel hardening
- Low-level C systems programming