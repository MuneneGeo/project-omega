# Contributing

Thanks for helping improve Project Omega.

## Ground rules
- Defensive use only. No exploit code, no "hack back" features.
- Keep the core a *single file with the Python standard library only*. Extra functionality belongs in plugins (omega_plugins/).
- Python 3.8+ compatible syntax.

## Workflow
1. Fork and create a branch: git checkout -b fix/short-description
2. Make your change.
3. Run python3 project_omega.py selftest - it must end with Result: ALL PASSED.
4. If you add a detection rule or feature, add a case to selftest() (a malicious sample and a benign control).
5. Open a pull request describing what changed and why. Never include real logs, IPs, tokens or customer data.

## Reporting bugs
Open an issue with the command, the output, your OS and Python version. For security issues see SECURITY.md.
