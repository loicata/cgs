# Project: Autonomous Cybersecurity Server for SMBs

## Language
All code, test names, comments, commit messages, documentation, and variable names must be in English.
However, communicate with me in French when giving summaries and reports.

---

# PHASE 1 — Audit and quality improvement of existing code

This phase is the priority. Do NOT move to phase 2 until I explicitly tell you to.

## Step 1.1 — Project mapping
When I say "analyse le projet", do the following:
1. List all modules and files with a one-line description for each.
2. Identify the main features.
3. List all external dependencies.
4. Identify program entry points (main, server, CLI).
5. Flag any obvious security issues.
6. Present everything as a summary table.
7. Rank modules from most critical to least critical in terms of security.
Wait for my approval before moving to the next step.

## Step 1.2 — Security audit of existing code
When I say "audit sécurité", do the following:
1. Run bandit on the entire codebase and present results sorted by severity (HIGH, MEDIUM, LOW).
2. Run pip-audit on dependencies and flag known vulnerabilities.
3. Check that no secret, password, or key is hardcoded in the source code.
4. Check that user inputs are properly validated and sanitized.
5. Check that network communications use encryption (TLS/SSL).
6. Present a summary report with issues ranked by priority.
Wait for my approval before fixing anything.

## Step 1.3 — Security fixes
When I say "corrige les failles", do the following:
1. Fix vulnerabilities in order of severity: HIGH first, then MEDIUM, then LOW.
2. For each fix, explain in one sentence what you changed and why.
3. Never alter the functional behavior of the program when fixing a security issue.
4. After each batch of fixes, run bandit and pip-audit again to confirm the issues are resolved.
Wait for my approval between each severity level (HIGH, MEDIUM, LOW).

## Step 1.4 — Adding tests to existing code
When I say "ajoute les tests", do the following:
1. Proceed module by module, from most critical to least critical (based on the ranking from step 1.1).
2. For each module:
   a. Write unit tests for each public function.
   b. Write integration tests that verify the module's overall behavior.
   c. Use mocks to simulate network, connections, and external services.
   d. Test names must clearly describe the behavior being verified in English (e.g., test_block_ip_after_5_failed_login_attempts).
   e. Run the tests and fix any bugs you discover.
   f. Give me a summary: number of tests passed, failed, and the module's coverage rate.
3. Do NOT move to the next module without my explicit approval.

## Step 1.5 — Phase 1 summary
When I say "bilan phase 1", present:
1. Overall test coverage rate and coverage per module.
2. Total number of vulnerabilities fixed (HIGH, MEDIUM, LOW).
3. Total number of bugs discovered and fixed through testing.
4. Modules that remain below 80% coverage.
5. Your recommendation on whether the project is solid enough to move to phase 2.
Wait for my approval to move to phase 2.

---

# PHASE 2 — Rules for future development

These rules apply only when I say "on passe en phase 2".

## General rules
- Never modify existing code behavior without explicitly notifying me before proceeding.
- After each development session, run all tests and give me a summary: tests passed, tests failed, and the list of failures with explanations.
- Immediately flag any security issue you spot.

## Mandatory tests for all new code
- For every new feature, write unit tests and integration tests with pytest.
- Each test name must clearly describe the behavior being verified, in English.
- Use mocks to simulate network, connections, and external services.
- Maintain at least 80% test coverage across the entire project.

## Code quality and security
- Use bandit for static security analysis of Python code.
- Use pip-audit to check for known vulnerabilities in dependencies.
- All secrets, passwords, and keys must use environment variables, never hardcoded.

## CI/CD with GitHub Actions
- The CI/CD pipeline must be defined in .github/workflows/ci.yml.
- It triggers on every push to the main branch.
- Pipeline steps:
  1. Install Python project dependencies.
  2. Run all tests with pytest and display the coverage report.
  3. Run pip-audit to check for dependency vulnerabilities.
  4. Run bandit to detect security flaws in the code.
  5. Block deployment if any test fails or if a critical vulnerability is detected.

## Docker
- The Dockerfile must be optimized and secure: non-root user, minimal image, no hardcoded secrets.
- The Docker image is pushed to GitHub Container Registry only if all tests pass and no critical vulnerability is detected.

## Regular report
When I say "rapport", run all tests, give me the summary of results, and tell me if there are any regressions.
