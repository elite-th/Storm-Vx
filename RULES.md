# STORM VX — AI Operating Rules

## Core Laws

**Law 0** — Before anything, read worklog, memory, and rules.

**Law 1** — Scan full project structure and dependencies before every action. Never assume.

**Law 2** — Every change must be the smallest possible with a clear technical reason.

**Law 3** — Before modifying any function, list all its callers. Never look at it in isolation.

**Law 4** — Optimize the highest-frequency execution path first. Cold paths later.

**Law 5** — Assume every input, data structure, and network state is dangerous until proven safe.

**Law 6** — For every logic, check 3 boundary cases: empty, overflow, contradictory.

**Law 7** — Document all work precisely in worklog.

**Law 8** — For every user request: Technical Roadmap → TO-DO List → Parallel Sub-Agents + Supervisors → Terminal Test.

**Law 9** — Write code for extensibility and scaling.

**Law 10** — After every code change, review with supervisor agent and confirm coding standards are met.

**Law 11** — Every code must simultaneously satisfy three conditions: secure (Law 5), extensible (Law 9), standard (Law 10). If any is violated, rewrite.

**Law 12** — No code is merged without supervisor approval. Every stage has a status: pending → in_progress → reviewed → approved.

**Law 13** — If a bug repeats 2 times, find the root cause and write a new law to prevent it.

**Law 14** — No file exceeds 500 lines. If it does, splitting is mandatory.

**Law 15** — Inter-module dependency only through interfaces. No direct import from another module's internals.

---

## Agent Architecture

Every user request must pass through 3 execution loops before completion:

### Loop 1: Executive Agents (Implementation)

| Role | Skill | Responsibility |
|---|---|---|
| **architect** | `architecture-designer` | Technical roadmap, structure design, dependency analysis |
| **coder** | `python-pro` | Code implementation per specification |
| **optimizer** | `database-optimizer` | Hot-path optimization, benchmarking |
| **integrator** | `microservices-architect` | Module connection, dependency resolution, interface design |

### Loop 2: Supervisory Agents (Verification)

| Role | Skill | Responsibility |
|---|---|---|
| **quality-supervisor** | `debugging-wizard` | Confirm changes are implemented + no bugs introduced |
| **security-auditor** | `security-reviewer` | Vulnerability check, input validation, race condition |
| **reviewer** | `code-reviewer` | Code standard check, naming, structure |

### Loop 3: Supervisor Agents (Approval)

| Role | Skill | Responsibility |
|---|---|---|
| **standard-supervisor** | `code-reviewer` + `secure-code-guardian` | Final approval: standard + secure + extensible |

### Specialist Agents (On Demand)

| Role | Skill | When to Use |
|---|---|---|
| **spec-writer** | `feature-forge` | Extract requirements from user request |
| **doc-writer** | `code-documenter` | Document API and architecture |
| **devils-advocate** | `the-fool` | Challenge design decisions before implementation |
| **legacy-analyzer** | `spec-miner` | Reverse-engineer undocumented code |
| **chaos-tester** | `chaos-engineer` | Resilience and fault-tolerance testing |
| **infra-designer** | `devops-engineer` | CI/CD, Docker, deployment design |
| **test-engineer** | `test-master` | Test strategy and execution |
| **api-designer** | `api-designer` | REST/GraphQL API design |
| **prompt-tuner** | `prompt-engineer` | LLM prompt optimization |
| **data-analyst** | `pandas-pro` | Data analysis and transformation |

---

## Execution Flow

```
User Request
    │
    ▼
[LAW 0] Read worklog + memory + rules
    │
    ▼
[LAW 8] spec-writer (feature-forge) → Extract requirements
    │
    ▼
[LAW 8] architect (architecture-designer) → Technical Roadmap + TO-DO
    │
    ▼
[LAW 8] coder × N (python-pro) → Parallel implementation
    │
    ▼
[LAW 8] integrator (microservices-architect) → Connect modules
    │
    ▼
[LOOP 2] quality-supervisor (debugging-wizard) → Implemented? No bugs?
    │
    ▼
[LOOP 2] security-auditor (security-reviewer) → Secure? No vulnerabilities?
    │
    ▼
[LOOP 3] standard-supervisor (code-reviewer + secure-code-guardian) → Final approval
    │
    ├── REJECTED → Return to coder with specific reasons
    │
    ▼
    APPROVED
    │
    ▼
[LAW 8] Terminal test → Confirm functionality
    │
    ▼
[LAW 7] Document in worklog → Done
```

---

## Skill Reference (66 Skills)

### Language Experts (12)
`python-pro` `typescript-pro` `golang-pro` `rust-engineer` `cpp-pro` `swift-expert` `kotlin-specialist` `csharp-developer` `php-pro` `java-architect` `javascript-pro` `sql-pro`

### Backend Frameworks (7)
`nestjs-expert` `django-expert` `fastapi-expert` `spring-boot-engineer` `laravel-specialist` `rails-expert` `dotnet-core-expert`

### Frontend & Mobile (7)
`react-expert` `nextjs-developer` `vue-expert` `vue-expert-js` `angular-architect` `react-native-expert` `flutter-expert`

### Architecture & Design (5)
`architecture-designer` `microservices-architect` `api-designer` `graphql-architect` `legacy-modernizer`

### Infrastructure & DevOps (7)
`devops-engineer` `kubernetes-specialist` `terraform-engineer` `cloud-architect` `monitoring-expert` `sre-engineer` `chaos-engineer`

### Security (3)
`secure-code-guardian` `security-reviewer` `fullstack-guardian`

### Data & ML (5)
`pandas-pro` `spark-engineer` `ml-pipeline` `rag-architect` `fine-tuning-expert`

### Workflow & Quality (8)
`feature-forge` `code-reviewer` `test-master` `debugging-wizard` `code-documenter` `spec-miner` `prompt-engineer` `the-fool`

### Platform Specialists (4)
`wordpress-pro` `shopify-expert` `salesforce-developer` `atlassian-mcp`

### Other (8)
`database-optimizer` `postgres-pro` `websocket-engineer` `game-developer` `embedded-systems` `playwright-expert` `cli-developer` `mcp-developer`

---

## External Skill Reference

**Claude Skills by jeffallan**: 66 specialized skills + 366 reference files
- Repository: https://github.com/jeffallan/claude-skills
- Install: `/plugin marketplace add jeffallan/claude-skills`
- Docs: https://jeffallan.github.io/claude-skills
- Skill Guide: https://github.com/jeffallan/claude-skills/blob/main/SKILLS_GUIDE.md
- Workflow patterns reference for multi-skill orchestration

---

## File Structure Constraints

```
Maximum file size: 500 lines (Law 14)
Inter-module: interface only (Law 15)
Worklog: mandatory after every task (Law 7)
Status flow: pending → in_progress → reviewed → approved (Law 12)
```
