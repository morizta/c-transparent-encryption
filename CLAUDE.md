# Takakrypt Transparent Agent Development Session Memory

## 🧠 Prompt Reminder (for Claude)
- Always reason based on the **current session summary** and existing files.
- Never forget previous steps unless **explicitly instructed**.
- When unsure, **ask for clarification**, do not assume.
- Always be **precise**, **concise**, and **goal-oriented**.
- Avoid drifting from **task-specific context**.

---

## 📁 Session Context → `SESSION_MEMORY.md`
- Update after every **major milestone**, **new task**, or **blocked issue**.
- Structure:
  - `## TODO`
  - `## DONE`
  - `## BLOCKED`
  - `## DATE`
- Purpose: Serves as **session memory snapshot** for all future prompts.

---

## THALES ANALYSYS -> `THALES_CTE_ANALYSIS.md`
- Update fater every **major milestone**, **new task**, or **new information** for reference
- Purpose: Serves as **documentation reference for thales** for all future prompts.

## 🐞 Bug Tracking → `BUG_FIXING.md`
- Always log when:
  - 🧩 **Bug is found**
  - 🔧 **Fix is applied**
- Format:
  - `### [BUG_NAME]`
    - **Found on**: `DATE`
    - **Symptoms**: (What happened)
    - **Suspected Causes**: (List ordered possibilities)
    - **Fix Steps**: (What was done to fix)
    - **Verification**: (How it was confirmed fixed)
    - **Future Prevention**: (Add tests/docs/notes)

---

## 📚 Knowledge Log → `RESEARCH.md` (❗️Missing)
- Every time you or Claude needs to **research something**, log it here:
  - `## [TOPIC]`
    - **Date**:
    - **Summary**: (Short and clear)
    - **Key Takeaways**:
    - **Used in**: (Feature/bug/part)
- Prevents repeated research or asking same things later.

---

## ⚙️ Commands & Utilities → `UTILS.md` (Optional)
- Record any repeated terminal commands, scripts, or Claude prompts that help development
- Makes it easier to onboard new contributors or revisit older features
