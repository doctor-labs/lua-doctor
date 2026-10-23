# Static Analysis Ecosystem Survey for Lua

## Executive Summary

This survey evaluates existing Lua static analysis tools and generic SAST dataflow engines to define `lua-doctor`'s positioning and technical niche.

**Core Finding**: No widely used security/taint scanner exists for Lua that identifies attacker input reaching command execution, code evaluation, or firmware mutation sinks across module boundaries. Linters (`luacheck`, `selene`) provide syntactic correctness and style checks, while multi-language pattern matchers (`semgrep`) lack Lua-specific interprocedural taint propagation and table field tracking. `lua-doctor` fills this gap as a specialized security analysis and RCE taint engine for Lua in embedded systems, OpenResty, LuCI, and firmware environments.

---

## Surveyed Tools and Approaches

### 1. Luacheck
* **Type**: Lua AST & Control-Flow Linter (C/Lua).
* **Focus**: Code correctness, undefined variables, unused locals, shadowing, cyclomatic complexity.
* **Capabilities**:
  * Excellent lexical analysis and scope resolution.
  * Detects uninitialized variables, unreachable code, unused parameters, and global leaks.
* **Limitations**:
  * Zero security or taint analysis capabilities.
  * Does not track dataflow from sources to sinks across function or module boundaries.
* **Integration into `lua-doctor`**: `luacheck`'s AST parser and local resolution stages are vendored into `lua-doctor` as the foundation for lint codes (950–1006) and dataflow graph construction.

### 2. Selene
* **Type**: Rust-based Lua/Luau Linter.
* **Focus**: Code quality, performance, and style consistency.
* **Capabilities**:
  * Fast execution and high-quality error reporting.
  * Lint checks for unscoped variables, duplicate table keys, parenthesized conditions, divide-by-zero, and deprecated standard library functions.
* **Limitations**:
  * Purely intraprocedural syntactic linting.
  * No concept of dataflow, taint sources, sanitizers, or security sinks.
* **Parity in `lua-doctor`**: All useful Selene rules (such as `unscoped_variables`, `unused_variable`, `shadowing`, `high_cyclomatic_complexity`, `manual_table_clone`, `divide_by_zero`) have been implemented in `lua-doctor` under the opt-in `lint` rule family.

### 3. Semgrep
* **Type**: Multi-language Pattern Matching Engine.
* **Focus**: AST-based rule matching across many languages.
* **Capabilities**:
  * Rule schema (`pattern`, `pattern-either`, `pattern-inside`, `pattern-not`, metavariables `$X`).
  * Good for shallow structural patterns in supported languages.
* **Limitations for Lua**:
  * Primitive Lua parsing and AST support compared to native Lua tools.
  * Lacks interprocedural return taint, table field tracking (`t.field`), store reads/writes, aliased sink tracking, and OpenResty/LuCI route modeling.
* **Adoption in `lua-doctor`**: `lua-doctor` adopts Semgrep's declarative pattern rule language (`pattern_rules` with `pattern`, `pattern-either`, `pattern-inside`, `pattern-not`, and metavariables `$VAR`) natively into its rule pipeline (`src/luadoctor/rules/patterns.lua`).

### 4. Generic SAST Engines (CodeQL, SonarQube, Fortify)
* **Type**: Enterprise Static Application Security Testing (SAST).
* **Focus**: Interprocedural dataflow and vulnerability scanning for enterprise stacks (C/C++, Java, Go, JS, Python, C#).
* **Limitations for Lua**:
  * Lua is unsupported by CodeQL's query engine.
  * SonarQube and Fortify provide minimal or no Lua taint rules, completely missing OpenWrt/LuCI/OpenResty idioms (`ngx.req`, `luci.dispatcher`, `nixio`, `uci`).

---

## Detailed Matrix Comparison

| Feature / Axis | Luacheck | Selene | Semgrep (Lua) | Generic SAST | `lua-doctor` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Attacker Input -> Command/Eval Taint** | ❌ No | ❌ No | ⚠️ Shallow | ❌ None | ✅ Deep Flow & Taint |
| **Sanitizer & Guard Modeling** | ❌ No | ❌ No | ⚠️ Basic | ❌ None | ✅ Context & Pattern Guards |
| **Table Field & Store Taint (`t.field`)** | ❌ No | ❌ No | ❌ No | ❌ No | ✅ Full Table Hop Tracking |
| **Interprocedural & Return Taint** | ❌ No | ❌ No | ❌ No | ❌ No | ✅ Whole-Program Dataflow |
| **OpenResty / LuCI / Firmware Awareness** | ❌ No | ❌ No | ❌ No | ❌ No | ✅ Native Platform Profiles |
| **Inline Directives & Precision Controls** | ⚠️ `--ignore` | ⚠️ `--allow` | ⚠️ nosemgrep | ⚠️ Inline comments | ✅ `-- lua-doctor: ignore` |
| **Structured Output & Agent Contract** | Plain | Plain/JSON | JSON/SARIF | SARIF/Proprietary | ✅ `doctor/1` JSON, SARIF, TAP, JUnit |

---

## Niche Confirmation & Strategy

1. **Definitive Security Niche**: `lua-doctor` stands alone as the only dedicated security taint scanner designed specifically for Lua codebases, OpenResty web gateways, and OpenWrt/LuCI embedded firmware.
2. **Best-of-Breed Borrowing**:
   - **From Luacheck**: Vendored parser and linearization pipeline for maximum AST fidelity.
   - **From Selene**: Opt-in lint checks covering style and code quality defects (codes 950–1006).
   - **From Semgrep**: Declarative pattern rule system (`pattern`, `pattern-inside`, `pattern-not`, `pattern-either`, metavariables).
3. **Machine-Friendly Agent Contract**: `lua-doctor` implements the standardized `doctor/1` envelope format, `--self-describe`, and deterministic exit codes (`0` clean, `1` findings, `2` error, `3` baseline new) for seamless integration into autonomous coding agents and CI/CD pipelines.
