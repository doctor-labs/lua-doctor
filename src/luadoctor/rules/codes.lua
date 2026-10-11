-- Warning code registry.
--
-- A code is the stable public identity of a finding. Every code declares its
-- severity, default confidence, CWE, message template and the extra fields its
-- findings carry. `docs/rules.md` must document every registered code; a spec
-- enforces that.
local codes = {}

local registry = {}

local function register(spec)
   assert(spec.code and spec.code:match("^%d%d%d$"), "code must be three digits: " .. tostring(spec.code))
   assert(not registry[spec.code], "duplicate warning code " .. spec.code)
   assert(spec.message, "code " .. spec.code .. " needs a message")
   assert(spec.severity, "code " .. spec.code .. " needs a severity")
   spec.fields = spec.fields or {}
   registry[spec.code] = spec
   return spec
end

local function sorted_codes(t)
   local keys = {}
   for k in pairs(t) do keys[#keys + 1] = k end
   table.sort(keys)
   return keys
end

codes.register = register
codes.get = function(code) return registry[code] end
codes.exists = function(code) return registry[code] ~= nil end
codes.all = function()
   local out = {}
   for _, code in ipairs(sorted_codes(registry)) do out[#out + 1] = registry[code] end
   return out
end
codes.count = function() local n = 0 for _ in pairs(registry) do n = n + 1 end return n end

--- Render a code's message template against a finding.
-- Placeholders are {field}; unknown placeholders are left alone so a typo is
-- visible in the report rather than silently swallowed.
function codes.render(spec, finding)
   local message = spec.message
   return (message:gsub("{(%w+)}", function(field)
      local value = finding[field]
      if value == nil then return "{" .. field .. "}" end
      return tostring(value)
   end))
end

--- A code's message with its `({field})` placeholder groups removed: what the
-- code means, without the names of one finding's fields.
function codes.meaning(code)
   local spec = registry[code]
   if not spec then return "" end
   return (spec.message:gsub("%s*%({%w+}%)", ""):gsub("%s*{%w+}", ""))
end

-- ---------------------------------------------------------------- 7xx exec

register {code = "701", severity = "high", cwe = "CWE-78",
   message = "command execution with a non-constant argument ({name})"}

register {code = "702", severity = "high", cwe = "CWE-78",
   message = "pipe opened with a non-constant command ({name})"}

register {code = "703", severity = "high", cwe = "CWE-94",
   message = "dynamic code evaluation with a non-constant argument ({name})"}

register {code = "704", severity = "high", cwe = "CWE-94",
   message = "code or script loaded from a non-constant path ({name})"}

register {code = "705", severity = "high", cwe = "CWE-94",
   message = "module name computed at runtime ({name})"}

register {code = "706", severity = "high", cwe = "CWE-94",
   message = "native library loaded from a non-constant path ({name})"}

register {code = "707", severity = "high", cwe = "CWE-94",
   message = "LuaJIT FFI escape hatch used ({name})"}

-- Registered high because most of the sinks it names are high, and the emitted
-- finding carries the severity of the sink it is about - an argument this file
-- cannot trace into a shell is a worse thing to have than one it cannot trace
-- into a destructive file operation.
--
-- The words are about the argument, not about the sink. This is reported beside
-- the sink's own 701 - which says the command is built from something the file
-- cannot fold - so a message whose subject is "execution sink" reads as a second
-- opinion on the sink, and the operator cannot tell which of the two to act on.
-- What 708 knows and 701 does not is where the value came from: not this file.
register {code = "708", severity = "high", cwe = "CWE-78",
   message = "exported execution sink whose argument nothing in this file feeds ({name})"}

register {code = "709", severity = "critical", cwe = "CWE-78", confidence = "high",
   message = "untrusted data reaches command execution ({name})",
   fields = {"sink", "source", "sources", "trace", "snippet", "sanitizer"}}

register {code = "710", severity = "critical", cwe = "CWE-94", confidence = "high",
   message = "untrusted data reaches dynamic code evaluation ({name})",
   fields = {"sink", "source", "sources", "trace", "snippet", "sanitizer"}}

register {code = "711", severity = "high", cwe = "CWE-78",
   message = "shell command written as a backtick literal"}

register {code = "712", severity = "high", cwe = "CWE-78", confidence = "high",
   message = "shell metacharacters from untrusted data are not quoted ({name})",
   fields = {"sink", "source", "sources", "trace", "snippet", "metachars"}}

-- The call fails at run time (an undefined name is nil) and the taint engine has
-- no sink to match, so a finding the intended API would have produced is
-- missing. Registered medium: it is a defect in the file, not an exploit.
register {code = "713", severity = "medium", cwe = "CWE-0", confidence = "medium",
   message = "call to an undefined name that looks like the execution sink {likely} ({name}); the call is not analyzed"}

-- A local that is not the library under another spelling replaces it for every
-- call in its scope, and the declared sinks and sources on that library stop
-- matching there. Medium for the same reason as 713: a defect in what the scan
-- can see, not an exploit.
register {code = "714", severity = "medium", cwe = "CWE-0", confidence = "medium",
   message = "local variable replaces a standard library that APIs are declared on, "
      .. "so calls through it are not analyzed ({name})"}

-- ---------------------------------------------------------------- 7xx firmware

register {code = "721", severity = "high", cwe = "CWE-1236",
   message = "write to flash or firmware configuration with untrusted data ({name})",
   fields = {"sink", "source", "sources", "trace", "path"}}

register {code = "722", severity = "high", cwe = "CWE-78",
   message = "configuration value set from untrusted data, which a service may later execute ({name})",
   fields = {"sink", "source", "sources", "trace", "chain"}}

register {code = "729", severity = "high", cwe = "CWE-78", confidence = "medium",
   message = "untrusted data stored in {store} is read back into command execution ({name})",
   fields = {"sink", "source", "sources", "trace", "store", "writer"}}

register {code = "723", severity = "medium", cwe = "CWE-538",
   message = "sensitive file read by path literal ({name})",
   fields = {"path"}}

-- The registered severity is the one that holds when the sink's command can
-- hold request data. A handler whose command is a literal is the same exposure
-- with no injection behind it, so its finding keeps the shape, carries lower
-- strength, and says why in `{note}`. A finding with nothing to add must set
-- that field to the empty string: `render` leaves an unset placeholder in the
-- message rather than printing nothing.
register {code = "724", severity = "high", cwe = "CWE-78",
   message = "function containing an execution sink is exposed as an RPC handler ({name}){note}",
   fields = {"sink", "exposed_as", "note"}}

register {code = "725", severity = "high", cwe = "CWE-693",
   message = "sandbox or global environment manipulated ({name})"}

register {code = "726", severity = "medium", cwe = "CWE-732",
   message = "self-modifying or destructive operation ({name})"}

register {code = "727", severity = "medium", cwe = "CWE-400",
   message = "unbounded string growth can exhaust memory ({name})"}

register {code = "728", severity = "medium", cwe = "CWE-1333",
   message = "untrusted data used as a search pattern ({name})",
   fields = {"sink", "source", "sources", "trace"}}

register {code = "730", severity = "high", cwe = "CWE-93", confidence = "high",
   message = "untrusted data written into an HTTP header or URI ({name})",
   fields = {"sink", "source", "sources", "trace", "snippet"}}

register {code = "731", severity = "high", cwe = "CWE-444", confidence = "high",
   message = "untrusted data written into an HTTP subrequest ({name})",
   fields = {"sink", "source", "sources", "trace", "snippet"}}

-- ---------------------------------------------------------------- 7xx payload

register {code = "741", severity = "critical", cwe = "CWE-94",
   message = "obfuscated code loader ({name})"}

register {code = "743", severity = "critical", cwe = "CWE-94",
   message = "decoded data fed to an execution sink ({name})"}

register {code = "745", severity = "medium", cwe = "CWE-693",
   message = "anti-analysis or watchdog behaviour ({name})"}

register {code = "746", severity = "critical", cwe = "CWE-506",
   message = "embedded machine-code blob ({name})"}

register {code = "747", severity = "high", cwe = "CWE-798",
   message = "hardcoded credential ({name})",
   fields = {"kind", "redacted"}}

register {code = "748", severity = "critical", cwe = "CWE-307",
   message = "scanner or credential brute-force loop ({name})"}

register {code = "749", severity = "high", cwe = "CWE-506",
   message = "persistence installed by the script ({name})"}

register {code = "750", severity = "critical", cwe = "CWE-1203",
   message = "matches a known exploit or malware signature: {name}",
   fields = {"signature", "pack_version"}}

-- ---------------------------------------------------------------- 8xx artifact

register {code = "801", severity = "medium", cwe = "CWE-0",
   message = "Lua bytecode file, source cannot be analyzed ({name})"}

register {code = "802", severity = "high", cwe = "CWE-94",
   message = "bytecode references an execution sink ({name})"}

register {code = "803", severity = "low", cwe = "CWE-0",
   message = "bytecode format does not match the assumed interpreter ({name})"}

register {code = "805", severity = "low", cwe = "CWE-0",
   message = "file is not parseable Lua despite its name ({name})"}

-- ---------------------------------------------------------------- 0xx suppression

-- A `-- lua-doctor:` directive the analyzer could not read: an action it does not
-- know, or a code pattern Lua cannot read as a pattern. It is in the 0xx range
-- with the other suppression problems, and it is a coverage gap rather than a
-- note: findings may have been kept or dropped other than the operator asked,
-- so a run with one of these does not pass.
--
-- This code was emitted for an unknown action from the start and never
-- registered, so a SARIF result could name a ruleId the tool did not declare,
-- and it sat on 021, which is luacheck's: a finding that means one thing in the
-- JSON and another in luacheck's own output. It is 012 now.
register {code = "012", severity = "low", cwe = "CWE-0",
   message = "a lua-doctor suppression directive could not be read ({name})"}

-- ---------------------------------------------------------------- 9xx meta

register {code = "901", severity = "low", cwe = "CWE-0",
   message = "source could not be parsed; lexical scan only"}

register {code = "902", severity = "low", cwe = "CWE-0",
   message = "source uses a Lua construct the parser does not support ({name})"}

register {code = "903", severity = "low", cwe = "CWE-0",
   message = "API seen that is not available in the configured Lua standard ({name})"}

register {code = "904", severity = "medium", cwe = "CWE-0", confidence = "certain",
   message = "flow-sensitive analysis skipped for a large file ({name}); results are approximate",
   fields = {"node_count", "mode"}}

-- ---------------------------------------------------------------- 95x lint (opt-in)

-- luacheck 113 / selene undefined_variable. Low: the std is a list of names, and
-- a platform can provide one it does not list. Opt-in, see rules/lint_gate.lua.
register {code = "951", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "accessing undefined variable ({name}){note}", fields = {"note"}}

-- luacheck 111 (setting a global the std does not define) and 112 (mutating one,
-- `foo.bar = 1`). The `action` field says which; the finding is about a global
-- that leaks into the shared environment, which is also how a sandbox is escaped.
register {code = "952", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "{action} non-standard global variable ({name})", fields = {"action"}}

-- luacheck 121 (`os = nil`) and 122 (`string.format = f`): the std marks the
-- name read-only. Overwriting a standard function is also how a script swaps in
-- its own `os.execute`, so this is the lint most worth reading in firmware.
register {code = "953", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "{action} read-only global variable ({name})", fields = {"action"}}

-- luacheck 142 / 143: the global exists but the field does not (`os.execte`,
-- `string.fromat`). The field is named in the finding's name as a dotted path.
register {code = "954", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "{action} undefined field of global ({name})", fields = {"action"}}

-- selene mismatched_arg_count. The extra arguments are ignored at run time, so
-- they usually mean the callee is not the function the author had in mind; for
-- a sink, a misplaced argument is how the value that matters never reaches it.
register {code = "957", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "too many arguments to {name}: it takes {max}, {given} passed", fields = {"max", "given"}}

-- selene incorrect_standard_library_use. One code for three kinds of misuse, the
-- `problem` field says which: too few required arguments, a literal of a type
-- the parameter cannot take, a pure function called for nothing.
register {code = "958", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "{problem} ({name})", fields = {"problem"}}

-- selene duplicate_keys. Two entries in one table constructor share the same
-- literal key, so one silently overwrites the other.
register {code = "959", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "duplicate key {key} in a table"}

-- selene compare_nan. Comparing a value against NaN is always false for == and
-- always true for ~=.
register {code = "960", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "comparing with NaN is always false for == and true for ~=; use x ~= x to test for NaN"}

-- selene constant_table_comparison. A table constructor has a new identity each
-- time it runs, so comparing one to anything by value is always false for == and
-- always true for ~=.
register {code = "961", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "comparing with a new table is always false for == and true for ~= (tables compare by identity)"}

-- selene almost_swapped. Two consecutive assignments swap two names but lose a
-- value: A = B; B = A copies B into both rather than swapping them.
register {code = "962", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "this looks like a swap that loses a value; use {a}, {b} = {b}, {a}"}
-- Empty branch / loop / reversed loop, judged the way luacheck and selene judge
-- them (luacheck 542/571, selene empty_if/empty_loop/suspicious_reverse_loop).
register {code = "963", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "empty if branch"}

register {code = "964", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "empty loop body"}

register {code = "965", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "this loop does not run: it counts down without a step; add , -1 (e.g. for i = 10, 1, -1)"}



-- selene if_same_then_else. Two branches of one if do the same thing, so one
-- of them is dead. Empty branches are not reported here (963's job in selene,
-- out of this tool's range).
register {code = "966", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "two branches of this if do the same thing"}

-- selene ifs_same_cond. An elseif repeats a condition that already ran, so it
-- can never execute.
register {code = "967", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "this elseif repeats an earlier condition, so it never runs"}

-- selene mixed_table. A table constructor has positional and keyed entries at
-- the same time, which is almost always an accidental index.
register {code = "968", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "this table mixes positional and keyed entries"}


-- luacheck 531/532 / selene unbalanced_assignments. A local or plain assignment
-- has a different number of names and values, and the last value cannot expand
-- to fill the gap (a call, an invoke, or `...` can).
register {code = "969", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "{n} names, {m} value(s): the assignment is unbalanced"}

-- selene parenthese_conditions. The whole condition of an if, elseif, while, or
-- until is wrapped in parentheses, which hides its intent and can mask a
-- subsequent condition change.
register {code = "970", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "parentheses around the whole condition are not needed"}

-- luacheck 521. A named label that no `goto` in the same function jumps to.
register {code = "971", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "unused label {name}"}

-- selene divide_by_zero. A `/` or `%` whose right operand is the literal 0 or
-- folds to 0, except the NaN idiom 0/0.
register {code = "972", severity = "low", cwe = "CWE-0", confidence = "medium",
   message = "division by zero"}

-- luacheck 631. A line whose length exceeds the configured limit (120).
register {code = "973", severity = "low", cwe = "CWE-0", confidence = "high",
   message = "line is {n} characters long (limit 120)"}

-- luacheck 551 / selene empty_statement. A semicolon on its own, not after a
-- statement: `;;`, a leading `;`, or a `;` after a comment.
register {code = "974", severity = "low", cwe = "CWE-0", confidence = "high",
   message = "empty statement (a stray `;`)"}

-- selene multiple_statements. More than one statement begins on the same line,
-- within a single block. Nested blocks are checked independently.
register {code = "975", severity = "low", cwe = "CWE-0", confidence = "high",
   message = "more than one statement on this line"}

-- luacheck 611/612/613/614. A line whose trailing run of whitespace is not part
-- of a multi-line string value. The rendered message is "trailing whitespace", or
-- "line contains only whitespace" when the whole line is spaces/tabs.
register {code = "976", severity = "low", cwe = "CWE-0", confidence = "high",
   message = "{msg}"}

-- luacheck 621. Indentation whose leading whitespace runs into a space right
-- before a tab, e.g. " \t".
register {code = "977", severity = "low", cwe = "CWE-0", confidence = "high",
   message = "indentation has a space before a tab"}

-- selene global_usage. A reference to the global table `_G` that is not a local
-- named `_G` shadowing it. Reading or writing the global directly bypasses scope
-- tracking and is brittle; keep a local table instead.
register {code = "978", severity = "low", cwe = "CWE-0", confidence = "high",
   message = "{msg}"}

-- selene type_check_inside_call. type() is being called with a comparison
-- expression as its argument, which is almost always a typo for
-- `type(x) == "..."` (and never type-checks the intended value).
register {code = "979", severity = "low", cwe = "CWE-0", confidence = "high",
   message = "comparison passed to type(): did you mean type(x) == \"...\"?"}

return codes
