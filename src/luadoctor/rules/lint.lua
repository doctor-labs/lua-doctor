-- Rule module: lint.
--
-- Names, judged the way luacheck judges them. luacheck's detect_globals stage
-- (vendored, unmodified) records every global access and set with the fields
-- indexed from it; this module decides, against the std, which of those are
-- findings and gives each luacheck code its lua-doctor code.
--
--   951  accessing an undefined variable        (luacheck 113, selene undefined_variable)
--   952  setting or mutating a non-standard global (luacheck 111, 112)
--   953  setting a read-only global or a field of one (luacheck 121, 122)
--   954  setting or accessing an undefined field of a global (luacheck 142, 143)
--
-- Opt-in: see rules/lint_gate.lua. Code range 950-979.
local M = {}

local detect_globals = require "luacheck.stages.detect_globals"
local std_names = require "luadoctor.registry.std_names"
local lint_gate = require "luadoctor.rules.lint_gate"

local detectors = {}

-- luacheck code -> the lua-doctor code that reports it, and the `action` its
-- message names.
local EMITTED = {
   ["113"] = {code = "951"},
   ["111"] = {code = "952", action = "setting"},
   ["112"] = {code = "952", action = "mutating"},
   ["121"] = {code = "953", action = "setting"},
   ["122"] = {code = "953", action = "setting a field of"},
   ["142"] = {code = "954", action = "setting"},
   ["143"] = {code = "954", action = "accessing"},
}

-- The raw warnings of detect_globals, once per file: several lint rules read
-- them and the stage records into the check state.
local function raw_warnings(chstate)
   if chstate.lint_globals then return chstate.lint_globals end
   local raw = {}
   if chstate.resolved_locals then
      local before = #chstate.warnings
      detect_globals.run(chstate)
      for i = before + 1, #chstate.warnings do raw[#raw + 1] = chstate.warnings[i] end
      for i = #chstate.warnings, before + 1, -1 do chstate.warnings[i] = nil end
   end
   chstate.lint_globals = raw
   return raw
end

-- luacheck's classification of one raw 111/112/113 warning: its final code, or
-- nil when the std says the name is fine. See luacheck's filter.lua.
local function classify(std, warning)
   local code = warning.code
   local full = std_names.field_status(std, warning.name, warning.indexing)

   if (code == "111" or code == "112") and full == "read_only" then
      return "12" .. code:sub(3, 3)
   end
   if (code == "112" or code == "113")
         and std_names.field_status(std, warning.name, warning.indexing, 1) ~= "undefined" then
      code = "14" .. code:sub(3, 3)
   end

   if warning.indirect and warning.previous_indexing_len
         and std_names.field_status(std, warning.name, warning.indexing,
            warning.previous_indexing_len) == "undefined" then
      return nil
   end
   if full ~= "undefined" then return nil end
   return code
end

local function span(ctx, warning)
   local start = (ctx.chstate.line_offsets[warning.line] or 0) + warning.column - 1
   return {line = warning.line, offset = start,
      end_offset = start + math.max(0, (warning.end_column or warning.column) - warning.column)}
end

-- `os.execte`: the global and the fields indexed from it, as far as they are
-- literal names (an unknown key is written `?`).
local function field_path(warning)
   local parts = {warning.name}
   for _, key in ipairs(warning.indexing or {}) do
      parts[#parts + 1] = type(key) == "string" and key or "?"
   end
   return table.concat(parts, ".")
end

local function detect_names(ctx)
   local wanted = {}
   local any = false
   for luacheck_code, target in pairs(EMITTED) do
      if lint_gate.wanted(ctx.opts, target.code) then
         wanted[luacheck_code] = target
         any = true
      end
   end
   if not any then return end

   local std = std_names.current(ctx.opts)
   for _, warning in ipairs(raw_warnings(ctx.chstate)) do
      local luacheck_code = classify(std, warning)
      local target = luacheck_code and wanted[luacheck_code]
      if target then
         ctx:emit(target.code, span(ctx, warning),
            {name = target.code == "954" and field_path(warning) or warning.name, action = target.action})
      end
   end
end

detectors[#detectors + 1] = detect_names

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M
