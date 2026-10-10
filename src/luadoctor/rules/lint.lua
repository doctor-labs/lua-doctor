-- Rule module: lint.
--
-- Names, judged the way luacheck judges them. luacheck's detect_globals stage
-- (vendored, unmodified) records every global access and set with the fields
-- indexed from it; this module decides, against the std, which of those are
-- findings and gives each luacheck code its lua-doctor code.
--
--   951  accessing an undefined variable        (luacheck 113, selene undefined_variable)
--        With allow_defined, a global the file assigns is defined where it is
--        read, as selene (and luacheck's option of that name) have it.
--   952  setting or mutating a non-standard global (luacheck 111, 112)
--   953  setting a read-only global or a field of one (luacheck 121, 122)
--   954  setting or accessing an undefined field of a global (luacheck 142, 143)
--   957  more arguments than the callee takes  (selene mismatched_arg_count)
--
-- Opt-in: see rules/lint_gate.lua. Code range 950-979.
local M = {}

local detect_globals = require "luacheck.stages.detect_globals"
local std_names = require "luadoctor.registry.std_names"
local platform_api = require "luadoctor.registry.platform_api"
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

-- luacheck's allow_defined: every whole-name set defines the global. A defined
-- name is no longer undefined to read (113) or mutate (112), and its defining
-- set is not a finding (luacheck calls an unread one 131, unused global, which
-- lua-doctor does not report).
local function defined_in_file(raw)
   local defined = {}
   for _, warning in ipairs(raw) do
      if warning.code == "111" then defined[warning.name] = true end
   end
   return defined
end

-- selene's "this might be a name from another standard library" note, for the
-- built-in profiles that do define it.
local function note_for(name)
   local profiles_found = std_names.profiles_defining(name)
   if #profiles_found == 0 then return "" end
   return ("; defined by --std +%s"):format(table.concat(profiles_found, " or +"))
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
   local raw = raw_warnings(ctx.chstate)
   local defined = ctx.opts.allow_defined and defined_in_file(raw) or {}
   for _, warning in ipairs(raw) do
      local luacheck_code = not defined[warning.name] and classify(std, warning)
      local target = luacheck_code and wanted[luacheck_code]
      if target then
         ctx:emit(target.code, span(ctx, warning),
            {name = target.code == "954" and field_path(warning) or warning.name, action = target.action,
               note = target.code == "951" and note_for(warning.name) or nil})
      end
   end
end

detectors[#detectors + 1] = detect_names

-- ---------------------------------------------------------------- 957

-- Every call expression with the statement it sits in, nested ones included. A
-- function body is its own line, so it is not entered.
local function each_call(chstate, visit)
   local function walk(node, item, depth)
      if type(node) ~= "table" or depth > 64 or node.tag == "Function" then return end
      if node.tag == "Call" then visit(node, item) end
      for _, child in ipairs(node) do
         if type(child) == "table" then walk(child, item, depth + 1) end
      end
   end
   for _, line in ipairs(chstate.lines) do
      for _, item in ipairs(line.items) do
         if item.tag == "Eval" then
            walk(item.node, item, 0)
         elseif item.tag == "Local" or item.tag == "Set" then
            for _, value in ipairs(item.rhs or {}) do walk(value, item, 0) end
         end
      end
   end
end

-- The arguments a call passes, and whether the last of them can expand into
-- several values (a call, `...`), in which case the count is a floor.
local function call_arguments(node)
   local args = {}
   for index = 2, #node do args[#args + 1] = node[index] end
   return args
end

-- How many arguments a local function takes, or nil when it is unknown or
-- takes any number: every definition that can reach the call must be a plain
-- function, and the most generous one decides (selene's "best overlap").
local function local_arity(callee, item)
   if callee.tag ~= "Id" or not callee.var or not item or not item.used_values then return nil end
   local values = item.used_values[callee.var]
   if not values or #values == 0 then return nil end
   local most = 0
   for _, value in ipairs(values) do
      local fn = value.node
      if not fn or fn.tag ~= "Function" then return nil end
      local count = 0
      for _, formal in ipairs(fn[1] or {}) do
         if formal.tag == "Dots" then return nil end
         count = count + 1
      end
      if count > most then most = count end
   end
   return most
end

local function detect_arg_count(ctx)
   if not lint_gate.wanted(ctx.opts, "957") then return end
   each_call(ctx.chstate, function(node, item)
      local args = call_arguments(node)
      local given = #args

      local path = ctx:path_of(node[1])
      local params = path and platform_api.params_for(path)
      local most
      if params then
         most = params[#params] ~= "..." and #params or nil
      else
         most = local_arity(node[1], item)
         path = path or (node[1].tag == "Id" and node[1][1]) or nil
      end

      if most and path and given > most then
         ctx:emit("957", node, {name = path, max = most, given = given})
      end
   end)
end

detectors[#detectors + 1] = detect_arg_count

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M
