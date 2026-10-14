-- Rule module: patterns.
--
-- Declared pattern rules (`pattern_rules` in a profile or --rules file). A pattern
-- is one Lua expression, written as code, with metavariables:
--
--   vendor.run($CMD)      any call to vendor.run with one argument
--   same($A, $A)         the same expression in both places, or no match
--
-- `$NAME` is an uppercase name that matches any one expression. It is rewritten to
-- an identifier before parsing, so the pattern parses with the same parser as the
-- file it is matched against. The pattern is matched at every expression of the
-- file, so `vendor.run(x)` inside a function body is found as well.
--
-- Codes this module owns: 742. See docs/rules.md.
local M = {}

local parse_context = require "luadoctor.engine.parse_context"
local platform_api = require "luadoctor.registry.platform_api"

local detectors = {}

local MARK = "lua_doctor_mv_"
local SEVERITIES = {critical = true, high = true, medium = true, low = true}
local CONFIDENCES = {certain = true, high = true, medium = true, low = true}

-- ---------------------------------------------------------------- compile

-- Parsed patterns, keyed by pattern text. The same text is compiled once per run.
local compiled = {}

--- Parse a pattern into the expression node it names, or return nil plus a reason.
local function compile(text)
   if compiled[text] then return compiled[text] end
   if type(text) ~= "string" or text:match("^%s*$") then
      return nil, "the pattern is empty"
   end
   local source = "return " .. (text:gsub("%$(%u[%u%d_]*)", MARK .. "%1"))
   local chstate = parse_context.build(source)
   if not chstate then return nil, "the pattern is not Lua expression syntax" end
   local ast = chstate.ast
   local ret = ast[1]
   if #ast ~= 1 or not ret or ret.tag ~= "Return" or not ret[1] or ret[2] then
      return nil, "the pattern must be one expression"
   end
   compiled[text] = ret[1]
   return ret[1]
end

-- ---------------------------------------------------------------- match

local function is_metavar(node)
   return type(node) == "table" and node.tag == "Id" and type(node[1]) == "string"
      and node[1]:sub(1, #MARK) == MARK
end

-- The text of a node with its positions left out, so two occurrences of one
-- expression compare equal wherever they sit in the file.
local function fingerprint(node)
   if type(node) ~= "table" then return string.format("%q", tostring(node)) end
   local parts = {}
   for i = 1, #node do parts[i] = fingerprint(node[i]) end
   return (node.tag or "") .. "(" .. table.concat(parts, ",") .. ")"
end

-- Does `node` match `pattern`? `env` collects what each metavariable matched.
local function matches(pattern, node, env)
   if is_metavar(pattern) then
      local name = pattern[1]
      if env[name] then return fingerprint(env[name]) == fingerprint(node) end
      env[name] = node
      return true
   end
   if type(pattern) ~= "table" then return pattern == node end
   if type(node) ~= "table" or pattern.tag ~= node.tag or #pattern ~= #node then return false end
   for i = 1, #pattern do
      if not matches(pattern[i], node[i], env) then return false end
   end
   return true
end

-- ---------------------------------------------------------------- validate

--- Check one `pattern_rules` entry; returns nil when it is usable, or a message.
-- Called by the profile loader, so a bad rule is refused before analysis.
function M.validate(rule)
   local id = type(rule.id) == "string" and rule.id ~= "" and rule.id or nil
   if not id then return "a pattern rule needs an id as a non-empty string" end
   if rule.severity ~= nil and not SEVERITIES[rule.severity] then
      return ("pattern rule '%s' has an unknown severity %q"):format(id, tostring(rule.severity))
   end
   if rule.confidence ~= nil and not CONFIDENCES[rule.confidence] then
      return ("pattern rule '%s' has an unknown confidence %q"):format(id, tostring(rule.confidence))
   end
   if rule.cwe ~= nil and type(rule.cwe) ~= "string" then
      return ("pattern rule '%s' needs cwe as a string"):format(id)
   end
   local _, reason = compile(rule.pattern)
   if reason then
      return ("pattern rule '%s': %s"):format(id, reason)
   end
   return nil
end

-- ---------------------------------------------------------------- detector

local function detect(ctx)
   for _, rule in ipairs(platform_api.pattern_rules()) do
      local pattern = compile(rule.pattern)
      if pattern then
         -- ponytail: one walk per rule over the whole file. Index by root tag if rule counts grow.
         ctx:each_node(function(node)
            if matches(pattern, node, {}) then
               ctx:emit("742", node, {name = rule.id, severity = rule.severity,
                  confidence = rule.confidence, cwe = rule.cwe})
            end
         end)
      end
   end
end

detectors[#detectors + 1] = detect

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M
