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
-- Combinators (semgrep-style), all optional on one rule:
--   pattern_either = {p1, p2, ...}  instead of pattern: any alternative matches
--   pattern_inside = p             the match must sit inside an expression that matches p
--   pattern_not = p                a match that also matches p is dropped
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
   local pattern_either = rule.pattern_either or rule["pattern-either"]
   local pattern_inside = rule.pattern_inside or rule["pattern-inside"]
   local pattern_not = rule.pattern_not or rule["pattern-not"]
   local pattern = rule.pattern
   if pattern_either ~= nil then
      if pattern ~= nil then
         return ("pattern rule '%s' gives pattern or pattern_either, not both"):format(id)
      end
      if type(pattern_either) ~= "table" or #pattern_either == 0 then
         return ("pattern rule '%s' needs pattern_either as a non-empty list"):format(id)
      end
      for _, text in ipairs(pattern_either) do
         local _, reason = compile(text)
         if reason then return ("pattern rule '%s': %s"):format(id, reason) end
      end
   else
      local _, reason = compile(pattern)
      if reason then
         return ("pattern rule '%s': %s"):format(id, reason)
      end
   end
   if pattern_inside ~= nil then
      local _, reason = compile(pattern_inside)
      if reason then return ("pattern rule '%s' pattern_inside: %s"):format(id, reason) end
   end
   if pattern_not ~= nil then
      local _, reason = compile(pattern_not)
      if reason then return ("pattern rule '%s' pattern_not: %s"):format(id, reason) end
   end
   return nil
end

-- ---------------------------------------------------------------- detector

-- Visit each tagged expression node that is in scope, parents before children.
-- Without an inside pattern every node is in scope; with one, a node is in scope
-- when it or one of its ancestors matches it. Same shape as the context walk.
local function scan(node, in_scope, inside, visit, depth)
   if depth > 200 or type(node) ~= "table" then return end
   if node.tag then
      if not in_scope and matches(inside, node, {}) then in_scope = true end
      if in_scope then visit(node) end
   end
   for index = 1, #node do
      local child = node[index]
      if type(child) == "table" then
         if child.tag then
            scan(child, in_scope, inside, visit, depth + 1)
         else
            for _, sub in ipairs(child) do
               if type(sub) == "table" and sub.tag then
                  scan(sub, in_scope, inside, visit, depth + 1)
               end
            end
         end
      end
   end
end

local function detect(ctx)
   for _, rule in ipairs(platform_api.pattern_rules()) do
      local pattern_either = rule.pattern_either or rule["pattern-either"]
      local pattern_inside = rule.pattern_inside or rule["pattern-inside"]
      local pattern_not = rule.pattern_not or rule["pattern-not"]
      local alternatives = {}
      for _, text in ipairs(pattern_either or {rule.pattern}) do
         alternatives[#alternatives + 1] = compile(text)
      end
      local inside = pattern_inside and compile(pattern_inside)
      local excluded = pattern_not and compile(pattern_not)
      -- ponytail: one walk per rule over the whole file. Index by root tag if rule counts grow.
      scan(ctx.chstate.ast, inside == nil, inside, function(node)
         for _, pattern in ipairs(alternatives) do
            if matches(pattern, node, {}) then
               if not (excluded and matches(excluded, node, {})) then
                  ctx:emit("742", node, {name = rule.id, severity = rule.severity,
                     confidence = rule.confidence, cwe = rule.cwe})
               end
               return
            end
         end
      end, 0)
   end
end

detectors[#detectors + 1] = detect

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M
