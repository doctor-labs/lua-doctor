-- Rule module: names.
--
-- Findings about a name, not about a flow: an execution API spelled so that the
-- taint engine cannot see it.
--
--   713  a call to an undefined name one edit away from a declared sink
--        (`os.execte(cmd)`): the call fails at run time and is not analyzed, so
--        the finding the sink would have produced is silently missing.
--
-- Code this module owns: 713. See docs/rules.md.
local M = {}

local platform_api = require "luadoctor.registry.platform_api"
local std_names = require "luadoctor.registry.std_names"

local detectors = {}

-- Optimal-string-alignment distance (insert, delete, substitute, adjacent
-- swap), giving up above `limit`. Names are short, so the full table is cheap.
local function edit_distance(a, b, limit)
   if math.abs(#a - #b) > limit then return limit + 1 end
   local previous, current = {}, {}
   local before_previous
   for j = 0, #b do previous[j] = j end
   for i = 1, #a do
      current[0] = i
      for j = 1, #b do
         local cost = a:byte(i) == b:byte(j) and 0 or 1
         local best = math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
         if i > 1 and j > 1 and a:byte(i) == b:byte(j - 1) and a:byte(i - 1) == b:byte(j) then
            best = math.min(best, before_previous[j - 2] + 1)
         end
         current[j] = best
      end
      before_previous, previous, current = previous, current, {}
   end
   return previous[#b]
end
M.edit_distance = edit_distance

-- One edit. Two let in `readfile` for `loadfile`, a helper every firmware tree
-- defines for itself (it fired four times in the luasocket tests). `popen` and
-- `open` are one edit apart and both real: that is why the name must also be
-- undefined.
local function close_enough(written, declared)
   if written == declared or #declared < 4 then return false end
   return edit_distance(written, declared, 1) <= 1
end

-- The declared execution entry points as {prefix, last, path}: calls only, no
-- assignment sinks, no wildcards in the middle of a path.
local function declared_sinks()
   local out = {}
   local function take(list)
      for _, entry in ipairs(list) do
         if entry.kind ~= "assign" then
            local path = entry.pattern:gsub("%.%*$", "")
            if not path:find("[%*%?:]") then
               local prefix, last = path:match("^(.*)%.([^%.]+)$")
               out[#out + 1] = {prefix = prefix or "", last = last or path, path = path}
            end
         end
      end
   end
   take(platform_api.sinks())
   take(platform_api.shapes())
   return out
end

-- Global names the file assigns (`function helper() end`, `helper = f`): a call
-- to one of those is defined in this file whatever the std says.
local function assigned_globals(chstate)
   local names = {}
   for _, line in ipairs(chstate.lines) do
      for _, item in ipairs(line.items) do
         if item.tag == "Set" then
            for _, target in ipairs(item.lhs or {}) do
               if target.tag == "Id" and not target.var then names[target[1]] = true end
            end
         end
      end
   end
   return names
end

local function split(path)
   local parts = {}
   for part in path:gmatch("[^%.]+") do parts[#parts + 1] = part end
   return parts
end

local function detect_misspelled_sink(ctx)
   local sinks = declared_sinks()
   local std = std_names.current(ctx.opts)
   local assigned = assigned_globals(ctx.chstate)

   ctx:each_call(function(node, path)
      if node.tag ~= "Call" or not path then return end
      local parts = split(path)
      local written = parts[#parts]
      local prefix = table.concat(parts, ".", 1, #parts - 1)

      local status, at = std_names.status(std, parts)
      if status ~= "undefined" or at ~= #parts then return end
      if #parts == 1 and assigned[parts[1]] then return end

      for _, sink in ipairs(sinks) do
         if sink.prefix == prefix and close_enough(written, sink.last) then
            ctx:emit("713", node[1], {name = path, likely = sink.path})
            return
         end
      end
   end)
end

detectors[#detectors + 1] = detect_misspelled_sink

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M
