-- Which global names and fields exist.
--
-- The platform registry knows APIs that matter to a security finding (sources,
-- sinks), not the names a Lua program may use. This module answers the second
-- question, from luacheck's own standard tables (`lua51` ... `luajit`, `max`),
-- so an undefined name can be told from a defined one: `os.execte` is not a
-- function, `os.execute` is.
--
-- A platform profile contributes names two ways. Every first path segment of a
-- pattern it declares is a global whose fields are unknown (`luci.http.formvalue`
-- defines `luci` and says nothing about `luci.foo`), and a profile may list
-- `globals` in luacheck's std format for names no pattern mentions.
local builtin_standards = require "luacheck.builtin_standards"
local standards = require "luacheck.standards"
local platform_api = require "luadoctor.registry.platform_api"
local profiles = require "luadoctor.registry.profiles"

local std_names = {}

local base_cache = {}

--- The Lua standard `--std` names, or nil.
local function lua_standard_of(std)
   if type(std) == "table" then std = table.concat(std, "+") end
   if type(std) ~= "string" then return nil end
   for part in std:gmatch("[^+]+") do
      local name = part:match("^%s*(.-)%s*$")
      if profiles.is_lua_standard(name) or (name == "luajit" and builtin_standards.luajit) then
         if builtin_standards[name] then return name end
      end
   end
   return nil
end

local function base_std(name)
   local std = base_cache[name]
   if std then return std end
   std = {}
   standards.add_std_table(std, builtin_standards[name])
   standards.finalize(std)
   base_cache[name] = std
   return std
end

--- The std a run is measured against: the Lua standard it names (the union of
-- all of them when it names none) plus what the loaded profiles declare.
-- Rebuilt per analysis because the loaded profiles change between runs.
function std_names.current(opts)
   local name = lua_standard_of(opts and opts.std) or "max"
   local base = base_std(name)

   local extra = {}
   local function add_root(root)
      if root and root ~= "" and not root:find("[%*%?]") and not base.fields[root] then
         extra[root] = extra[root] or {other_fields = true}
      end
   end
   local function from_entries(list)
      for _, entry in ipairs(list or {}) do
         add_root((entry.pattern or ""):match("^([^%.:]+)"))
      end
   end
   from_entries(platform_api.platform_sources())
   from_entries(platform_api.sinks())
   from_entries(platform_api.shapes())
   from_entries(platform_api.propagators())
   for _, entry in ipairs(platform_api.global_source_entries()) do add_root(entry.global) end
   for _, declared in ipairs(platform_api.std_globals()) do
      local extension = {}
      standards.add_std_table(extension, declared)
      for root, def in pairs(extension.fields or {}) do
         if not base.fields[root] then extra[root] = def end
      end
   end

   return {base = base, extra = extra}
end

local function def_of(std, name)
   return std.base.fields[name] or std.extra[name]
end

--- How a path of literal names stands against the std.
-- `parts` is {"os", "execte"}. Returns "defined" or "undefined", and for an
-- undefined path the index of the first part that is not. A name the std marks
-- `other_fields` accepts any field, which is how an unknown platform table
-- stays silent rather than guessed at.
function std_names.status(std, parts)
   local def = def_of(std, parts[1])
   if not def then return "undefined", 1 end
   for i = 2, #parts do
      if def.fields and def.fields[parts[i]] then
         def = def.fields[parts[i]]
      elseif def.other_fields then
         return "defined"
      else
         return "undefined", i
      end
   end
   return "defined"
end

--- Is `name` a global the std defines, or a platform root?
function std_names.defines_global(std, name)
   return def_of(std, name) ~= nil
end

return std_names
