-- `--cache FILE`: the per-file results of a scan, kept between runs.
--
-- A file's findings depend only on its own text and the options the run was
-- given (a cross-file pass is the exception, and --whole-program is never cached).
-- So a result is reused when the file's content digest matches the one stored
-- with it, and the run's option fingerprint matches the cache's. Anything else
-- is analyzed again. The cache is one JSON file, the same shape a `--json`
-- report uses for findings, and a file that cannot be read or parsed is treated
-- as empty: a cache is never the reason a run fails.
local json = require "luadoctor.report.json"
local findings = require "luadoctor.report.findings"
local version = require "luadoctor.version"

local results_cache = {}

local SCHEMA = "lua-doctor-cache/1"

-- Options that say how the run is driven, not what a file's findings are.
local NOT_OPTIONS = {paths = true, cache = true, jobs = true, on_file = true, on_phase = true}

-- ponytail: a 64-bit FNV digest, not a cryptographic hash. A collision serves a
-- stale result; use sha256 if the cache ever needs to be trusted across machines.
function results_cache.digest(source)
   return findings.fnv1a(source)
end

-- A canonical text of the options and the tool version, so two runs with the
-- same settings produce the same key whatever order their tables were built in.
local function canonical(value)
   if type(value) ~= "table" then
      return type(value) .. ":" .. tostring(value)
   end
   local keys = {}
   for key, entry in pairs(value) do
      if type(entry) ~= "function" and not NOT_OPTIONS[key] then
         keys[#keys + 1] = key
      end
   end
   table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
   local parts = {}
   for _, key in ipairs(keys) do
      parts[#parts + 1] = tostring(key) .. "=" .. canonical(value[key])
   end
   return "{" .. table.concat(parts, ",") .. "}"
end

function results_cache.key(opts)
   return findings.fnv1a(canonical({version = version, opts = opts}))
end

-- The saved per-file entries ({digest, findings, writes} keyed by path) for
-- this option key, or an empty table when there is nothing usable.
function results_cache.load(path, key)
   local handle = io.open(path, "rb")
   if not handle then return {} end
   local text = handle:read("*a")
   handle:close()
   local ok, document = pcall(findings.decode, text)
   if not ok or type(document) ~= "table" or document.schema ~= SCHEMA or document.key ~= key
      or type(document.files) ~= "table" then
      return {}
   end
   return document.files
end

-- Writes the entries for the paths in this run. A cache that cannot be written
-- costs the next run its speed, not this run its report, so it says so and goes on.
function results_cache.store(path, key, files)
   local handle, open_error = io.open(path, "wb")
   if not handle then
      io.stderr:write("lua-doctor: cannot write cache " .. path .. ": " .. tostring(open_error) .. "\n")
      return
   end
   handle:write(json.encode({schema = SCHEMA, key = key, files = files}))
   handle:close()
end

return results_cache
