-- TAP (Test Anything Protocol) version 13 report. One "not ok" row per finding,
-- so a CI consumer that already parses TAP can surface lua-doctor findings without
-- a custom parser. A report with nothing to say says so: "1..0" rather than an empty
-- stream, which a TAP reader treats as a failure, not as clean.
local sanitize = require("luadoctor.util.util").sanitize
local contract = require "luadoctor.report.findings"

local tap = {}

function tap.render(list)
   local memo = {}
   local buffer = {"TAP version 13"}

   buffer[#buffer + 1] = ("1..%d"):format(#list)

   for i, finding in ipairs(list) do
      local file = contract.open_file(finding, memo)
      local label = file and (sanitize(file) .. ":" .. tostring(finding.line) .. ":" ..
         tostring(finding.column)) or "lua-doctor"
      buffer[#buffer + 1] = ("not ok %d - %s [%s] %s"):format(i, label,
         sanitize(finding.code), sanitize(finding.message or ""))
   end

   return table.concat(buffer, "\n")
end

return tap
