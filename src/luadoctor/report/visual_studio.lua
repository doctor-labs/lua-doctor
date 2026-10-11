-- Visual Studio / msbuild-style report. One line per finding, in the shape
-- "<file>(<line>,<column>) : <error|warning> <code>: <message>" so a build that
-- parses compiler output can surface lua-doctor findings without a custom parser.
-- Severity "critical" and "high" are errors; everything else is a warning.
local contract = require "luadoctor.report.findings"
local sanitize = require("luadoctor.util.util").sanitize

local visual_studio = {}

function visual_studio.render(list)
   list = contract.normalize(list) or list
   local memo = {}
   local buffer = {}

   for _, finding in ipairs(list) do
      local file = contract.open_file(finding, memo) or ""
      local kind = (finding.severity == "critical" or finding.severity == "high")
         and "error" or "warning"
      buffer[#buffer + 1] = ("%s(%s,%s) : %s %s: %s"):format(
         sanitize(file), tostring(finding.line), tostring(finding.column),
         kind, sanitize(finding.code), sanitize(finding.message or ""))
   end

   return table.concat(buffer, "\n")
end

return visual_studio
