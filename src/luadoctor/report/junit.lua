-- JUnit XML report. One <testcase> per finding, each carrying a <failure> so a
-- JUnit reader counts lua-doctor findings as failures on the named testcase.
-- Every string sourced from an analyzed file is XML-escaped: a scanned file is
-- untrusted input, and a report that pastes a message into an attribute value
-- unescaped breaks the document for every consumer.
--
-- The testcase name is "<file>:<line>:<column> [<code>]" so a reader can jump
-- straight to the site of the finding.
local contract = require "luadoctor.report.findings"
local sanitize = require("luadoctor.util.util").sanitize

local junit = {}

local function esc(value)
   return (tostring(value)
      :gsub("&", "&amp;")
      :gsub("<", "&lt;")
      :gsub(">", "&gt;")
      :gsub('"', "&quot;"))
end

function junit.render(list)
   list = contract.normalize(list) or list
   local memo = {}
   local buffer = {
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<testsuites>',
      ('  <testsuite name="lua-doctor" tests="%d" failures="%d">'):format(#list, #list),
   }

   for _, finding in ipairs(list) do
      local file = contract.open_file(finding, memo) or ""
      local name = ("%s:%s:%s [%s]"):format(
         sanitize(file), tostring(finding.line), tostring(finding.column),
         sanitize(finding.code))
      buffer[#buffer + 1] = (
         '    <testcase classname="%s" name="%s">'
         .. '<failure type="%s" message="%s"/></testcase>'):format(
         esc(sanitize(file)), esc(name),
         esc(sanitize(finding.code)), esc(sanitize(finding.message or "")))
   end

   buffer[#buffer + 1] = "  </testsuite>"
   buffer[#buffer + 1] = "</testsuites>"

   return table.concat(buffer, "\n")
end

return junit
