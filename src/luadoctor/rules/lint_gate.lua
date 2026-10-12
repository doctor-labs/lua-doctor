-- The lint family (950-981, 999-1002) is opt-in.
-- These codes are about names and library use, not about a flow, and a firmware
-- tree reports them by the thousand (every global a platform provides and the
-- std does not list). On by default they would move every score and every exit
-- code, so they run only when the operator asks: `--category lint`, or a
-- `--enable`/`--only` pattern that starts a lint code (`--enable 95`), on the
-- command line or in the library options.
local lint_gate = {}

local function names(list)
   return type(list) == "table" and list or {}
end

--- Should the lint rule that emits `code` run under these options?
function lint_gate.wanted(opts, code)
   opts = opts or {}
   for _, category in ipairs(names(opts.category)) do
      if category == "lint" then return true end
   end
   for _, key in ipairs({"enable", "only"}) do
      for _, pattern in ipairs(names(opts[key])) do
         local code_pattern = type(pattern) == "string" and pattern:match("^([^:]*)") or ""
         if code_pattern ~= "" then
            local ok, hit = pcall(string.match, code, "^" .. code_pattern)
            if ok and hit then return true end
         end
      end
   end
   return false
end

return lint_gate
