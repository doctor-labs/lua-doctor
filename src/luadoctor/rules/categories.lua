-- The category a warning code belongs to, read from its number. The ranges are
-- the sections of docs/rules.md, so a new code lands in a category without an
-- edit here, and a spec checks that every registered code has one.
local categories = {}

local ORDER = {"exec", "firmware", "payload", "artifact", "meta"}

-- `lint` is opt-in (see rules/lint_gate.lua) and is listed only when a report has
-- one, so a default run's category counts are the five above and nothing else.
local TITLES = {
   lint = "lint: undefined names and standard-library misuse",
   exec = "execution and dynamic code",
   firmware = "firmware specific",
   payload = "payload and backdoor",
   artifact = "artifact and bytecode",
   meta = "suppression and coverage",
}

--- The category id for a code, or nil for a number outside every range.
function categories.of(code)
   local n = tonumber(code)
   if not n then return nil end
   if n >= 700 and n <= 719 then return "exec" end
   if n >= 720 and n <= 739 then return "firmware" end
   if n >= 740 and n <= 799 then return "payload" end
   if n >= 800 and n <= 899 then return "artifact" end
   if n >= 950 and n <= 979 then return "lint" end
   if n < 100 or (n >= 900 and n <= 949) then return "meta" end
   return nil
end

--- Every category id, in the order a report lists them. Pass the counts of a
-- report to include `lint`, which is listed only when it has findings.
function categories.order(counts)
   local out = {table.unpack(ORDER)}
   if counts and (counts.lint or 0) > 0 then out[#out + 1] = "lint" end
   return out
end

function categories.title(id)
   return TITLES[id]
end

return categories
