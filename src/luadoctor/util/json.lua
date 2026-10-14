-- Minimal JSON decoder for --rules declarations. Data only: nothing runs.
-- json.decode(text) returns the decoded value, or nil plus a message with the
-- byte offset. null is dropped from objects and rejected inside lists.
-- Input over 1 MiB, or nesting deeper than 64, is refused.
local json = {}

local NULL = {}
local MAX_DEPTH = 64
local MAX_BYTES = 1024 * 1024
local ESCAPES = {['"'] = '"', ["\\"] = "\\", ["/"] = "/",
   b = "\b", f = "\f", n = "\n", r = "\r", t = "\t"}

function json.decode(text)
   if #text > MAX_BYTES then
      return nil, ("input is larger than %d bytes"):format(MAX_BYTES)
   end
   local pos = 1
   local function fail(message)
      error({json_error = ("%s at byte %d"):format(message, pos)}, 0)
   end
   local function skip()
      pos = text:find("[^ \t\r\n]", pos) or (#text + 1)
   end

   local value

   local function parse_string()
      local out, i = {}, pos + 1
      while true do
         local j = text:find('["\\%c]', i)
         if not j then pos = #text + 1; fail("unterminated string") end
         out[#out + 1] = text:sub(i, j - 1)
         local c = text:sub(j, j)
         if c == '"' then
            pos = j + 1
            return table.concat(out)
         elseif c == "\\" then
            local e = text:sub(j + 1, j + 1)
            if e == "u" and text:match("^%x%x%x%x", j + 2) then
               out[#out + 1] = utf8.char(tonumber(text:sub(j + 2, j + 5), 16))
               i = j + 6
            elseif ESCAPES[e] then
               out[#out + 1] = ESCAPES[e]
               i = j + 2
            else
               pos = j
               fail("bad escape")
            end
         else
            pos = j
            fail("control character in string")
         end
      end
   end

   local function parse_list(depth)
      if depth > MAX_DEPTH then fail("nested deeper than " .. MAX_DEPTH) end
      pos = pos + 1
      local list = {}
      skip()
      if text:sub(pos, pos) == "]" then pos = pos + 1; return list end
      while true do
         local item = value(depth)
         if item == NULL then fail("null is not allowed in a list") end
         list[#list + 1] = item
         skip()
         local c = text:sub(pos, pos)
         pos = pos + 1
         if c == "]" then return list end
         if c ~= "," then pos = pos - 1; fail("expected ',' or ']'") end
      end
   end

   local function parse_object(depth)
      if depth > MAX_DEPTH then fail("nested deeper than " .. MAX_DEPTH) end
      pos = pos + 1
      local object = {}
      skip()
      if text:sub(pos, pos) == "}" then pos = pos + 1; return object end
      while true do
         skip()
         if text:sub(pos, pos) ~= '"' then fail("expected a string key") end
         local key = parse_string()
         skip()
         if text:sub(pos, pos) ~= ":" then fail("expected ':'") end
         pos = pos + 1
         local item = value(depth)
         if item ~= NULL then object[key] = item end
         skip()
         local c = text:sub(pos, pos)
         pos = pos + 1
         if c == "}" then return object end
         if c ~= "," then pos = pos - 1; fail("expected ',' or '}'") end
      end
   end

   value = function(depth)
      skip()
      local c = text:sub(pos, pos)
      if c == "{" then return parse_object(depth + 1) end
      if c == "[" then return parse_list(depth + 1) end
      if c == '"' then return parse_string() end
      if text:sub(pos, pos + 3) == "true" then pos = pos + 4; return true end
      if text:sub(pos, pos + 4) == "false" then pos = pos + 5; return false end
      if text:sub(pos, pos + 3) == "null" then pos = pos + 4; return NULL end
      local number = text:match("^-?%d+%.?%d*[eE][+-]?%d+", pos)
         or text:match("^-?%d+%.?%d*", pos)
      if number then
         pos = pos + #number
         return tonumber(number)
      end
      fail("unexpected character")
   end

   local ok, result = pcall(function()
      local decoded = value(0)
      skip()
      if pos <= #text then fail("trailing data") end
      if decoded == NULL then return nil end
      return decoded
   end)
   if ok then return result end
   if type(result) == "table" and result.json_error then return nil, result.json_error end
   error(result, 0)
end

return json
