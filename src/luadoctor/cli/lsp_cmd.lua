-- `lua-doctor lsp`: a minimal Language Server Protocol server on stdio. Messages are
-- framed with Content-Length headers and carry JSON-RPC 2.0 bodies. Full-text sync:
-- every didOpen, didChange and didSave re-runs the per-file analysis on the document
-- as the editor holds it, and publishes the findings as textDocument/publishDiagnostics.
-- Nothing is read from disk, so an unsaved buffer is analyzed as typed.
--
-- ponytail: the JSON decoder below is a small bounded one local to this module; it
-- can be swapped for util/json.lua once that lands.
local json = require "luadoctor.report.json"
local api = require "luadoctor.api"
local version = require "luadoctor.version"

local lsp = {}

local EXIT_CLEAN, EXIT_FAILED, EXIT_ERROR = 0, 1, 2
local MAX_BODY = 8 * 1024 * 1024
local MAX_HEADER_LINE = 4096
local MAX_DEPTH = 64

-- LSP: 1 Error, 2 Warning, 3 Information, 4 Hint. A finding that would stop a build
-- is an Error; a low finding is only information.
local SEVERITY = {critical = 1, high = 1, medium = 2, low = 3, info = 4}

local SIMPLE_ESCAPES = {['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f",
   n = "\n", r = "\r", t = "\t"}

-- Bounded JSON decoder. Raises a string on malformed input or nesting deeper than
-- MAX_DEPTH, so one bad body cannot exhaust the stack.
local function decode(text)
   local pos = 1
   local parse_value

   local function fail(message) error(message, 0) end
   local function skip() pos = text:find("[^ \t\r\n]", pos) or #text + 1 end

   local function parse_string()
      local out, i = {}, pos + 1
      while true do
         local j = text:find('["\\%c]', i)
         if not j then fail("unterminated string") end
         out[#out + 1] = text:sub(i, j - 1)
         local ch = text:sub(j, j)
         if ch == '"' then
            pos = j + 1
            return table.concat(out)
         end
         if ch ~= "\\" then fail("control character in string") end
         local esc = text:sub(j + 1, j + 1)
         if esc == "u" then
            local code = tonumber(text:match("^%x%x%x%x", j + 2) or "", 16)
            if not code then fail("bad unicode escape") end
            i = j + 6
            if code >= 0xD800 and code <= 0xDFFF then
               local low = tonumber(text:match("^\\u(%x%x%x%x)", i) or "", 16)
               if code <= 0xDBFF and low and low >= 0xDC00 and low <= 0xDFFF then
                  code = 0x10000 + (code - 0xD800) * 0x400 + (low - 0xDC00)
                  i = i + 6
               else
                  code = 0xFFFD
               end
            end
            out[#out + 1] = utf8.char(code)
         else
            local replacement = SIMPLE_ESCAPES[esc]
            if not replacement then fail("bad escape") end
            out[#out + 1] = replacement
            i = j + 2
         end
      end
   end

   parse_value = function(depth)
      skip()
      local c = text:sub(pos, pos)
      if c == '"' then
         return parse_string()
      elseif c == "{" or c == "[" then
         if depth > MAX_DEPTH then fail("nested deeper than " .. MAX_DEPTH .. " levels") end
         pos = pos + 1
         local container, closer = {}, c == "{" and "}" or "]"
         skip()
         if text:sub(pos, pos) == closer then
            pos = pos + 1
            return container
         end
         while true do
            if c == "{" then
               skip()
               if text:sub(pos, pos) ~= '"' then fail("expected a key") end
               local key = parse_string()
               skip()
               if text:sub(pos, pos) ~= ":" then fail("expected ':'") end
               pos = pos + 1
               container[key] = parse_value(depth + 1)
            else
               container[#container + 1] = parse_value(depth + 1)
            end
            skip()
            local separator = text:sub(pos, pos)
            pos = pos + 1
            if separator == closer then return container end
            if separator ~= "," then fail("expected ',' or a closing bracket") end
         end
      elseif text:sub(pos, pos + 3) == "true" then
         pos = pos + 4
         return true
      elseif text:sub(pos, pos + 4) == "false" then
         pos = pos + 5
         return false
      elseif text:sub(pos, pos + 3) == "null" then
         pos = pos + 4
         return json.null
      end
      local number = text:match("^-?%d+%.?%d*[eE]?[-+]?%d*", pos)
      if not number or not tonumber(number) then fail("unexpected character at " .. pos) end
      pos = pos + #number
      return tonumber(number)
   end

   local result = parse_value(1)
   skip()
   if pos <= #text then fail("trailing characters after the value") end
   return result
end

local function send(output, message)
   message.jsonrpc = "2.0"
   local body = json.encode(message, false)
   output:write(("Content-Length: %d\r\n\r\n%s"):format(#body, body))
   output:flush()
end

-- The next body. Returns nil alone at end of input; returns nil, a message and
-- whether the stream is unrecoverable when the framing is bad. A bad header block
-- is consumed through its blank line, so the next message still lines up.
local function read_message(input)
   local length
   repeat
      local line = input:read("L")
      if line == nil then return nil end
      if #line > MAX_HEADER_LINE then return nil, "header line longer than 4 KiB", true end
      line = (line:gsub("\r?\n$", ""))
      local name, value = line:match("^([^:]+):%s*(.-)%s*$")
      if name and name:lower() == "content-length" then length = value end
   until line == ""

   if length == nil then return nil, "missing Content-Length header" end
   if not length:match("^%d+$") then return nil, "Content-Length is not a number" end
   local size = tonumber(length)
   if size > MAX_BODY then return nil, "message larger than 8 MiB", true end
   local body = size == 0 and "" or input:read(size)
   if body == nil or #body < size then return nil end
   return body
end

-- Findings as LSP diagnostics. Columns are bytes, which matches LSP only on ASCII
-- lines. ponytail: UTF-16 position encoding is not converted.
-- A failed analysis publishes nothing rather than ending the session.
local function diagnostics_for(text)
   local diagnostics = {}
   local ok, findings = pcall(api.check_source, text, {})
   if not ok then return diagnostics end
   for _, finding in ipairs(findings) do
      local line = (finding.line or 1) - 1
      local start = math.max((finding.column or 1) - 1, 0)
      local stop = finding.end_column or start + 1
      if stop <= start then stop = start + 1 end
      diagnostics[#diagnostics + 1] = {
         range = {start = {line = line, character = start}, ["end"] = {line = line, character = stop}},
         severity = SEVERITY[finding.severity] or 2,
         code = finding.code,
         source = "lua-doctor",
         message = finding.message,
      }
   end
   return diagnostics
end

local function publish(state, uri)
   local text = state.docs[uri]
   send(state.output, {method = "textDocument/publishDiagnostics",
      params = {uri = uri, diagnostics = text and diagnostics_for(text) or {}}})
end

local function document(state, method, params)
   local document_params = type(params.textDocument) == "table" and params.textDocument or {}
   local uri = document_params.uri
   if type(uri) ~= "string" then return nil end
   if method == "textDocument/didClose" then
      state.docs[uri] = nil
   else
      local text
      if method == "textDocument/didOpen" then
         text = document_params.text
      elseif method == "textDocument/didChange" then
         local changes = params.contentChanges
         local last = type(changes) == "table" and changes[#changes]
         text = type(last) == "table" and last.text or nil
      else
         text = params.text
      end
      if type(text) == "string" then state.docs[uri] = text end
   end
   publish(state, uri)
   return nil
end

-- Returns a result, or nil plus a JSON-RPC error code and message. Notifications
-- get no reply, so their return values are dropped by the caller.
local function handle(state, request)
   local method = request.method
   local params = type(request.params) == "table" and request.params or {}
   if method == "initialize" then
      return {capabilities = {textDocumentSync = 1},
         serverInfo = {name = "lua-doctor", version = version.luadoctor}}
   elseif method == "initialized" then
      return nil
   elseif method == "shutdown" then
      state.shutdown = true
      return json.null
   elseif method == "exit" then
      state.exit = true
      return nil
   elseif method == "textDocument/didOpen" or method == "textDocument/didChange"
      or method == "textDocument/didSave" or method == "textDocument/didClose" then
      return document(state, method, params)
   end
   return nil, -32601, "method not found: " .. tostring(method)
end

-- Serve until exit or end of input. Returns the process exit code: 0 after shutdown
-- then exit, 1 for exit without shutdown, 2 when the framing is unrecoverable.
local function serve(input, output)
   local state = {docs = {}, output = output}
   while true do
      local body, problem, fatal = read_message(input)
      if body == nil and problem == nil then break end
      if problem then
         send(output, {id = json.null, error = {code = -32600, message = problem}})
         if fatal then return EXIT_ERROR end
      else
         local ok, request = pcall(decode, body)
         if not ok then
            send(output, {id = json.null, error = {code = -32700, message = "parse error: " .. tostring(request)}})
         elseif type(request) ~= "table" or type(request.method) ~= "string" then
            send(output, {id = json.null, error = {code = -32600, message = "invalid request"}})
         else
            local dispatched, result, code, message = pcall(handle, state, request)
            if not dispatched then
               code, message = -32603, "internal error"
               result = nil
            end
            if request.id ~= nil then
               if code then
                  send(output, {id = request.id, error = {code = code, message = message}})
               else
                  send(output, {id = request.id, result = result == nil and json.null or result})
               end
            end
         end
         if state.exit then break end
      end
   end
   return state.shutdown and EXIT_CLEAN or EXIT_FAILED
end

lsp.serve = serve

function lsp.run()
   return serve(io.stdin, io.stdout)
end

return lsp
