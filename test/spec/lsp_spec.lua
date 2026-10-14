local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match = harness.assert_equal, harness.assert_match

-- `lua-doctor lsp` speaks LSP framing (Content-Length headers, JSON-RPC bodies) on
-- stdin and stdout. Each test feeds framed messages through the CLI and matches
-- the framed replies, so only the public CLI seam is used.
local function frame(body)
   return ("Content-Length: %d\r\n\r\n%s"):format(#body, body)
end

local function session(messages, opts)
   local input = {}
   for _, body in ipairs(messages) do input[#input + 1] = frame(body) end
   opts = opts or {}
   opts.stdin = table.concat(input)
   return harness.cli({"lsp"}, opts)
end

local INITIALIZE = [[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"processId":null,"capabilities":{}}}]]
local INITIALIZED = [[{"jsonrpc":"2.0","method":"initialized","params":{}}]]
local BAD_OPEN = [[{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///w/a.lua","languageId":"lua","version":1,"text":"local x = os.execute(arg[1])\nprint(x)\n"}}}]]
local CLEAN_CHANGE = [[{"jsonrpc":"2.0","method":"textDocument/didChange","params":{"textDocument":{"uri":"file:///w/a.lua","version":2},"contentChanges":[{"text":"print(1)\n"}]}}]]
local CLOSE = [[{"jsonrpc":"2.0","method":"textDocument/didClose","params":{"textDocument":{"uri":"file:///w/a.lua"}}}]]
local SHUTDOWN = [[{"jsonrpc":"2.0","id":2,"method":"shutdown"}]]
local EXIT = [[{"jsonrpc":"2.0","method":"exit"}]]

describe("lua-doctor lsp", function()
   it("answers initialize with full-text document sync and the server name", function()
      local out = session({INITIALIZE, INITIALIZED, SHUTDOWN, EXIT})
      assert_match(out, '"textDocumentSync"%s*:%s*1', out)
      assert_match(out, '"name"%s*:%s*"lua%-doctor"', out)
   end)

   it("publishes a finding from an opened document as an LSP diagnostic", function()
      local out = session({INITIALIZE, INITIALIZED, BAD_OPEN, SHUTDOWN, EXIT})
      assert_match(out, '"method"%s*:%s*"textDocument/publishDiagnostics"', out)
      assert_match(out, '"uri"%s*:%s*"file:///w/a%.lua"', out)
      assert_match(out, '"code"%s*:%s*"701"', out)
      assert_match(out, '"source"%s*:%s*"lua%-doctor"', out)
      assert_match(out, '"severity"%s*:%s*1', out)
      assert_match(out, '"character"%s*:%s*10[,}]', out)
      assert_match(out, '"character"%s*:%s*28[,}]', out)
      assert_match(out, '"line"%s*:%s*0[,}]', out)
   end)

   it("republishes an empty list once a change removes the finding", function()
      local out = session({INITIALIZE, INITIALIZED, BAD_OPEN, CLEAN_CHANGE, SHUTDOWN, EXIT})
      assert_match(out, '"diagnostics"%s*:%s*%[%]', out)
   end)

   it("clears the diagnostics of a document that is closed", function()
      local out = session({INITIALIZE, INITIALIZED, BAD_OPEN, CLOSE, SHUTDOWN, EXIT})
      assert_match(out, '"diagnostics"%s*:%s*%[%]', out)
   end)

   it("exits with code 0 after shutdown and exit", function()
      local _, code = session({INITIALIZE, INITIALIZED, SHUTDOWN, EXIT})
      assert_equal(code, 0)
   end)

   it("answers a request for an unknown method with method not found and keeps serving", function()
      local out = session({[[{"jsonrpc":"2.0","id":7,"method":"textDocument/hover","params":{}}]],
         INITIALIZE, SHUTDOWN, EXIT})
      assert_match(out, '"code"%s*:%s*%-32601', out)
      assert_match(out, '"textDocumentSync"', out)
   end)

   it("rejects a message with no Content-Length and keeps serving", function()
      local out = harness.cli({"lsp"}, {stdin = "Bogus-Header: 1\r\n\r\n" .. frame(INITIALIZE) .. frame(EXIT)})
      assert_match(out, '"code"%s*:%s*%-32600', out)
      assert_match(out, '"textDocumentSync"', out)
   end)

   it("rejects a message larger than 8 MiB with a JSON-RPC error and exits with code 2", function()
      local out, code = harness.cli({"lsp"}, {stdin = "Content-Length: 8388609\r\n\r\n"})
      assert_match(out, '"code"%s*:%s*%-32600', out)
      assert_equal(code, 2, out)
   end)

   it("answers a body nested deeper than 64 levels with a parse error and keeps serving", function()
      local deep = ("["):rep(70) .. ("]"):rep(70)
      local out = session({('{"jsonrpc":"2.0","id":9,"method":"initialize","params":%s}'):format(deep),
         INITIALIZE, EXIT})
      assert_match(out, '"code"%s*:%s*%-32700', out)
      assert_match(out, '"textDocumentSync"', out)
   end)
end)
