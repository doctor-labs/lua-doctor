-- Rule module: lint.
--
-- Names, judged the way luacheck judges them. luacheck's detect_globals stage
-- (vendored, unmodified) records every global access and set with the fields
-- indexed from it; this module decides, against the std, which of those are
-- findings and gives each luacheck code its lua-doctor code.
--
--   951  accessing an undefined variable        (luacheck 113, selene undefined_variable)
--        With allow_defined, a global the file assigns is defined where it is
--        read, as selene (and luacheck's option of that name) have it.
--   952  setting or mutating a non-standard global (luacheck 111, 112)
--   953  setting a read-only global or a field of one (luacheck 121, 122)
--   954  setting or accessing an undefined field of a global (luacheck 142, 143)
--   957  more arguments than the callee takes  (selene mismatched_arg_count)
--   958  standard library misuse                (selene incorrect_standard_library_use):
--        too few required arguments, a literal of the wrong type, an unused result
--   959  duplicate key in a table constructor    (selene duplicate_keys)
--   960  comparing with NaN                     (selene compare_nan)
--   961  comparing with a table constructor     (selene constant_table_comparison)
--   962  two assignments that look like a broken swap (selene almost_swapped)
--   963  empty if branch                         (luacheck 542, selene empty_if)
--   964  empty loop body                         (selene empty_loop)
--   965  reversed numeric for                    (luacheck 571, selene suspicious_reverse_loop)
--   966  two branches of an if do the same thing      (selene if_same_then_else)
--   967  an elseif repeats an earlier condition         (selene ifs_same_cond)
--   968  a table constructor mixes positional and keyed entries (selene mixed_table)
--   969  unbalanced assignment               (luacheck 531/532, selene unbalanced_assignments):
--        a local or plain assignment with values where names and values differ,
--        when the last value is not a call or ...
--   970  parenthesized condition              (selene parenthese_conditions):
--        the whole condition of an if, elseif, while or until is one parenthesized expression
--   971  unused label                          (luacheck 521): a named label no
--        `goto` in the same function jumps to
--   972  division by zero                       (selene divide_by_zero): a `/` or `%`
--        whose right operand is the literal 0 (or folds to it), except the NaN idiom 0/0
--   973  line too long                          (luacheck 631): a line longer than 120 characters
--   974  empty statement                        (luacheck 551, selene empty_statement): a stray `;`
--   975  multiple statements on one line        (selene multiple_statements): more than one
--        statement begins on the same line, within one block
--   976  trailing whitespace                    (luacheck 611/612/613/614): a line whose
--        text ends in a space or tab, except inside a multi-line string (whose spaces
--        are part of the value)
--   977  indentation has a space before a tab   (luacheck 621): the leading whitespace of
--        a line contains a space immediately followed by a tab
--   978  use of _G                                (selene global_usage): reading or
--        writing the global table `_G` directly, or indexing it, instead of a
--        local table (a local named `_G` shadows the global and is not reported)
--   979  a comparison inside type()              (selene type_check_inside_call): type()
--        is called with a comparison expression (e.g. type(x == "s")) as its argument
--        instead of comparing type(x) to a string literal
--   982  unused local                              (luacheck 211): a local or local
--        function that is bound but never read in its scope
--   983  unused function argument                  (luacheck 212): a named parameter
--        that is never read (`...` and `self` are not flagged)
--   984  unused loop variable                       (luacheck 213): a generic for key/value
--        or a numeric for counter that is never read (`_` is not flagged)
--
--   981  module-level global assigned but never read (luacheck 131)
--
-- Opt-in: see rules/lint_gate.lua. Code range 950-984.
local M = {}

local detect_globals = require "luacheck.stages.detect_globals"
local std_names = require "luadoctor.registry.std_names"
local platform_api = require "luadoctor.registry.platform_api"
local lint_gate = require "luadoctor.rules.lint_gate"

local detectors = {}

-- luacheck code -> the lua-doctor code that reports it, and the `action` its
-- message names.
local EMITTED = {
   ["113"] = {code = "951"},
   ["111"] = {code = "952", action = "setting"},
   ["112"] = {code = "952", action = "mutating"},
   ["121"] = {code = "953", action = "setting"},
   ["122"] = {code = "953", action = "setting a field of"},
   ["142"] = {code = "954", action = "setting"},
   ["143"] = {code = "954", action = "accessing"},
}

-- The raw warnings of detect_globals, once per file: several lint rules read
-- them and the stage records into the check state.
local function raw_warnings(chstate)
   if chstate.lint_globals then return chstate.lint_globals end
   local raw = {}
   if chstate.resolved_locals then
      local before = #chstate.warnings
      detect_globals.run(chstate)
      for i = before + 1, #chstate.warnings do raw[#raw + 1] = chstate.warnings[i] end
      for i = #chstate.warnings, before + 1, -1 do chstate.warnings[i] = nil end
   end
   chstate.lint_globals = raw
   return raw
end

-- luacheck's classification of one raw 111/112/113 warning: its final code, or
-- nil when the std says the name is fine. See luacheck's filter.lua.
local function classify(std, warning)
   local code = warning.code
   local full = std_names.field_status(std, warning.name, warning.indexing)

   if (code == "111" or code == "112") and full == "read_only" then
      return "12" .. code:sub(3, 3)
   end
   if (code == "112" or code == "113")
         and std_names.field_status(std, warning.name, warning.indexing, 1) ~= "undefined" then
      code = "14" .. code:sub(3, 3)
   end

   if warning.indirect and warning.previous_indexing_len
         and std_names.field_status(std, warning.name, warning.indexing,
            warning.previous_indexing_len) == "undefined" then
      return nil
   end
   if full ~= "undefined" then return nil end
   return code
end

local function span(ctx, warning)
   local start = (ctx.chstate.line_offsets[warning.line] or 0) + warning.column - 1
   return {line = warning.line, offset = start,
      end_offset = start + math.max(0, (warning.end_column or warning.column) - warning.column)}
end

-- `os.execte`: the global and the fields indexed from it, as far as they are
-- literal names (an unknown key is written `?`).
local function field_path(warning)
   local parts = {warning.name}
   for _, key in ipairs(warning.indexing or {}) do
      parts[#parts + 1] = type(key) == "string" and key or "?"
   end
   return table.concat(parts, ".")
end

-- luacheck's allow_defined: every whole-name set defines the global. A defined
-- name is no longer undefined to read (113) or mutate (112), and its defining
-- set is not a finding (luacheck calls an unread one 131, unused global, which
-- lua-doctor does not report).
local function defined_in_file(raw)
   local defined = {}
   for _, warning in ipairs(raw) do
      if warning.code == "111" then defined[warning.name] = true end
   end
   return defined
end

-- selene's "this might be a name from another standard library" note, for the
-- built-in profiles that do define it.
local function note_for(name)
   local profiles_found = std_names.profiles_defining(name)
   if #profiles_found == 0 then return "" end
   return ("; defined by --std +%s"):format(table.concat(profiles_found, " or +"))
end

local function detect_names(ctx)
   local wanted = {}
   local any = false
   for luacheck_code, target in pairs(EMITTED) do
      if lint_gate.wanted(ctx.opts, target.code) then
         wanted[luacheck_code] = target
         any = true
      end
   end
   if not any then return end

   local std = std_names.current(ctx.opts)
   local raw = raw_warnings(ctx.chstate)
   local defined = ctx.opts.allow_defined and defined_in_file(raw) or {}
   for _, warning in ipairs(raw) do
      local luacheck_code = not defined[warning.name] and classify(std, warning)
      local target = luacheck_code and wanted[luacheck_code]
      if target then
         ctx:emit(target.code, span(ctx, warning),
            {name = target.code == "954" and field_path(warning) or warning.name, action = target.action,
               note = target.code == "951" and note_for(warning.name) or nil})
      end
   end
end

detectors[#detectors + 1] = detect_names

-- ---------------------------------------------------------------- 957

-- Every call expression with the statement it sits in, nested ones included. A
-- function body is its own line, so it is not entered.
local function each_call(chstate, visit)
   local function walk(node, item, depth)
      if type(node) ~= "table" or depth > 64 or node.tag == "Function" then return end
      if node.tag == "Call" then visit(node, item) end
      for _, child in ipairs(node) do
         if type(child) == "table" then walk(child, item, depth + 1) end
      end
   end
   for _, line in ipairs(chstate.lines) do
      for _, item in ipairs(line.items) do
         if item.tag == "Eval" then
            walk(item.node, item, 0)
         elseif item.tag == "Local" or item.tag == "Set" then
            for _, value in ipairs(item.rhs or {}) do walk(value, item, 0) end
         end
      end
   end
end

-- The arguments a call passes, and whether the last of them can expand into
-- several values (a call, `...`), in which case the count is a floor.
local function call_arguments(node)
   local args = {}
   for index = 2, #node do args[#args + 1] = node[index] end
   return args
end

-- How many arguments a local function takes, or nil when it is unknown or
-- takes any number: every definition that can reach the call must be a plain
-- function, and the most generous one decides (selene's "best overlap").
local function local_arity(callee, item)
   if callee.tag ~= "Id" or not callee.var or not item or not item.used_values then return nil end
   local values = item.used_values[callee.var]
   if not values or #values == 0 then return nil end
   local most = 0
   for _, value in ipairs(values) do
      local fn = value.node
      if not fn or fn.tag ~= "Function" then return nil end
      local count = 0
      for _, formal in ipairs(fn[1] or {}) do
         if formal.tag == "Dots" then return nil end
         count = count + 1
      end
      if count > most then most = count end
   end
   return most
end

local function detect_arg_count(ctx)
   if not lint_gate.wanted(ctx.opts, "957") then return end
   each_call(ctx.chstate, function(node, item)
      local args = call_arguments(node)
      local given = #args

      local path = ctx:path_of(node[1])
      local params = path and platform_api.params_for(path)
      local most
      if params then
         most = params[#params] ~= "..." and #params or nil
      else
         most = local_arity(node[1], item)
         path = path or (node[1].tag == "Id" and node[1][1]) or nil
      end

      if most and path and given > most then
         ctx:emit("957", node, {name = path, max = most, given = given})
      end
   end)
end

detectors[#detectors + 1] = detect_arg_count

-- ---------------------------------------------------------------- 958

-- Functions whose only effect is their result, so calling one as a statement
-- discards the whole call (selene's `must_use`).
local MUST_USE = {}
for _, path in ipairs({
   "tostring", "tonumber", "type", "rawequal", "rawget", "rawlen", "getmetatable",
   "string.byte", "string.char", "string.find", "string.format", "string.gsub", "string.len",
   "string.lower", "string.match", "string.rep", "string.reverse", "string.sub", "string.upper",
   "table.concat", "table.unpack", "unpack",
   "math.abs", "math.ceil", "math.floor", "math.sqrt", "math.max", "math.min", "math.fmod",
   "os.time", "os.clock", "os.date", "os.getenv", "os.difftime",
}) do MUST_USE[path] = true end

-- The kind of value an argument is when it is a literal, else nil.
local LITERAL_KIND = {String = "string", Number = "number", True = "boolean", False = "boolean",
   Nil = "nil", Table = "table", Function = "function"}

local function literal_kind(node)
   return type(node) == "table" and LITERAL_KIND[node.tag] or nil
end

-- Does a literal of `kind` fail a parameter of type `expected`? Lua coerces
-- between numbers and strings, so only a string that is not a number fails a
-- `number`.
local function type_mismatch(expected, kind, node)
   if expected == "any" then return false end
   if expected == "string" then
      return kind == "boolean" or kind == "nil" or kind == "table" or kind == "function"
   elseif expected == "number" then
      if kind == "string" then return tonumber(node[1]) == nil end
      return kind == "boolean" or kind == "nil" or kind == "table" or kind == "function"
   elseif expected == "table" then
      return kind ~= "table"
   elseif expected == "function" then
      return kind ~= "function"
   end
   return false
end

local ARTICLE = {string = "a string", number = "a number", table = "a table", ["function"] = "a function",
   boolean = "a boolean", ["nil"] = "nil"}

local function detect_stdlib_misuse(ctx)
   if not lint_gate.wanted(ctx.opts, "958") then return end

   each_call(ctx.chstate, function(node, item)
      local path = ctx:path_of(node[1])
      local params = path and platform_api.params_for(path)
      if not params then return end
      local args = call_arguments(node)
      local last = args[#args]
      local open = last and (last.tag == "Call" or last.tag == "Invoke" or last.tag == "Dots")

      local required = 0
      for index, param in ipairs(params) do
         if param ~= "..." and not param:find("?", 1, true) then required = index end
      end
      if #args < required and not open then
         ctx:emit("958", node, {name = path,
            problem = ("too few arguments to %s: it requires %d, %d passed"):format(path, required, #args)})
         return
      end

      for index, arg in ipairs(args) do
         local param = params[index] or (params[#params] == "..." and "any") or nil
         local kind = param and literal_kind(arg)
         if kind then
            local expected = param:gsub("%?$", "")
            -- A nil literal is how an optional parameter is skipped.
            local skipped = kind == "nil" and param:find("?", 1, true)
            if not skipped and type_mismatch(expected, kind, arg) then
               ctx:emit("958", arg, {name = path,
                  problem = ("argument %d of %s should be %s, %s was passed")
                     :format(index, path, ARTICLE[expected] or expected, ARTICLE[kind])})
            end
         end
      end

      if MUST_USE[path] and item and item.tag == "Eval" and item.node == node then
         ctx:emit("958", node, {name = path, problem = ("the result of %s is not used"):format(path)})
      end
   end)
end

detectors[#detectors + 1] = detect_stdlib_misuse

-- ---------------------------------------------------------------- 959

-- The string-form key a literal Pair key node makes, or nil for a non-literal
-- key (anything under `[...]` that is not a bare name or string literal).
local function literal_key(node)
   if not node then return nil end
   if node.tag == "String" then return node[1] end
   if node.tag == "Number" then return tonumber(node[1]) end
   return nil
end

local function detect_duplicate_keys(ctx)
   if not lint_gate.wanted(ctx.opts, "959") then return end

   ctx:each_node(function(node)
      if node.tag == "Table" then
         local seen = {}
         for _, pair in ipairs(node) do
            if pair.tag == "Pair" then
               local key = literal_key(pair[1])
               if key ~= nil then
                  if seen[key] then
                     ctx:emit("959", pair, {key = key})
                  else
                     seen[key] = true
                  end
               end
            end
         end
      end
   end)
end

detectors[#detectors + 1] = detect_duplicate_keys

-- ---------------------------------------------------------------- 960

-- Is this expression the literal NaN `0/0`, or its unary negation `-(0/0)`?
local function is_nan_literal(node)
   if not node or type(node) ~= "table" then return false end
   if node.tag == "Op" and node[1] == "div" then
      local left, right = node[2], node[3]
      return left and left.tag == "Number" and tonumber(left[1]) == 0
         and right and right.tag == "Number" and tonumber(right[1]) == 0
   end
   if node.tag == "Op" and node[1] == "unm" then
      local operand = node[2]
      return is_nan_literal(operand)
   end
   return false
end

local function detect_compare_nan(ctx)
   if not lint_gate.wanted(ctx.opts, "960") then return end

   ctx:each_node(function(node)
      if node.tag == "Op" and (node[1] == "eq" or node[1] == "ne") then
         if is_nan_literal(node[2]) or is_nan_literal(node[3]) then
            ctx:emit("960", node)
         end
      end
   end)
end

detectors[#detectors + 1] = detect_compare_nan

-- ---------------------------------------------------------------- 961

-- A table constructor literal, not a variable.
local function is_table_literal(node)
   return type(node) == "table" and node.tag == "Table"
end

local function detect_constant_table_comparison(ctx)
   if not lint_gate.wanted(ctx.opts, "961") then return end

   ctx:each_node(function(node)
      if node.tag == "Op" and (node[1] == "eq" or node[1] == "ne") then
         if is_table_literal(node[2]) or is_table_literal(node[3]) then
            ctx:emit("961", node)
         end
      end
   end)
end

detectors[#detectors + 1] = detect_constant_table_comparison

-- ---------------------------------------------------------------- 962

-- Is this lhs/rhs a single plain name (an Id that is a local or global, not an
-- indexed assignment)?
local function plain_name(node)
   return type(node) == "table" and node.tag == "Id"
end

-- A Set item that assigns exactly one lhs and one rhs.
local function is_simple_set(item)
   return item.tag == "Set" and #item.lhs == 1 and #item.rhs == 1
end

local function detect_almost_swapped(ctx)
   if not lint_gate.wanted(ctx.opts, "962") then return end

   local prev = nil
   for _, line in ipairs(ctx.chstate.lines) do
      for _, item in ipairs(line.items) do
         if prev and is_simple_set(prev) and is_simple_set(item)
            and plain_name(prev.lhs[1]) and plain_name(prev.rhs[1])
            and plain_name(item.lhs[1]) and plain_name(item.rhs[1])
            and prev.lhs[1][1] == item.rhs[1][1]
            and prev.rhs[1][1] == item.lhs[1][1]
            and prev.lhs[1][1] ~= prev.rhs[1][1] then
            ctx:emit("962", item.node, {a = prev.lhs[1][1], b = prev.rhs[1][1]})
         end
         prev = item
      end
   end
end

detectors[#detectors + 1] = detect_almost_swapped

-- ---------------------------------------------------------------- 963

-- A branch of an `if`/`elseif`/`else` whose block has no statements (comments
-- do not count). One finding per empty branch. luacheck 542 / selene empty_if.
--
-- An `If` node is {cond1, block1, cond2, block2, ..., [else_block]}: the branch
-- blocks sit at every even index, and when the node has an odd length the last
-- element is the else block.
local function each_if_branch(node, visit)
   for index = 2, #node, 2 do
      visit(node[index])
   end
   if #node % 2 == 1 then
      visit(node[#node])
   end
end

local function detect_empty_if_branch(ctx)
   if not lint_gate.wanted(ctx.opts, "963") then return end

   ctx:each_node(function(node)
      if node.tag ~= "If" then return end
      each_if_branch(node, function(block)
         if type(block) == "table" and #block == 0 then
            ctx:emit("963", node)
         end
      end)
   end)
end

detectors[#detectors + 1] = detect_empty_if_branch

-- ---------------------------------------------------------------- 964

-- A `for` (numeric or generic), `while` or `repeat` whose body has no statements
-- (comments do not count). selene empty_loop.
--
-- Fornum (numeric for): {var, from, to, [step], block}  -- block at last index
-- Forin (generic for):  {iter_vars, explist, block}       -- block at last index
-- While:               {condition, block}                 -- block at index 2
-- Repeat:              {block, condition}                 -- block at index 1
local function detect_empty_loop(ctx)
   if not lint_gate.wanted(ctx.opts, "964") then return end

   ctx:each_node(function(node)
      local tag = node.tag
      local block
      if tag == "Fornum" or tag == "Forin" then
         block = node[#node]
      elseif tag == "While" then
         block = node[2]
      elseif tag == "Repeat" then
         block = node[1]
      else
         return
      end
      if type(block) == "table" and #block == 0 then
         ctx:emit("964", node)
      end
   end)
end

detectors[#detectors + 1] = detect_empty_loop

-- ---------------------------------------------------------------- 965

-- A numeric `for v = A, B do` with NO step, where A and B are both number
-- literals with A > B, or A is a length operator `#t` and B is the literal 1 (or
-- 0). Anything not literal is never reported. luacheck 571 / selene
-- suspicious_reverse_loop.
--
-- Fornum node: {var, from, to, [step], block}. No step means the node has exactly 4 elements (the block at index 4).
--
-- A number literal folds to a number; a length `#t` is Op{len, t}.
local function detect_reversed_for(ctx)
   if not lint_gate.wanted(ctx.opts, "965") then return end

   ctx:each_node(function(node)
      if node.tag ~= "Fornum" or #node ~= 4 then return end

      local from, to = node[2], node[3]
      local from_val, to_val

      if from.tag == "Number" then
         from_val = tonumber(from[1])
      elseif from.tag == "Op" and from[1] == "len" then
         from_val = "len"
      else
         return
      end

      if to.tag == "Number" then
         to_val = tonumber(to[1])
      else
         return
      end

      if from_val == "len" then
         if to_val == 1 or to_val == 0 then
            ctx:emit("965", node)
         end
      elseif from_val ~= nil and to_val ~= nil and from_val > to_val then
         ctx:emit("965", node)
      end
   end)
end

detectors[#detectors + 1] = detect_reversed_for

-- ---------------------------------------------------------------- 966, 967, 968

-- Two AST subtrees are structurally identical for this check when they share a
-- tag and the same children at each position, recursing through the arrays.
-- Source positions (line, offset, end_offset) are deliberately ignored.
local function same_ast(a, b)
   if type(a) ~= "table" or type(b) ~= "table" then return a == b end
   if a.tag ~= b.tag then return false end
   if #a ~= #b then return false end
   for i = 1, #a do
      if not same_ast(a[i], b[i]) then return false end
   end
   return true
end

-- A statement list is empty when the block node holds no executable statement.
local function block_empty(block)
   for _, stmt in ipairs(block) do
      if stmt and stmt.tag then return false end
   end
   return true
end

local function detect_if_same_then_else(ctx)
   if not lint_gate.wanted(ctx.opts, "966") then return end

   ctx:each_node(function(node)
      if node.tag == "If" then
         -- Layout: {cond1, block1, cond2, block2, ..., [else_block]}. The even
         -- indices are the conditional blocks; an odd length adds a trailing else.
         local blocks = {}
         for index = 2, #node, 2 do
            blocks[#blocks + 1] = node[index]
         end
         if #node % 2 == 1 then blocks[#blocks + 1] = node[#node] end
         for i = 1, #blocks do
            if block_empty(blocks[i]) then break end
            for j = i + 1, #blocks do
               if block_empty(blocks[j]) then break end
               if same_ast(blocks[i], blocks[j]) then
                  ctx:emit("966", node)
                  return -- one finding per if
               end
            end
         end
      end
   end)
end

detectors[#detectors + 1] = detect_if_same_then_else

local function detect_ifs_same_cond(ctx)
   if not lint_gate.wanted(ctx.opts, "967") then return end

   ctx:each_node(function(node)
      if node.tag == "If" then
         local seen = {}
         for index = 1, #node - 1, 2 do
            local cond = node[index]
            for _, earlier in ipairs(seen) do
               if same_ast(cond, earlier) then
                  ctx:emit("967", cond)
                  return
               end
            end
            seen[#seen + 1] = cond
         end
      end
   end)
end

detectors[#detectors + 1] = detect_ifs_same_cond

local function detect_mixed_table(ctx)
   if not lint_gate.wanted(ctx.opts, "968") then return end

   ctx:each_node(function(node)
      if node.tag == "Table" then
         local has_positional, has_keyed = false, false
         for _, entry in ipairs(node) do
            if entry.tag == "Pair" then
               has_keyed = true
            else
               has_positional = true
            end
         end
         if has_positional and has_keyed then
            ctx:emit("968", node)
         end
      end
   end)
end

detectors[#detectors + 1] = detect_mixed_table

-- ---------------------------------------------------------------- 969

-- A value that can expand into any number of results: a call, an invoke, or
-- `...`. When it is the last value of an assignment, the name/value counts
-- can mismatch on purpose.
local function is_open_value(node)
   return node.tag == "Call" or node.tag == "Invoke" or node.tag == "Dots"
end

local function detect_unbalanced_assignment(ctx)
   if not lint_gate.wanted(ctx.opts, "969") then return end

   ctx:each_node(function(node)
      if node.tag ~= "Local" and node.tag ~= "Set" then return end
      local names = node[1]
      local values = node[2]
      if not values or #values == 0 then return end
      if #names ~= #values then
         local last = values[#values]
         if not is_open_value(last) then
            ctx:emit("969", node, {n = #names, m = #values})
         end
      end
   end)
end

detectors[#detectors + 1] = detect_unbalanced_assignment

-- ---------------------------------------------------------------- 970

-- Is the source character at `offset` an opening parenthesis, and the one at
-- `offset+1` (after the node's end) a closing one? The AST has had Paren nodes
-- unwrapped by unwrap_parens, so the condition node itself is not a "Paren"; we
-- recover the original parenthesization from the source text.
local function is_parenthesized(source, cond)
   if not cond or not cond.offset or not cond.end_offset then return false end
   return source:sub(cond.offset - 1, cond.offset - 1) == "("
      and source:sub(cond.end_offset + 1, cond.end_offset + 1) == ")"
end

-- The conditions of an if/as an array of conditions at odd indices
-- (1, 3, ...), up to the last pair; an `else` block, when present, sits at the
-- final even index and is not a condition.
local function each_condition(node, visit)
   if not node or not node.tag then return end
   if node.tag == "If" then
      for i = 1, #node - 1, 2 do
         visit(node[i])
      end
   elseif node.tag == "While" then
      visit(node[1])
   elseif node.tag == "Repeat" then
      visit(node[2])
   end
end

local function detect_parenthesized_condition(ctx)
   if not lint_gate.wanted(ctx.opts, "970") then return end

   ctx:each_node(function(node)
      each_condition(node, function(cond)
         if cond and cond.tag == "Paren" then
            ctx:emit("970", node)
         elseif is_parenthesized(ctx.source, cond) then
            ctx:emit("970", node)
         end
      end)
   end)
end

detectors[#detectors + 1] = detect_parenthesized_condition

-- ---------------------------------------------------------------- 971

-- A label is local to the function that contains it: a `goto` in an enclosing
-- function or a sibling one does not use it. So each label and goto is collected
-- against the function scope that owns it, and a label is reported only when no
-- `goto` of the same name in that same scope reaches it. The top-level chunk is
-- its own scope, just like a function body.
--
-- A `Function` node is {tag="Function", args, body, end_range = ...}; the body is the
-- list of statements at index 2. We push a scope before walking a function's
-- body and pop it after, so labels and gotos are matched within their owner.
local function detect_unused_label(ctx)
   if not lint_gate.wanted(ctx.opts, "971") then return end

   local scopes = {}  -- stack of {labels = {}, gotos = {}}

   local function push_scope()
      scopes[#scopes + 1] = {labels = {}, gotos = {}}
   end
   local function pop_scope()
      local scope = table.remove(scopes)
      local names = {}
      for name in pairs(scope.labels) do
         if not scope.gotos[name] then names[#names + 1] = name end
      end
      table.sort(names)  -- pairs order is not stable; emit deterministically
      for _, name in ipairs(names) do
         ctx:emit("971", scope.labels[name], {name = name})
      end
   end

   local function walk(node, depth)
      if depth > 200 or type(node) ~= "table" then return end

      local tag = node.tag

      if tag == "Function" then
         -- Enter the function's own scope, walk its body, then check labels.
         push_scope()
         local body = node[2]  -- {args, body, end_range = ...}
         walk(body, depth + 1)
         pop_scope()
         return
      end

      if tag == "Label" then
         scopes[#scopes].labels[node[1]] = node
      elseif tag == "Goto" then
         scopes[#scopes].gotos[node[1]] = true
      end

      for index = 1, #node do
         local child = node[index]
         if type(child) == "table" then
            if child.tag then
               walk(child, depth + 1)
            else
               for _, sub in ipairs(child) do
                  if type(sub) == "table" and sub.tag then
                     walk(sub, depth + 1)
                  end
               end
            end
         end
      end
   end

   push_scope()   -- top-level chunk scope
   walk(ctx.chstate.ast, 0)
   pop_scope()
end

detectors[#detectors + 1] = detect_unused_label

-- ---------------------------------------------------------------- 972

-- A `/` or `%` whose right operand folds to the literal 0, except the NaN idiom
-- `0/0` where both operands are literal 0 (selene divide_by_zero). const_eval
-- folds constant arithmetic; a non-constant right operand is left alone.
local function detect_division_by_zero(ctx)
   if not lint_gate.wanted(ctx.opts, "972") then return end

   ctx:each_node(function(node)
      if not node or node.tag ~= "Op" then return end
      local op = node[1]
      if op ~= "div" and op ~= "mod" then return end

      local right = node[3]
      local right_value = ctx.constant(right)
      if right_value ~= 0 then return end

      -- The NaN idiom 0/0: both operands are literal 0.
      if op == "div" and is_nan_literal(node) then return end

      ctx:emit("972", node)
   end)
end

detectors[#detectors + 1] = detect_division_by_zero

-- ---------------------------------------------------------------- 973

-- luacheck 631. A line longer than 120 characters. The line_lengths table maps
-- line numbers to their character length; any line over the limit is reported at
-- column 121, where the overflow begins.
local function detect_line_too_long(ctx)
   if not lint_gate.wanted(ctx.opts, "973") then return end

   local line_lengths = ctx.chstate.line_lengths
   for line, length in pairs(line_lengths) do
      if length > 120 then
         ctx:emit("973", {
            tag = "Id",
            line = line,
            offset = (ctx.chstate.line_offsets[line] or 0) + 121,
            end_offset = (ctx.chstate.line_offsets[line] or 0) + 121,
         }, {n = length})
      end
   end
end

detectors[#detectors + 1] = detect_line_too_long

-- ---------------------------------------------------------------- 974

-- luacheck 551 / selene empty_statement. A semicolon that does not follow a
-- statement: `;;`, a leading `;`, or a `;` after a comment. The parser records
-- these as ranges in hanging_semicolons, each a {line, offset, end_offset} table.
local function detect_empty_statement(ctx)
   if not lint_gate.wanted(ctx.opts, "974") then return end

   local hanging_semicolons = ctx.chstate.hanging_semicolons
   for _, range in ipairs(hanging_semicolons) do
      ctx:emit("974", range)
   end
end

detectors[#detectors + 1] = detect_empty_statement

-- ---------------------------------------------------------------- 975

-- selene multiple_statements. More than one statement begins on the same line
-- within one block. Nested blocks are checked independently: `if a then return
-- end` on one line is one statement in its block and is not reported.
--
-- A "block" is any statement list: the chunk AST (a table with no tag whose
-- elements are statements), and the body block of If/While/Repeat/Fornum/Forin/
-- Do/Function nodes. Each block type stores its statement list at a known index:
--   Chunk  - the whole AST table (no tag)
--   If     - even indices (2, 4, ...): each branch block; odd trailing index if
--   Fornum - last index is the block
--   Forin  - last index is the block
--   While  - index 2 is the block
--   Repeat - index 1 is the block
--   Do     - index 1 is the block
--   Function - index 2 is {args, body, end_range=...}; index 1 of that is args,
--              index 2 is the body block
local function detect_multiple_statements(ctx)
   if not lint_gate.wanted(ctx.opts, "975") then return end

   -- Extract the statement-list (block) children from a block-container node.
   local function block_children(node)
      local tag = node.tag
      if tag == "If" then
         local blocks = {}
         for i = 2, #node, 2 do blocks[#blocks + 1] = node[i] end
         if #node % 2 == 1 then blocks[#blocks + 1] = node[#node] end
         return blocks
      elseif tag == "While" then
         return {node[2]}
      elseif tag == "Repeat" then
         return {node[1]}
      elseif tag == "Fornum" or tag == "Forin" then
         return {node[#node]}
      elseif tag == "Do" then
         return {node[1]}
      elseif tag == "Function" then
         local body = node[2]  -- {args, body, end_range = ...}
         if type(body) == "table" then
            return {body[2]}
         end
         return {}
      end
      return {}
   end

   local function check_block(block)
      if type(block) ~= "table" then return end
      local prev_line
      for _, stmt in ipairs(block) do
         if stmt and stmt.tag and stmt.line then
            if prev_line and prev_line == stmt.line then
               ctx:emit("975", stmt)
            end
            prev_line = stmt.line
         end
      end
   end

   local function walk(node, depth)
      if depth > 200 or type(node) ~= "table" then return end

      if node.tag then
         if node.tag == "Function" or node.tag == "Do"
            or node.tag == "While" or node.tag == "Repeat"
            or node.tag == "Fornum" or node.tag == "Forin"
            or node.tag == "If" then
            -- Check each block in this node, then descend into them.
            local blocks = block_children(node)
            for _, block in ipairs(blocks) do
               check_block(block)
               walk(block, depth + 1)
            end
         end
      else
         -- A chunk/block: a table with no tag whose elements are statements.
         check_block(node)
         for _, child in ipairs(node) do
            walk(child, depth + 1)
         end
      end
   end

   walk(ctx.chstate.ast, 0)
end

detectors[#detectors + 1] = detect_multiple_statements

-- ---------------------------------------------------------------- 976

-- luacheck 611/612/613/614. A line whose trailing run of whitespace is not part
-- of a multi-line string value: either the whole line is spaces/tabs (611), or
-- trailing whitespace sits on a code line (612) or a comment line (614). Spaces
-- inside a multi-line string are data, not style, so lines whose
-- line_endings[line] == "string" are skipped (613).
local function detect_trailing_whitespace(ctx)
   if not lint_gate.wanted(ctx.opts, "976") then return end

   local source = ctx.chstate.source
   local line_offsets = ctx.chstate.line_offsets
   local line_lengths = ctx.chstate.line_lengths
   local line_endings = ctx.chstate.line_endings

   local num_lines = #line_offsets
   for line = 1, num_lines do
      local length = line_lengths[line]
      if length and length > 0 then
         local line_offset = line_offsets[line] or 0
         -- Mirror luacheck's detect_bad_whitespace: anchor at the line start and
         -- capture the leading non-newline tail, then the trailing whitespace run
         -- and the line terminator that follows it.
         local trailing_ws_pattern
         if line == num_lines then
            trailing_ws_pattern = "^[^\r\n]-()[ \t\f\v]+()[\r\n]?$"
         else
            trailing_ws_pattern = "^[^\r\n]-()[ \t\f\v]+()[\r\n]"
         end
         local _, _, trailing_ws_start_byte, line_end_byte =
            source:find(trailing_ws_pattern, line_offset)
         if trailing_ws_start_byte then
            local trailing_ws_end_byte = line_end_byte - 1
            local trailing_ws_start_char = line_offset + length - (line_end_byte - trailing_ws_start_byte)
            if trailing_ws_start_char == line_offset then
               -- The trailing run starts at the very first byte: the whole line is
               -- spaces/tabs (luacheck 611). Whitespace-only lines are never string
               -- continuations, so they are always reported.
               ctx:emit("976", {
                  tag = "Id",
                  line = line,
                  offset = line_offset,
                  end_offset = trailing_ws_end_byte,
               }, {msg = "line contains only whitespace"})
            elseif line_endings[line] ~= "string" then
               -- Trailing whitespace on a code line (612) or a comment line (614).
               -- Spaces inside a multi-line string are data (613), so skip them.
               ctx:emit("976", {
                  tag = "Id",
                  line = line,
                  offset = trailing_ws_start_char,
                  end_offset = trailing_ws_end_byte,
               }, {msg = "trailing whitespace"})
            end
         end
      end
   end
end

detectors[#detectors + 1] = detect_trailing_whitespace

-- ---------------------------------------------------------------- 977

-- luacheck 621. Indentation whose leading whitespace contains a space
-- immediately followed by a tab (e.g. " \t"). Pure-whitespace lines are already
-- 976's domain, so they are skipped, and a line continuing a multi-line string
-- (line_endings[line - 1] == "string") is skipped: its leading spaces are part
-- of the string value, not indentation.
local function detect_space_before_tab(ctx)
   if not lint_gate.wanted(ctx.opts, "977") then return end

   local source = ctx.chstate.source
   local line_offsets = ctx.chstate.line_offsets
   local line_lengths = ctx.chstate.line_lengths
   local line_endings = ctx.chstate.line_endings

   for line = 2, #line_offsets do
      local length = line_lengths[line]
      if length and length > 0 then
         local line_offset = line_offsets[line] or 0
         -- A continuation line of a multi-line string: its leading whitespace is
         -- string content, not indentation.
         if line_endings[line - 1] ~= "string" then
            -- Match leading whitespace that contains a space immediately followed
            -- by a tab: `^[ \t\f\v]* [ \t\f\v]*` anchored with a space-then-tab in
            -- the middle. luacheck uses `^[ \t\f\v]- \t[ \t\f\v]*`.
            local run_start, run_end = source:find("^[ \t\f\v]- \t[ \t\f\v]*", line_offset)
            if run_start then
               -- `run_start` is the line's first byte; `run_end` is one past the
               -- last byte of the leading run. Emit at the leading run's start.
               ctx:emit("977", {
                  tag = "Id",
                  line = line,
                  offset = line_offset,
                  end_offset = run_end - 1,
               })
            end
         end
      end
   end
end

detectors[#detectors + 1] = detect_space_before_tab

-- ---------------------------------------------------------------- 978

-- selene global_usage. A reference to the global table `_G` that is not a local
-- named `_G` shadowing it. luacheck's resolve_locals phase stamps a `.var`
-- field on an Id node when it resolves to a local variable, so a global `_G`
-- access is an Id named "_G" with no `.var`.
--
-- Reported on every Index node whose object is the global _G: `_G.x`,
-- `_G["x"]`, `_G.x = ...` (indexing) and `_G.x += ...` (mutation). The emitted
-- node is the Index; its offset/end_offset already span the whole `_G.x`.
local function detect_G_usage(ctx)
   if not lint_gate.wanted(ctx.opts, "978") then return end

   ctx:each_node(function(node)
      if node.tag ~= "Index" then return end
      local obj = node[1]
      if not obj or obj.tag ~= "Id" or obj[1] ~= "_G" or obj.var then return end
      ctx:emit("978", node, {msg =
         "use of _G (selene global_usage): read or write the global directly, or keep a local table"})
   end)
end

detectors[#detectors + 1] = detect_G_usage

-- ---------------------------------------------------------------- 979

-- selene type_check_inside_call. type() is being called with a comparison
-- expression (==, ~=, <, <=, >, >=) as its argument, which is almost always a
-- typo for `type(x) == "..."` and never type-checks the intended value.
--
-- A Call whose callee is the global Id "type" (no `.var`, so it is not a local
-- shadowing it) and whose first argument is an Op comparison.
local function detect_type_check_inside_call(ctx)
   if not lint_gate.wanted(ctx.opts, "979") then return end

   ctx:each_node(function(node)
      if node.tag ~= "Call" then return end
      local fn = node[1]
      if not fn or fn.tag ~= "Id" or fn[1] ~= "type" or fn.var then return end
      -- First argument is node[2]; Call = {tag="Call", fn, arg1, arg2, ...}
      local arg = node[2]
      if not arg then return end
      if arg.tag ~= "Op" then return end
      local op = arg[1]
      if op ~= "eq" and op ~= "ne" and op ~= "lt" and op ~= "le"
         and op ~= "gt" and op ~= "ge" then
         return
      end
      ctx:emit("979", node)
   end)
end

detectors[#detectors + 1] = detect_type_check_inside_call

-- ---------------------------------------------------------------- 981

-- luacheck 131. A module-level global that is assigned but never read in the file.
-- `function name() end` desugars to a Set of global `name`; `name = value` is a
-- Set whose lhs target is an Id with no `.var` (resolved by resolve_locals, which
-- stamps `.var` on locals only).
--
-- A read of a global name is an Id with no `.var` used as a value, including the
-- object of an Index (`name.x` reads global `name`), and a `_G.NAME` access,
-- which reads `NAME` through the global table.
--
-- Only top-level chunk statements are considered for assignment: a global set
-- inside a function body is not module-level and is not reported here.
local function detect_unused_global(ctx)
   if not lint_gate.wanted(ctx.opts, "981") then return end

   -- (a) every global name assigned at module level, with its assignment node.
   -- The AST Set node is {tag="Set", [1]=lhs_list, [2]=rhs_list}.
   local assigned = {}
   for _, stmt in ipairs(ctx.chstate.ast) do
      if stmt.tag == "Set" and stmt[1] then
         for _, target in ipairs(stmt[1]) do
            if target.tag == "Id" and not target.var then
               assigned[target[1]] = stmt
            end
         end
      end
   end

   -- (b) every global name read anywhere: a bare global Id, the object of an
   -- Index, or a _G.NAME key (which reads NAME through the global table).
   -- A Set/Local/Localrec lhs target is a store, not a read, so its Ids are
   -- skipped during the walk.
   local read = {}
   local skip_lhs = {}
   local function index_lhs(node, depth)
      if depth > 200 or type(node) ~= "table" then return end
      if (node.tag == "Set" or node.tag == "Local" or node.tag == "Localrec")
            and node[1] then
         for _, target in ipairs(node[1]) do
            if type(target) == "table" then skip_lhs[target] = true end
         end
      end
      for index = 1, #node do
         local child = node[index]
         if type(child) == "table" and child.tag then
            index_lhs(child, depth + 1)
         end
      end
   end
   index_lhs(ctx.chstate.ast, 0)

   local function walk_reads(node, depth)
      if depth > 200 or type(node) ~= "table" then return end
      if not skip_lhs[node] then
         if node.tag == "Id" and not node.var then
            read[node[1]] = true
         elseif node.tag == "Index" then
            local obj = node[1]
            if obj and obj.tag == "Id" and not obj.var then
               read[obj[1]] = true
               if obj[1] == "_G" and node[2] and node[2].tag == "String" then
                  read[node[2][1]] = true
               end
            end
         end
      end
      for index = 1, #node do
         local child = node[index]
         if type(child) == "table" and child.tag then
            walk_reads(child, depth + 1)
         end
      end
   end
   walk_reads(ctx.chstate.ast, 0)

   for name, stmt in pairs(assigned) do
      if not read[name] then
         ctx:emit("981", stmt, {name = name})
      end
   end
end

detectors[#detectors + 1] = detect_unused_global

-- ---------------------------------------------------------------- 982, 983, 984

-- luacheck 211/212/213, mapped to lua-doctor codes 982/983/984.
--
-- `resolve_locals` (run in parse_context) gives flow-sensitive reaching
-- definitions: each `var` object on an Id node carries `var.accessed`, set by
-- linearize for every resolved read, and `var.values[*].used`, set by
-- resolve_locals when a reaching definition was actually consumed. For these
-- three lints the relevant fact is simply "was this name ever read at all":
-- `var.accessed` already answers that, flow-insensitively, and is cheaper than
-- walking the RDefs table luacheck populated for the taint pass.
--
-- A `var` is one of:
--   "var"   - a local (declared with `local` or `local function`)
--   "arg"   - a named function parameter
--   "loop"  - a generic-for loop variable (for k, v in ...)
--   "loopi" - a numeric-for counter (for i = a, b do)
-- The var's `node` is the declaration Id; `var.accessed` is true when any Id
-- referencing it was scanned as an expression during linearize.
--
-- We walk the AST once and visit each var by identity, so a name with many
-- references is checked once. When resolve_locals was skipped (904, large
-- file), `var.accessed` is still set by linearize, so the detection is sound;
-- the gate and the 904 coverage gap already tell the operator the file was
-- approximate.
local function collect_unused(ctx, var, seen)
   if not var or seen[var] then return end
   seen[var] = true

   local name = var.name
   local vtype = var.type

   if vtype == "var" then
      -- 982: a local (incl. local function) never read. `_` is the throwaway.
      if name ~= "_" and not var.accessed then
         if lint_gate.wanted(ctx.opts, "982") then
            ctx:emit("982", var.node, {name = name})
         end
      end
   elseif vtype == "arg" then
      -- 983: a named parameter never read. `...` and `self` are not flagged.
      if name ~= "..." and name ~= "self" and not var.self then
         if not var.accessed and lint_gate.wanted(ctx.opts, "983") then
            ctx:emit("983", var.node, {name = name})
         end
      end
   elseif vtype == "loop" or vtype == "loopi" then
      -- 984: a loop variable never read. `_` is not flagged.
      if name ~= "_" and not var.accessed then
         if lint_gate.wanted(ctx.opts, "984") then
            ctx:emit("984", var.node, {name = name})
         end
      end
   end
end

local function detect_unused(ctx)
   -- Bail early when none of the three codes is enabled.
   if not lint_gate.wanted(ctx.opts, "982")
      and not lint_gate.wanted(ctx.opts, "983")
      and not lint_gate.wanted(ctx.opts, "984") then
      return
   end

   -- resolve_locals attaches `.var` to declaration Ids and is what gives the
   -- access tracking its meaning; skip when it did not run.
   if not ctx.chstate.resolved_locals then return end

   local seen = {}
   ctx:each_node(function(node)
      if node.var then
         collect_unused(ctx, node.var, seen)
      end
   end)
end

detectors[#detectors + 1] = detect_unused

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M
