-- busted: the test-framework globals, taken from luacheck's own std table (vendored).
return {
   name = "busted",
   globals = require "luacheck.builtin_standards".busted,
}
