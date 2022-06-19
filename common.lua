--- Shared content between client and server
-- @module common

local api = {}

--- Generate a UUID.
-- https://gist.github.com/jrus/3197011
-- @treturn string uuid
function api.generateUUID()
  local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
  return string.gsub(template, '[xy]', function(c)
    local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
    return string.format('%x', v)
  end)
end

function api.valueInTable(T, value)
  for k,v in pairs(T) do
    if v == value then return true end
  end
  return false
end

--- Error table
-- @table error
api.error = {
  timed_out = "timed out", -- didn't recieve a response from the server in time
  key_failure = "key failure", -- invalid key pairs
  sig_invalid = "signature invalid", -- signiture doesn't match the message
}

--- Message types
-- @table messageTypes
api.messageTypes = {
  encrypted = "encrypted", -- The message key of this table is encrypted
  key_exchange = "key exchange", -- The message key of this table is a public key
  error = "error", -- The message key of this table is an error type from api.error
}

return api