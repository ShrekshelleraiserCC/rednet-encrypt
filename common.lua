--- Shared content between client and server
-- @module common

local api = {}

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