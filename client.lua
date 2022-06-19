--- Client Module
-- @module client

local ecc = require("ecc")
local common = require("common")
local modem = peripheral.find("modem")
local expect = require("cc.expect")
assert(modem, "Modem not found.")
rednet.open(peripheral.getName(modem))

--- Default settings
-- @table api
local api = {
  timeout=0.5, -- How long to wait before declaring a message as timing out
  maxKeyAge=(1000 * 60 * 10), -- How long to allow keys to last
  onKeyExchange = nil -- Function called after keys are exchanged for whatever reason, you can place an authorization function in here i.e. for password/account login persistance
}
api.__index = api

--- Perform the key exchange, called automatically
-- @return true or throws an error
function api:keyExchange()
  self.hostId = rednet.lookup(self.protocol)
  if type(self.hostId) == "nil" then
    error("No host for "..self.protocol.." found.")
  elseif type(self.hostId) == "table" then
    error("Multiplce hosts of "..self.protocol.." on network.") -- just throw for now
  end
  -- {type: "key_exchange", message: <public key>, sig: <sig of public key>}
  local message = {type=common.messageTypes.key_exchange, message=self.public, sig=ecc.sign(self.private, self.public)}
  rednet.send(self.hostId, message, self.protocol)
  local errCount = 0
  while errCount < 3 do
    local id, response, protocol = rednet.receive(self.protocol, self.timeout)
    if response and id == self.hostId then
      if response.type == common.messageTypes.key_exchange and ecc.verify(response.message, response.message, response.sig) then
        -- key_exchange, and signiture is valid
        self.hostPublic = response.message
        self.common = ecc.exchange(self.private, self.hostPublic)
        self.lastKeyExchange = os.epoch("utc")
        if self.onKeyExchange then
          self:onKeyExchange()
        end
        self.uuids = {} -- reset uuid cache
        return true
        -- If this fails then we assume that the response type was incorrect, so we wait for the correct response type
      end
    else
      -- timed out, send the message again
      errCount = errCount + 1
      rednet.send(self.hostId, message, self.protocol)
    end
  end
  error("Unable to perform key exchange.")
end

function api:_checkKeyAge()
  if self.lastKeyExchange + self.maxKeyAge < os.epoch("utc") then
    -- more than 10 minutes passed since we last exchanged keys, so do it again
    api:keyExchange()
  end
end



function api:_sendEncryptedMessage(message)
  expect(1, message, "table")
  message.uuid = message.uuid or common.generateUUID()
  message.epoch = os.epoch("utc")
  local serializedMessage = textutils.serialize(message)
  local encryptedMessage = ecc.encrypt(serializedMessage, self.common)
  local toSend = {type=common.messageTypes.encrypted, message=encryptedMessage, sig=ecc.sign(self.private, encryptedMessage)}
  rednet.send(self.hostId, toSend, self.protocol)
end

--- Send a message to the host server and get a reply
-- @tparam table message
-- @treturn[1] bool false
-- @treturn[1] string error
-- @treturn[2] bool true
-- @treturn[2] any Response
function api:sendReq(message)
  expect(1, message, "table")
  self:_checkKeyAge()
  local errCount = 0
  local lastErrReason
  local send = true
  while errCount < 3 do
    if send then
      self:_sendEncryptedMessage(message)
      send = false
    end
    local id, response = rednet.receive(self.protocol, self.timeout)
    if type(response) == "nil" then
      -- timeout
      errCount = errCount + 1
      lastErrReason = common.error.timed_out
      send = true
    elseif response.type == common.messageTypes.encrypted and id == self.hostId then
      -- message is encrypted
      if ecc.verify(self.hostPublic, response.message, response.sig) then
        -- signiture is valid
        local status, decryptResponse = pcall(textutils.unserialize,string.char(unpack(ecc.decrypt(response.message, common))))
        if status and decryptResponse.uuid and (not common.valueInTable(self.uuids, decryptResponse.uuid)) then
          -- the message decrypted successfully to a serialized table, and the uuid is unique
          self.uuids[#self.uuids+1] = decryptResponse.uuid
          return true, decryptResponse
        elseif status then
          -- the message decrypted successfully, but the uuid is not unique
          -- For now this message will just be ignored.
        else
          -- key is invalid
          self:keyExchange()
          errCount = errCount + 1
          lastErrReason = common.error.key_failure
        end
      else
        errCount = errCount + 1
        lastErrReason = common.error.sig_invalid
        -- signature is invalid
      end
      -- If still continuing execution at this point it's errored and we need to resend the message
      send = true
    elseif response.type == common.messageTypes.error and id == self.hostId and errCount < 2 then
      lastErrReason = response.message
      errCount = errCount + 1
      if response.message == common.error.key_failure then
        self:keyExchange()
      end
      send = true
    elseif ecc.verify(self.hostPublic, response.message, response.sig) and id == self.hostId then
      -- signiture is valid, but message isn't encrypted. Will also trigger on the third error
      return (response.type ~= common.messageTypes.error), response.message
    elseif id == self.hostId then
      -- signiture is invalid
      errCount = errCount + 1
      lastErrReason = common.error.sig_invalid
      send = true
    end
    -- If the message recieved was NOT from the host selected then don't resend the message, just process more of the queue
  end
  -- This should be impossible to reach
  return false, lastErrReason
end

--- Create a new client object.
-- @tparam string protocol
-- @treturn table Client object
function api.new(protocol)
  local o = {}
  o.private, o.public = ecc.keypair()
  setmetatable(o, api)
  o.protocol = protocol
  o:keyExchange()
  return o
end

return api