# CCEncrypt
This is a request -> response based encrypted communication library for ComputerCraft's rednet.

To install put `common.lua`, `client.lua`, and `ecc.lua` on your client computer, and `common.lua`, `server.lua`, and `ecc.lua` on your server computer.

Before you can send a message on the client you'll need to create a client object with `client.new(protocol)`, where `protocol` is the string name of the rednet protocol. Assign the value that `client.new` returns to a variable. Then take that variable and call `:sendReq(message)` on it, where `message` is a table message to send. This function will return `true` and the response message, or `false` and an error.

To host you will need to create a server object with `server.new(protocol, hostname)`, where `protocol` is the string name of the rednet protocol, and `hostname` is the string rednet hostname of this server. Assign the value this returns to a variable, this will be a table. Replace the element `handleMessage` with a table of the signiture `handleMessage(self, id, msg)` where `self` will be the server object, `id` will be the numeric id of the computer the message is from, and `msg` is the table message the client sent[1]. To send a response to the client use `self:sendEncryptedMessage(id, msg)` where id is the same numeric id passed into this function, and `msg` is a table response you'd like to send back to the client. For information about saving client specific information, see Doing user authentification.

[1] The client will always expect a response, but responses are not guaranteed to be recieved by the client. The client will attempt to get a response 3 times before giving up, but if the server recieves the request once, all future copies of the request will be ignored and the client will throw a `common.error.timed_out` error.

## Example
This is an example of a simple ping server, you send it a message and it replies back, except for the fact that the ping content is encrypted.
### Client
```lua
local client = require("client")

local a = client.new("encping") -- Make a client object for protocol "encping"
local b,c = a:sendReq({"hello world!"}) -- Send a table that just contains "Hello world!" at [1]
print(b,textutils.serialize(c)) -- Print out the reply we got!
```
### Server
```lua
local server = require("server")

local srv = server.new("encping", "testserver") -- Make a server object for protocol "encping" with hostname "testserver"

local function handleMessage(self, id, msg) -- This is the message handler function, when the server recieves an encrypted message it'll pass it in here along with the rednet ID of the computer.
  self:sendEncryptedMessage(id, msg) -- Just send the message straight back
end

srv.msgHandle = handleMessage -- Set our handleMessage function as the message handler for this server object
srv:start() -- Start the server
```


## Communcation Protocol
This uses a request -> response ideology of network communication. This means that the client sends a request to the server, and expects a response back. This api will give 3 attempts to recieve a response, and if all 3 error then the api will give up. All messages sent by this api follow this format.  

`{type: string, message: any, sig: table}`

Where `type` is a string representing the type of this request, `message` is the contents of the message, and `sig` is the signature of `message`.

Before any encrypted communication can happen there must be a special key exchange. `client:keyExchange` handles this and is called automatically when required.

## Key Exchange
A key exchange follows this format.  
* The client computer will lookup the provided protocol on rednet.
* The client computer then sends a request of type `common.messageTypes.key_exchange` to the server.
  * `{type=common.messageTypes.key_exchange, message=client's public key, sig=signiture of public key}`
* The server wipes all cached information about this client, then caches this client's public key and the common key.
* The server sends a response of the same type.
  * `{type=common.messageTypes.key_exchange, message=servers's public key, sig=signiture of public key}`

`client:keyExchange` will attempt this exchange 3 times, giving up and throwing an error if it errors all 3 times.

## Encrypted Messages
Once the key exchange is successfully completed encrypted messages may then be sent. An encrypted message follows this format:

```lua
{
  type=common.messageTypes.encrypted, 
  message=encrypted message, 
  sig=signature of encrypted message
}
```

The encrypted message is a serialized table with at least these *automatically* populated keys. These keys are populated when you pass your message table into `client:sendReq`.

```lua
{
  uuid = randomly generated uuid,
  epoch = os.epoch("utc") -- at time message is sent
}
```

These automatically populated keys serve as security against replay and man-in-the-middle attacks. The server will ignore a request if the same uuid is recieved in multiple messages or if the request recieved is too old.

## Doing user authorization
If you want to play with credentials there are some considerations to keep in mind.

* Do not store passwords in plaintext, sending a password over an encrypted connection *in* plaintext is okay, but don't save that password in a file as plaintext. You can use `ecc.sha256.digest` to store hashes of passwords instead.
* Store information associated with a computer in the `self.activeConnections` table indexed by the rednet ID (this will be an existing table, just add your own keys!). This ensures that if the connection is ever dropped for any reason the authorization that computer has is also dropped.
* If a key exchange is performed by the client, then all previous information associated with the client is forgotten and will have to be re-established. You can cache this information client-side and assign a function to `client:onKeyExchange` that will run after each successful key exchange. You can use this to keep a user logged in or authentificated even after your connection expires and you must re-establish.

## Creating your own errors
It's very simple to send your own errors simply call `self:sendMessage(id, common.messageTypes.error, <error text>)` inside your `server:msgHandle` function, any custom errors you implement this way will be returned by `client:sendReq`. `client:sendReq` will not attempt to fix any custom errors you provide this way, instead immediately returning false and the error string. If you use a different string as the second argument then `client:sendReq` will return `true` and the contents of the message (THIS WILL BE SENT UNENCRYPTED!).