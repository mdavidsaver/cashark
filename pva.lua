-- Wireshark Lua script plugin
-- packet disector for PV Access protocol
--
-- https://github.com/mdavidsaver/cashark
--
-- Copyright 2015 Michael Davidsaver
--
-- Distribution and use subject to the EPICS Open License
-- See the file LICENSE
--
-- Revision $Id: 3b93cac5a0c481aefc530849da572cdcac713502 $

print("Loading PVA...")

local pva = Proto("pva", "Process Variable Access")

local bcommands = {
    [0] = "BEACON",
    [1] = "CONNECTION_VALIDATION",
    [2] = "ECHO",
    [3] = "SEARCH",
    [4] = "SEARCH_RESPONSE",
    [5] = "AUTHNZ",
    [6] = "ACL_CHANGE",
    [7] = "CREATE_CHANNEL",
    [8] = "DESTROY_CHANNEL",
    [9] = "CONNECTION_VALIDATED",
    [10] = "GET",
    [11] = "PUT",
    [12] = "PUT_GET",
    [13] = "MONITOR",
    [14] = "ARRAY",
    [15] = "DESTROY_REQUEST",
    [16] = "PROCESS",
    [17] = "GET_FIELD",
    [18] = "MESSAGE",
    [19] = "MULTIPLE_DATA",
    [20] = "RPC",
    [21] = "CANCEL_REQUEST",
}

local fmagic= ProtoField.uint8("pva.magic", "Magic", base.HEX)
local fver  = ProtoField.uint8("pva.version", "Version", base.DEC)
local fflags= ProtoField.uint8("pva.flags", "Flags", base.HEX)
local fflag_dir = ProtoField.uint8("pva.direction", "Direction", base.HEX, {[0]="client",[1]="server"}, 0x40)
local fflag_end = ProtoField.uint8("pva.endian", "Byte order", base.HEX, {[0]="LSB",[1]="MSG"}, 0x80)
local fcmd  = ProtoField.uint8("pva.command", "Command", base.HEX, bcommands)
local fsize = ProtoField.uint32("pva.size", "Size", base.DEC)
local fbody = ProtoField.bytes("pva.body", "Body")
local fpvd = ProtoField.bytes("pva.pvd", "Data")

-- For CONNECTION_VALIDATION

local fvalid_bsize = ProtoField.uint32("pva.qsize", "Client Queue Size")
local fvalid_isize = ProtoField.uint16("pva.isize", "Client Introspection registery size")
local fvalid_qos = ProtoField.uint16("pva.qos", "Client QoS", base.HEX)
local fvalid_authz = ProtoField.string("pva.authz", "AuthZ name")

-- For SEARCH
local fsearch_seq = ProtoField.uint32("pva.seq", "Search Sequence #")
local fsearch_addr = ProtoField.bytes("pva.addr", "Address")
local fsearch_port = ProtoField.uint16("pva.port", "Port")
local fsearch_mask = ProtoField.uint8("pva.mask", "Mask", base.HEX)
local fsearch_proto = ProtoField.string("pva.proto", "Transport Protocol")
local fsearch_cid = ProtoField.uint32("pva.cid", "Search ID")
local fsearch_name = ProtoField.string("pva.pv", "Name")

pva.fields = {
    fmagic, fver, fflags, fflag_dir, fflag_end, fcmd, fsize, fbody, fpvd,
    fvalid_bsize, fvalid_isize, fvalid_qos, fvalid_authz,
    fsearch_seq, fsearch_addr, fsearch_port, fsearch_mask, fsearch_proto, fsearch_cid, fsearch_name,
}

local specials_server
local specials_client

local function decode (buf, pkt, root)
  if buf:len()<8 then return 0 end
  -- [0xCA, ver, flags, cmd, size[4]]

  if buf(0,1):uint()~=0xca
  then
    pkt.cols.info:append("Corrupt message.  Bad magic.")
    return 0;
  end

  local flagval = buf(2,1):uint()
  local isbe = bit.band(flagval, 0x80)
  local msglen
  if isbe~=0
  then
    msglen = buf(4,4):uint()
  else
    msglen = buf(4,4):le_uint()
  end

  if buf:len()<8+msglen
  then
    return (buf:len()-(8+msglen))
  end

  local t = root:add(pva, buf(0,8+msglen))

  t:add(fmagic, buf(0,1))
  t:add(fver, buf(1,1))
  local flags = t:add(fflags, buf(2,1))
  t:add(fcmd, buf(3,1))
  t:add(fsize, buf(4,4), msglen)

  flags:add(fflag_dir, buf(2,1))
  flags:add(fflag_end, buf(2,1))

  local cmd = buf(3,1):uint()
  local showgeneric = 1

  if bit.band(flagval, 0x40)~=0
  then
      -- server

      local spec = specials_server[cmd]
      if spec
      then
          spec(buf(8,msglen), pkt, t, isbe~=0)
          showgeneric = 0
      end
  else
      -- client

      local spec = specials_client[cmd]
      if spec
      then
          spec(buf(8,msglen), pkt, t, isbe~=0)
          showgeneric = 0
      end
  end
  
  if showgeneric~=0
  then
    local cmd_name = bcommands[cmd]
    if cmd_name
    then
      pkt.cols.info:append(cmd_name..", ")
    else
      pkt.cols.info:append("Msg: "..cmd.." ")
    end

    if isbe
    then
      t:add(fbody, buf(8, msglen))
    else
      t:addle(fbody, buf(8, msglen))
    end
  end

  return 8+msglen
end

function pva.dissector (buf, pkt, root)

  if buf(0,1):uint()~=0xca
  then
      return
  end

  pkt.cols.protocol = pva.name
  pkt.cols.info:clear()
  if bit.band(buf(2,1):uint(), 0x40)~=0
  then
    pkt.cols.info:append("Server ")
  else
    pkt.cols.info:append("Client ")
  end

  local origbuf = buf
  local totalconsumed = 0

  --print(pkt.number.." "..buf:len())

  while buf:len()>0
  do
    local pdir
    local consumed
    consumed = decode(buf,pkt,root)
    --print("Consumed "..consumed)

    if consumed<0
    then
      -- Wireshark documentation lists this as the prefered was
      -- to indicate TCP reassembly.  However, as of version 1.2.11
      -- this does not work for LUA disectors.  However, the pinfo
      -- mechanism does.
      --return consumed
      pkt.desegment_offset = totalconsumed
      pkt.desegment_len = -consumed
      return
    elseif consumed<8
    then
      pkt.cols.info:preppend("[Incomplete] ")
      break
    else
      --print("Consuming "..consumed)
      totalconsumed = totalconsumed + consumed
      buf=buf(consumed):tvb()
    end
  end
end

local utbl = DissectorTable.get("udp.port")
utbl:add(5075, pva)
utbl:add(5076, pva)
local ttbl = DissectorTable.get("tcp.port")
ttbl:add(5075, pva)


local function decodeSize(buf, isbe)
    local s0 = buf(0,1):uint()
    if s0==255 then
        return 0, buf(1) -- special nil string? treat as zero
    elseif s0==254 then
        if isbe then
            return buf(1,4):uint(), buf(5)
        else
            return buf(1,4):le_uint(), buf(5)
        end
    else
        return s0, buf(1)
    end 
end

-- extract a string and return that string, and the remaining buffer
local function decodeString(buf, isbe)
    local s, buf = decodeSize(buf, isbe)
    if s==buf:len() then
        return buf(0,s), nil
    else
        return buf(0,s), buf(s)
    end
end


-- Since PVA has some identifiable header we can
-- avoid having to select "Decode as..." every time :)
local function test_pva (buf, pkt, root)
  -- check for 8 byte minimum length, prefix [0xca, 1, _, cmd] where cmd is a valid command #
  if buf:len()<8 or buf(0,1):uint()~=0xca or buf(1,1):uint()~=1 or not bcommands[buf(3,1):uint()]
  then
      return false
  end
  pva.dissector(buf, pkt, root)
  pkt.conversation = pva
  return true
end

pva:register_heuristic("udp", test_pva)
pva:register_heuristic("tcp", test_pva)

local function pva_client_search (buf, pkt, t, isbe)
    pkt.cols.info:append("SEARCH('")
    local seq, port
    if isbe then
        seq = buf(0,4):uint()
        port = buf(24,2):uint()
    else
        seq = buf(0,4):le_uint()
        port = buf(24,2):le_uint()
    end

    t:add(fsearch_seq, buf(0,4), seq)
    t:add(fsearch_mask, buf(4,1))
    t:add(fsearch_addr, buf(8,16))
    t:add(fsearch_port, buf(24,2), port)
    
    local nproto, npv

    nproto, buf = decodeSize(buf(26), isbe)
    for i=0,nproto-1 do
        local name
        name, buf = decodeString(buf, isbe)
        t:add(fsearch_proto, name)
    end
    
    if isbe then
        npv = buf(0,2):uint()
    else
        npv = buf(0,2):le_uint()
    end
    buf = buf(2)

    for i=0,npv-1 do
        local cid, name
        if isbe then
            cid = buf(0,4):uint()
        else
            cid = buf(0,4):le_uint()
        end
        t:add(fsearch_cid, buf(0,4), cid)
        name, buf = decodeString(buf(4), isbe)
        t:add(fsearch_name, name)

        if i>0 then pkt.cols.info:append("', '") end
        pkt.cols.info:append(name:string())
    end
    pkt.cols.info:append("'), ")
end

local function pva_client_validate (buf, pkt, t, isbe)
    pkt.cols.info:append("CONNECTION_VALIDATION, ")
    local bsize, isize, qos
    if isbe
    then
        bsize = buf(0,4):uint()
        isize = buf(4,2):uint()
        qos = buf(6,2):uint()
    else
        bsize = buf(0,4):le_uint()
        isize = buf(4,2):le_uint()
        qos = buf(6,2):le_uint()
    end
    t:add(fvalid_bsize, buf(0,4), bsize)
    t:add(fvalid_isize, buf(4,2), isize)
    t:add(fvalid_qos, buf(6,2), qos)

    local authz
    authz, buf = decodeString(buf(8), isbe)
    t:add(fvalid_authz, authz)
    t:add(fpvd, buf)
end

specials_server = {
}
specials_client = {
    [1] = pva_client_validate,
    [3] = pva_client_search,
}

print("Loaded PVA")
