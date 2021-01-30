-- Wireshark Lua script plugin
-- packet disector for PV Access protocol
--
-- https://github.com/mdavidsaver/cashark
--
-- Copyright 2021 Michael Davidsaver
--
-- Distribution and use subject to the EPICS Open License
-- See the file LICENSE
--
-- Revision $Id: 3b93cac5a0c481aefc530849da572cdcac713502 $

print("Loading PVA...")

local pva = Proto("pva", "Process Variable Access")

-- application messages
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
    [22] = "ORIGIN_TAG",
}

-- control messages
local bctrlcommands = {
    [0] = "MARK_TOTAL_BYTES_SENT",
    [1] = "ACK_TOTAL_BYTES_RECEIVED",
    [2] = "SET_BYTE_ORDER",
}

local stscodes = {
    [0xff] = "OK",
    [0] = "OK",
    [1] = "Warning",
    [2] = "Error",
    [3] = "Fatal Error",
}

local fmagic= ProtoField.uint8("pva.magic", "Magic", base.HEX)
local fver  = ProtoField.uint8("pva.version", "Version", base.DEC)
local fflags= ProtoField.uint8("pva.flags", "Flags", base.HEX)
local fflag_dir = ProtoField.uint8("pva.direction", "Direction", base.HEX, {[0]="client",[1]="server"}, 0x40)
local fflag_end = ProtoField.uint8("pva.endian", "Byte order", base.HEX, {[0]="LSB",[1]="MSG"}, 0x80)
local fflag_msgtype = ProtoField.uint8("pva.msg_type", "Message type", base.HEX, {[0]="Application",[1]="Control"}, 0x01)
local fflag_segmented = ProtoField.uint8("pva.segmented", "Segmented", base.HEX, {[0]="Not segmented",[1]="First segment",[2]="Last segment",[3]="In-the-middle segment"}, 0x30)
local fcmd  = ProtoField.uint8("pva.command", "Command", base.HEX, bcommands)
local fctrlcmd  = ProtoField.uint8("pva.ctrlcommand", "Control Command", base.HEX, bctrlcommands)
local fctrldata  = ProtoField.uint32("pva.ctrldata", "Control Data", base.HEX)
local fsize = ProtoField.uint32("pva.size", "Size", base.DEC)
local fbody = ProtoField.bytes("pva.body", "Body")
local fpvd = ProtoField.bytes("pva.pvd", "Data")
local fguid = ProtoField.bytes("pva.guid", "GUID")

-- common
local fcid = ProtoField.uint32("pva.cid", "Client Channel ID")
local fsid = ProtoField.uint32("pva.sid", "Server Channel ID")
local fioid = ProtoField.uint32("pva.ioid", "Operation ID")
local fsubcmd = ProtoField.uint8("pva.subcmd", "Sub-command", base.HEX)
local fsubcmd_proc = ProtoField.uint8("pva.process", "Process", base.HEX, {[0]="",[1]="Yes"}, 0x04)
local fsubcmd_init = ProtoField.uint8("pva.init",    "Init   ", base.HEX, {[0]="",[1]="Yes"}, 0x08)
local fsubcmd_dstr = ProtoField.uint8("pva.destroy", "Destroy", base.HEX, {[0]="",[1]="Yes"}, 0x10)
local fsubcmd_get  = ProtoField.uint8("pva.get",     "Get    ", base.HEX, {[0]="",[1]="Yes"}, 0x40)
local fsubcmd_gtpt = ProtoField.uint8("pva.getput",  "GetPut ", base.HEX, {[0]="",[1]="Yes"}, 0x80)
local fstatus = ProtoField.uint8("pva.status", "Status", base.HEX, stscodes)

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
local fsearch_mask_repl  = ProtoField.uint8("pva.reply", "Reply", base.HEX, {[0]="Optional",[1]="Required"}, 0x01)
local fsearch_mask_bcast = ProtoField.uint8("pva.mcast", "Reply", base.HEX, {[0]="Unicast",[1]="Multicast"}, 0x80)
local fsearch_proto = ProtoField.string("pva.proto", "Transport Protocol")
local fsearch_cid = ProtoField.uint32("pva.cid", "CID")
local fsearch_name = ProtoField.string("pva.pv", "Name")

-- For SEARCH_RESPONSE
local fsearch_found = ProtoField.bool("pva.found", "Found")

pva.fields = {
    fmagic, fver, fflags, fflag_dir, fflag_end, fflag_msgtype, fflag_segmented, fcmd, fctrlcmd, fctrldata, fsize, fbody, fpvd, fguid,
    fcid, fsid, fioid, fsubcmd, fsubcmd_proc, fsubcmd_init, fsubcmd_dstr, fsubcmd_get, fsubcmd_gtpt, fstatus,
    fvalid_bsize, fvalid_isize, fvalid_qos, fvalid_authz,
    fsearch_seq, fsearch_addr, fsearch_port, fsearch_mask, fsearch_mask_repl, fsearch_mask_bcast,
    fsearch_proto, fsearch_cid, fsearch_name,
    fsearch_found,
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
  local ctrlcmd = bit.band(flagval, 0x01)
  local msglen
  if ctrlcmd==0
  then
    if isbe~=0
    then
      msglen = buf(4,4):uint()
    else
      msglen = buf(4,4):le_uint()
    end
  else
    -- control message len is always 0 (only header), size holds data
    msglen = 0
  end
  
  if buf:len()<8+msglen
  then
    return (buf:len()-(8+msglen))
  end

  local t = root:add(pva, buf(0,8+msglen))

  t:add(fmagic, buf(0,1))
  t:add(fver, buf(1,1))
  local flags = t:add(fflags, buf(2,1))
  if ctrlcmd==0
  then
    t:add(fcmd, buf(3,1))
    t:add(fsize, buf(4,4), msglen)
  else
    t:add(fctrlcmd, buf(3,1))
    t:add(fctrldata, buf(4,4))
  end  

  flags:add(fflag_msgtype, buf(2,1))
  flags:add(fflag_segmented, buf(2,1))
  flags:add(fflag_dir, buf(2,1))
  flags:add(fflag_end, buf(2,1))

  local cmd = buf(3,1):uint()
  local showgeneric = 1

  if ctrlcmd==0
  then
    -- application message
    if bit.band(flagval, 0x40)~=0
    then
        -- server

        local spec = specials_server[cmd]
        if spec
        then
            spec(buf(8,msglen), pkt, t, isbe~=0, cmd)
            showgeneric = 0
        end
    else
        -- client

        local spec = specials_client[cmd]
        if spec
        then
            spec(buf(8,msglen), pkt, t, isbe~=0, cmd)
            showgeneric = 0
        end
    end
  else
    -- control message
    local cmd_name = bctrlcommands[cmd]
    if cmd_name
    then
      pkt.cols.info:append(cmd_name..", ")
    else
      pkt.cols.info:append("Msg: "..cmd.." ")
    end
    showgeneric = 0
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
  pkt.cols.info:append(pkt.src_port.." -> "..pkt.dst_port.." ")
  if bit.band(buf(2,1):uint(), 0x40)~=0
  then
    pkt.cols.info:append("Server ")
  else
    pkt.cols.info:append("Client ")
  end

  local origbuf = buf
  local totalconsumed = 0

  --print(pkt.number.." "..buf:len())

  -- wireshark 1.99.2 introduced dissect_tcp_pdus() to do this for us
  while buf:len()>0
  do
    local consumed = decode(buf,pkt,root)
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
  if buf:len()<8 or buf(0,1):uint()~=0xca or buf(1,1):uint()==0 or not bcommands[buf(3,1):uint()]
  then
      return false
  end
  pva.dissector(buf, pkt, root)
  pkt.conversation = pva
  return true
end

-- Wireshark 2.0 errors if the same protocol name is given for two
-- heuristic dissectors, even for different transports.
-- So don't register the udp dissector.  This prevents decoding of
-- search replies from pvAccessCPP which sends from a random port
--pva:register_heuristic("udp", test_pva)
local status, err = pcall(function() pva:register_heuristic("tcp", test_pva) end)
if not status then
  print("Failed to register PVA heuristic dissector.  Must manually specify TCP port! (try newer wireshark?)")
  print(err)
end

local function decodeStatus (buf, pkt, t, isbe)
  local code = buf(0,1):uint()
  local subt = t:add(fstatus, buf(0,1))
  if buf:len()>1 then
    buf = buf(1):tvb()
  end
  if code==0xff
  then
    return buf
  else
    local message, stack
    message, buf = decodeString(buf, isbe)
    stack, buf = decodeString(buf, isbe)
    subt:append_text(message:string())
    if(code~=0 and stack:len()>0)
    then
      subt:add_expert_info(PI_RESPONSE_CODE, PI_WARN, stack:string())
    end
    return buf
  end
end

local function pva_client_search (buf, pkt, t, isbe, cmd)
    local seq, port
    if isbe then
        seq = buf(0,4):uint()
        port = buf(24,2):uint()
    else
        seq = buf(0,4):le_uint()
        port = buf(24,2):le_uint()
    end
    pkt.cols.info:append("SEARCH("..seq)

    t:add(fsearch_seq, buf(0,4), seq)
    local mask = t:add(fsearch_mask, buf(4,1))
    mask:add(fsearch_mask_repl, buf(4,1))
    mask:add(fsearch_mask_bcast, buf(4,1))
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
    if npv>0 then
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

            pkt.cols.info:append(', '..cid..":'"..name:string().."'")
        end
    end
    pkt.cols.info:append("), ")
end

local function pva_server_search_response (buf, pkt, t, isbe, cmd)
    local seq, port
    if isbe then
        seq = buf(12,4):uint()
        port = buf(32,2):uint()
    else
        seq = buf(12,4):le_uint()
        port = buf(32,2):le_uint()
    end
    pkt.cols.info:append("SEARCH_RESPONSE("..seq)

    t:add(fguid, buf(0,12))
    t:add(fsearch_seq, buf(12,4), seq)
    t:add(fsearch_addr, buf(16,16))
    t:add(fsearch_port, buf(32,2), port)

    local proto
    proto, buf = decodeString(buf(34), isbe)
    t:add(fsearch_proto, proto)

    t:add(fsearch_found, buf(0, 1))

    local npv
    if isbe then
        npv = buf(1,2):uint()
    else
        npv = buf(1,2):le_uint()
    end
    if npv>0 then
        buf = buf(3)

        for i=0,npv-1 do
            local cid, name

            if isbe then
                cid = buf(i*4,4):uint()
            else
                cid = buf(i*4,4):le_uint()
            end
            t:add(fsearch_cid, buf(i*4,4), cid)

            pkt.cols.info:append(', '..cid)
        end
    end
    pkt.cols.info:append(")")

end

local function pva_client_validate (buf, pkt, t, isbe, cmd)
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

local function pva_client_create_channel (buf, pkt, t, isbe, cmd)
    pkt.cols.info:append("CREATE_CHANNEL(")
    local npv
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

        if i<npv-1 then pkt.cols.info:append("', '") end
        pkt.cols.info:append("'"..name:string())
    end
    pkt.cols.info:append("'), ")
end

local function pva_server_create_channel (buf, pkt, t, isbe, cmd)
    local cid, sid
    if isbe
    then
        cid = buf(0,4):uint()
        sid = buf(4,4):uint()
    else
        cid = buf(0,4):le_uint()
        sid = buf(4,4):le_uint()
    end
    pkt.cols.info:append("CREATE_CHANNEL(cid="..cid..", sid="..sid.."), ")
    t:add(fcid, buf(0,4), cid)
    t:add(fsid, buf(4,4), sid)
    decodeStatus(buf(8), pkt, t, isbe)
end

local function pva_destroy_channel (buf, pkt, t, isbe, cmd)
    local cid, sid
    if isbe
    then
        sid = buf(0,4):uint()
        cid = buf(4,4):uint()
    else
        sid = buf(0,4):le_uint()
        cid = buf(4,4):le_uint()
    end
    pkt.cols.info:append("DESTROY_CHANNEL(cid="..cid..", sid="..sid.."), ")
    t:add(fsid, buf(0,4), sid)
    t:add(fcid, buf(4,4), cid)
end

local function pva_client_op (buf, pkt, t, isbe, cmd)
    local cname = bcommands[cmd]
    local sid, ioid, subcmd
    if isbe
    then
        sid = buf(0,4):uint()
        ioid = buf(4,4):uint()
    else
        sid = buf(0,4):le_uint()
        ioid = buf(4,4):le_uint()
    end
    subcmd = buf(8,1):uint()
    t:add(fsid, buf(0,4), sid)
    t:add(fioid, buf(4,4), ioid)
    local cmd = t:add(fsubcmd, buf(8,1), subcmd)
    cmd:add(fsubcmd_proc, buf(8,1), subcmd)
    cmd:add(fsubcmd_init, buf(8,1), subcmd)
    cmd:add(fsubcmd_dstr, buf(8,1), subcmd)
    cmd:add(fsubcmd_get, buf(8,1), subcmd)
    cmd:add(fsubcmd_gtpt, buf(8,1), subcmd)
    if buf:len()>9 then
        t:add(fpvd, buf(9))
    end

    pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u, sub=%02x), ", cname, sid, ioid, subcmd))
end


local function pva_server_op (buf, pkt, t, isbe, cmd)
    local cname = bcommands[cmd]
    local ioid, subcmd
    if isbe
    then
        ioid = buf(0,4):uint()
    else
        ioid = buf(0,4):le_uint()
    end
    subcmd = buf(4,1):uint()
    t:add(fioid, buf(0,4), ioid)
    local tcmd = t:add(fsubcmd, buf(4,1), subcmd)
    tcmd:add(fsubcmd_proc, buf(4,1), subcmd)
    tcmd:add(fsubcmd_init, buf(4,1), subcmd)
    tcmd:add(fsubcmd_dstr, buf(4,1), subcmd)
    tcmd:add(fsubcmd_get, buf(4,1), subcmd)
    tcmd:add(fsubcmd_gtpt, buf(4,1), subcmd)

    if cmd~=13 or bit.band(subcmd,0x08)~=0 then
        -- monitor updates have no status
        buf = decodeStatus(buf(5), pkt, t, isbe)
    end
    if buf and buf:len()>0 then
        t:add(fbody, buf(0))
    end

    pkt.cols.info:append(string.format("%s(ioid=%u, sub=%02x), ", cname, ioid, subcmd))
end

local function pva_client_op_destroy (buf, pkt, t, isbe, cmd)
    local cname = bcommands[cmd]
    local sid, ioid;
    if isbe
    then
        sid = buf(0,4):uint()
        ioid = buf(4,4):uint()
    else
        sid = buf(0,4):le_uint()
        ioid = buf(4,4):le_uint()
    end
    t:add(fsid, buf(0,4), sid)
    t:add(fioid, buf(4,4), ioid)

    pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u), ", cname, sid, ioid))
end

specials_server = {
    [4] = pva_server_search_response,
    [7] = pva_server_create_channel,
    [8] = pva_destroy_channel,
    [10] = pva_server_op,
    [11] = pva_server_op,
    [12] = pva_server_op,
    [13] = pva_server_op,
    [14] = pva_server_op,
    [20] = pva_server_op,
}
specials_client = {
    [1] = pva_client_validate,
    [3] = pva_client_search,
    [7] = pva_client_create_channel,
    [8] = pva_destroy_channel,
    [10] = pva_client_op,
    [11] = pva_client_op,
    [12] = pva_client_op,
    [13] = pva_client_op,
    [14] = pva_client_op,
    [15] = pva_client_op_destroy,
    [20] = pva_client_op,
    [21] = pva_client_op_destroy,
}

print("Loaded PVA")
