-- Wireshark Lua script plugin
-- packet disector for Channel Access protocol
--
-- https://github.com/mdavidsaver/cashark
--
-- Copyright 2012 Michael Davidsaver
--
-- Distribution and use subject to the EPICS Open License
-- See the file LICENSE
--
-- Revision 20130807


ca = Proto("ca", "Channel Access")

local bcommands = {
  [0] = "Version",
  [1] = "Event",
  [2] = "Event Cancel",
  [4] = "Write",
  [6] = "Search",
  [0x0b] = "Error",
  [0x0c] = "Clear Channel",
  [0x0d] = "Beacon",
  [0x0f] = "Read Notify",
  [0x11] = "Repeater Confirm",
  [0x12] = "Create Channel",
  [0x13] = "Write Notify",
  [0x14] = "User",
  [0x15] = "Host",
  [0x16] = "Rights",
  [0x18] = "Repeater Register",
  [0x1a] = "Create Channel Fail",
  [0x1b] = "Server Disconnect"
}

local fcmd  = ProtoField.uint16("ca.command", "Command", base.HEX, bcommands)
local fsize = ProtoField.uint32("ca.size", "Payload Size")

-- Plain fields
local ftype = ProtoField.uint16("ca.type", "Data Type", base.HEX)
local fcnt  = ProtoField.uint32("ca.count", "Data Count")
local fp1   = ProtoField.uint32("ca.p1", "Param 1", base.HEX)
local fp2   = ProtoField.uint32("ca.p2", "Param 2", base.HEX)
local fdata = ProtoField.bytes ("ca.data", "Data")

-- Specialized
local fserv = ProtoField.ipv4("ca.serv.ip", "Server IP")
local fport = ProtoField.uint16("ca.serv.port", "Server Port")
local brep  = { [0xa] = "Success or failure", [0x5] = "Only for Success" }
local frep  = ProtoField.uint16("ca.doreply", "Reply", base.HEX, brep)
local fver  = ProtoField.uint16("ca.version", "Version")
local fdtype= ProtoField.uint16("ca.dtype", "DBR Type")
local fcid  = ProtoField.uint32("ca.cid", "Client Channel ID", base.HEX)
local fsid  = ProtoField.uint32("ca.sid", "Server Channel ID", base.HEX)
local fioid = ProtoField.uint32("ca.ioid", "Client Operation ID", base.HEX)
local fdbr  = ProtoField.bytes ("ca.dbr", "DBR Data")
local fpv   = ProtoField.string("ca.pv", "PV Name")
local feca  = ProtoField.uint32("ca.eca", "Status", base.HEX)
local fmsg  = ProtoField.string("ca.error", "Error Message")

ca.fields = {fcmd, fsize, ftype, fcnt, fp1, fp2, fdata,
       fdbr, fpv, fserv, fport, frep, fver, fdtype, fcid, fsid, fioid,
       feca, fmsg}

local specials

function decodeheader(buf)
  local msglen = buf(2,2)
  local dcount = buf(6,2)

  local hlen=16
  if msglen:uint()==0xffff and dcount:uint()==0
  then
    if(buf:len()<24) then return buf:len()-24 end
    msglen = buf(16,4)
    dcount = buf(20,4)
    hlen=24
  end
  return msglen, dcount, hlen
end

-- Decode a single CA message
-- returns number of bytes consumed or a negative number giving
-- the number of bytes needed to complete the message
function decode (buf, pkt, root)
  if buf:len()<16 then return 0 end
    
  local cmd = buf(0,2)
  local msglen
  local dcount
  local hlen
  
  msglen, dcount, hlen = decodeheader(buf)
  --print("CA header "..hlen.." with "..msglen:uint())
  
  if buf:len()<hlen+msglen:uint()
  then
    return (buf:len()-(hlen+msglen:uint())), nil
  end

  t = root:add(ca, buf(0,hlen+msglen:uint()))
    
  t:add(fcmd, cmd)
  t:add(fsize,msglen)
  
  cmd=cmd:uint()

  spec=specials[cmd]
  if spec
  then
    -- use specialized decoder
    spec(buf, pkt, t, hlen, msglen:uint(), dcount)
    msglen=msglen:uint()
  else
    -- generic decode
    cmd_name = bcommands[cmd]
    if cmd_name
    then
      pkt.cols.info:append(cmd_name..", ")
    else
      pkt.cols.info:append("Msg: "..cmd.." ")
    end

    t:add(ftype,buf(4,2))
    t:add(fcnt, dcount)
    t:add(fp1 , buf(8,4))
    t:add(fp2 , buf(12,4))
  
    msglen=msglen:uint()
    dcount=dcount:uint()

    if msglen>0
    then
      t:add(fdata, buf(hlen,msglen))      
    end
  end
  
  return hlen+msglen
end

function ca.dissector (buf, pkt, root)

  pkt.cols.protocol = ca.name
  pkt.cols.info:clear()

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
    elseif consumed<16
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
utbl:add(5064, ca)
utbl:add(5065, ca)
local ttbl = DissectorTable.get("tcp.port")
ttbl:add(5064, ca)

function casearch (buf, pkt, t, hlen, msglen, dcount)
  if msglen==8 and buf(hlen,1):uint()==0
  then
    -- server message
    t:add(fport, buf(4,2))
    t:add(fserv , buf(8,4))
    t:add(fcid , buf(12,4))
    t:add(fver, buf(hlen+2,2))
    pkt.cols.info:append("Search Reply("..buf(12,4):uint().."), ")
  else
    -- client message
    t:add(frep, buf(4,2))
    t:add(fver, dcount)
    t:add(fcid, buf(8,4))
    tp2 = t:add(fp2 , buf(12,4))
    if(buf(8,4):uint()~=buf(12,4):uint())
    then
      tp2:add_expert_info(PI_MALFORMED, PI_ERROR, "CID mismatch")
    end
    t:add(fpv, buf(hlen,msglen))
    pkt.cols.info:append("Search('"..buf(hlen,msglen):string())
    pkt.cols.info:append("',"..buf(8,4):uint().."), ")
  end
end

function cacreatechan (buf, pkt, t, hlen, msglen, dcount)
  if msglen==0
  then
    -- server message
    t:add(fdtype,buf(4,2))
    t:add(fcnt, dcount)
    t:add(fcid , buf(8,4))
    t:add(fsid , buf(12,4))
    pkt.cols.info:append("Create Reply(cid="..buf(8,4):uint()..", sid="..buf(12,4):uint().."), ")
  else
    -- client message
    t:add(fcid , buf(8,4))
    t:add(fver , buf(12,4))
    t:add(fpv, buf(hlen,msglen))
    pvname=buf(hlen,msglen):string()
    pkt.cols.info:append("Create Request('"..pvname)
    pkt.cols.info:append("', cid="..buf(8,4):uint().."), ")
  end
  return dir
end

function careadnotify (buf, pkt, t, hlen, msglen, dcount)
  t:add(fdtype,buf(4,2))
  t:add(fcnt, dcount)
  t:add(fioid, buf(12,4))
  if msglen==0 and dcount~=0
  then
    -- client message (request)
    t:add(fsid , buf(8,4))
    pkt.cols.info:append("Read Request(sid="..buf(8,4):uint()..", ioid="..buf(12,4):uint().."), ")
  else
    -- server message (reply)
    t:add(feca , buf(8,4))
    t:add(fdata, buf(hlen,msglen))
    pkt.cols.info:append("Read Reply(ioid="..buf(12,4):uint().."), ")
  end
end

function cawritenotify (buf, pkt, t, hlen, msglen, dcount)
  t:add(fdtype,buf(4,2))
  t:add(fcnt, dcount)
  t:add(fioid, buf(12,4))
  if msglen==0 and dcount~=0
  then
    -- server message (reply)
    t:add(feca , buf(8,4))
    pkt.cols.info:append("Write Reply(sid="..buf(8,4):uint()..", ioid="..buf(12,4):uint().."), ")
  else
    -- client message (request)
    t:add(fsid , buf(8,4))
    t:add(fdata, buf(hlen,msglen))
    pkt.cols.info:append("Write Request(ioid="..buf(12,4):uint().."), ")
  end
end

function cawrite (buf, pkt, t, hlen, msglen, dcount)
  -- client message (request)
  t:add(fdtype,buf(4,2))
  t:add(fcnt, dcount)
  t:add(fioid, buf(12,4))
  t:add(fsid , buf(8,4))
  t:add(fdata, buf(hlen,msglen))
  pkt.cols.info:append("Write(ioid="..buf(12,4):uint().."), ")
end

function caerror (buf, pkt, t, hlen, msglen, dcount)

  t:add(ftype,buf(4,2))
  t:add(fcnt, dcount)
  t:add(fcid, buf(8,4))
  informeca(t, buf(12,4))

  emsglen, edcount, ehlen = decodeheader(buf(16):tvb())

  emsg = buf(16,ehlen):tvb()

  ehead = t:add(ca, emsg)

  ehead:add(fcmd, emsg(0,2))
  ehead:add(fsize,emsglen)
  ehead:add(ftype,emsg(4,2))
  ehead:add(fcnt, edcount)
  ehead:add(fp1 , emsg(8,4))
  ehead:add(fp2 , emsg(12,4))

  t:add(fmsg, buf(16+ehlen))

  pkt.cols.info:append("Error("..buf(16+ehlen):string()..")")
end

-- Specialized decoders for some message types
specials = {
 [4] = cawrite,
 [6] = casearch,
 [0x0b] = caerror,
 [0x0f] = careadnotify,
 [0x12] = cacreatechan,
 [0x13] = cawritenotify
}

-- awk -F '[ (),]+' '/define.*ECA/{printf " [%d] = \"%s\",\n", $5, $2}' caerr.h
ecamsg = {
 [0] = "ECA_NORMAL",
 [1] = "ECA_MAXIOC",
 [2] = "ECA_UKNHOST",
 [3] = "ECA_UKNSERV",
 [4] = "ECA_SOCK",
 [5] = "ECA_CONN",
 [6] = "ECA_ALLOCMEM",
 [7] = "ECA_UKNCHAN",
 [8] = "ECA_UKNFIELD",
 [9] = "ECA_TOLARGE",
 [10] = "ECA_TIMEOUT",
 [11] = "ECA_NOSUPPORT",
 [12] = "ECA_STRTOBIG",
 [13] = "ECA_DISCONNCHID",
 [14] = "ECA_BADTYPE",
 [15] = "ECA_CHIDNOTFND",
 [16] = "ECA_CHIDRETRY",
 [17] = "ECA_INTERNAL",
 [18] = "ECA_DBLCLFAIL",
 [19] = "ECA_GETFAIL",
 [20] = "ECA_PUTFAIL",
 [21] = "ECA_ADDFAIL",
 [22] = "ECA_BADCOUNT",
 [23] = "ECA_BADSTR",
 [24] = "ECA_DISCONN",
 [25] = "ECA_DBLCHNL",
 [26] = "ECA_EVDISALLOW",
 [27] = "ECA_BUILDGET",
 [28] = "ECA_NEEDSFP",
 [29] = "ECA_OVEVFAIL",
 [30] = "ECA_BADMONID",
 [31] = "ECA_NEWADDR",
 [32] = "ECA_NEWCONN",
 [33] = "ECA_NOCACTX",
 [34] = "ECA_DEFUNCT",
 [35] = "ECA_EMPTYSTR",
 [36] = "ECA_NOREPEATER",
 [37] = "ECA_NOCHANMSG",
 [38] = "ECA_DLCKREST",
 [39] = "ECA_SERVBEHIND",
 [40] = "ECA_NOCAST",
 [41] = "ECA_BADMASK",
 [42] = "ECA_IODONE",
 [43] = "ECA_IOINPROGRESS",
 [44] = "ECA_BADSYNCGRP",
 [45] = "ECA_PUTCBINPROG",
 [46] = "ECA_NORDACCESS",
 [47] = "ECA_NOWTACCESS",
 [48] = "ECA_ANACHRONISM",
 [49] = "ECA_NOSEARCHADDR",
 [50] = "ECA_NOCONVERT",
 [51] = "ECA_BADCHID",
 [52] = "ECA_BADFUNCPTR",
 [53] = "ECA_ISATTACHED",
 [54] = "ECA_UNAVAILINSERV",
 [55] = "ECA_CHANDESTROY",
 [56] = "ECA_BADPRIORITY",
 [57] = "ECA_NOTTHREADED",
 [58] = "ECA_16KARRAYCLIENT",
 [59] = "ECA_CONNSEQTMO",
 [60] = "ECA_UNRESPTMO"
}

function informeca (t, buf)
    local teca = t:add(feca, buf)
    local msg = ecamsg[math.floor(buf:uint()/8)] -- buf>>3
    if msg
    then
      teca:add_expert_info(PI_RESPONSE_CODE, PI_NOTE, msg)
    end
end

print("Load CA")
