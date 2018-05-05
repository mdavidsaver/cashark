-- Wireshark Lua script plugin
-- packet disector for Channel Access protocol
--
-- https://github.com/mdavidsaver/cashark
--
-- Copyright 2015 Michael Davidsaver
--
-- Distribution and use subject to the EPICS Open License
-- See the file LICENSE
--
-- Revision $Id$

print("Loading CA...")

local ca = Proto("ca", "Channel Access")

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
  [0x17] = "Echo",
  [0x18] = "Repeater Register",
  [0x1a] = "Create Channel Fail",
  [0x1b] = "Server Disconnect"
}

local ecacodes = {
  [0x001] = "ECA_NORMAL",
  [0x00a] = "ECA_MAXIOC",
  [0x012] = "ECA_UKNHOST",
  [0x01a] = "ECA_UKNSERV",
  [0x022] = "ECA_SOCK",
  [0x028] = "ECA_CONN",
  [0x030] = "ECA_ALLOCMEM",
  [0x038] = "ECA_UKNCHAN",
  [0x040] = "ECA_UKNFIELD",
  [0x048] = "ECA_TOLARGE",
  [0x050] = "ECA_TIMEOUT",
  [0x058] = "ECA_NOSUPPORT",
  [0x060] = "ECA_STRTOBIG",
  [0x06a] = "ECA_DISCONNCHID",
  [0x072] = "ECA_BADTYPE",
  [0x07b] = "ECA_CHIDNOTFND",
  [0x083] = "ECA_CHIDRETRY",
  [0x08e] = "ECA_INTERNAL",
  [0x090] = "ECA_DBLCLFAIL",
  [0x098] = "ECA_GETFAIL",
  [0x0a0] = "ECA_PUTFAIL",
  [0x0a8] = "ECA_ADDFAIL",
  [0x0b0] = "ECA_BADCOUNT",
  [0x0ba] = "ECA_BADSTR",
  [0x0c0] = "ECA_DISCONN",
  [0x0c8] = "ECA_DBLCHNL",
  [0x0d2] = "ECA_EVDISALLOW",
  [0x0d8] = "ECA_BUILDGET",
  [0x0e0] = "ECA_NEEDSFP",
  [0x0e8] = "ECA_OVEVFAIL",
  [0x0f2] = "ECA_BADMONID",
  [0x0f8] = "ECA_NEWADDR",
  [0x103] = "ECA_NEWCONN",
  [0x108] = "ECA_NOCACTX",
  [0x116] = "ECA_DEFUNCT",
  [0x118] = "ECA_EMPTYSTR",
  [0x120] = "ECA_NOREPEATER",
  [0x128] = "ECA_NOCHANMSG",
  [0x130] = "ECA_DLCKREST",
  [0x138] = "ECA_SERVBEHIND",
  [0x140] = "ECA_NOCAST",
  [0x14a] = "ECA_BADMASK",
  [0x153] = "ECA_IODONE",
  [0x15b] = "ECA_IOINPROGRESS",
  [0x162] = "ECA_BADSYNCGRP",
  [0x16a] = "ECA_PUTCBINPROG",
  [0x170] = "ECA_NORDACCESS",
  [0x178] = "ECA_NOWTACCESS",
  [0x182] = "ECA_ANACHRONISM",
  [0x188] = "ECA_NOSEARCHADDR",
  [0x190] = "ECA_NOCONVERT",
  [0x19a] = "ECA_BADCHID",
  [0x1a2] = "ECA_BADFUNCPTR",
  [0x1a8] = "ECA_ISATTACHED",
  [0x1b0] = "ECA_UNAVAILINSERV",
  [0x1b8] = "ECA_CHANDESTROY",
  [0x1c2] = "ECA_BADPRIORITY",
  [0x1ca] = "ECA_NOTTHREADED",
  [0x1d0] = "ECA_16KARRAYCLIENT",
  [0x1d8] = "ECA_CONNSEQTMO",
  [0x1e0] = "ECA_UNRESPTMO"
}


local rights = {
  [0] = "NA",
  [1] = "RO",
  [2] = "WO",
  [3] = "RW"
}

-- Data fields
local status = ProtoField.int16("ca.data.status", "Status", base.DEC)
local severity = ProtoField.int16("ca.data.severity", "Severity", base.DEC)
local timestamp_sec = ProtoField.uint32("ca.data.timestamp.sec", "Timestamp Seconds", base.DEC)
local timestamp_nsec = ProtoField.uint32("ca.data.timestamp.nsec", "Timestamp Nanoseconds", base.DEC)
local unit = ProtoField.string("ca.data.units", "Unit")
local precision = ProtoField.int16("ca.data.precision", "Precision", base.DEC)
local no_str = ProtoField.int16("ca.data.no_str", "Number of Strings", base.DEC)
local enum_str = ProtoField.string("ca.data.no_str", "Enum String")
local padding_char = ProtoField.uint8("ca.data.padding", "Padding", base.DEC)
local padding_short = ProtoField.uint16("ca.data.padding", "Padding", base.DEC)
local padding_long = ProtoField.uint32("ca.data.padding", "Padding", base.DEC)

local upper_disp_limit_char = ProtoField.int8("ca.data.upper_disp_limit", "Upper Display Limit", base.DEC)
local lower_disp_limit_char = ProtoField.int8("ca.data.lower_disp_limit", "Lower Display Limit", base.DEC)
local upper_alarm_limit_char = ProtoField.int8("ca.data.upper_alarm_limit", "Upper Alarm Limit", base.DEC)
local upper_warning_limit_char = ProtoField.int8("ca.data.upper_warning_limit", "Upper Warning Limit", base.DEC)
local lower_warning_limit_char = ProtoField.int8("ca.data.lower_warning_limit", "Lower Warning Limit", base.DEC)
local lower_alarm_limit_char = ProtoField.int8("ca.data.lower_alarm_limit", "Lower Alarm Limit", base.DEC)
local upper_ctrl_limit_char = ProtoField.int8("ca.data.upper_ctr_limit", "Upper Control Limit", base.DEC)
local lower_ctrl_limit_char = ProtoField.int8("ca.data.lower_ctrl_limit", "Lower Control Limit", base.DEC)

local upper_disp_limit_short = ProtoField.int16("ca.data.upper_disp_limit", "Upper Display Limit", base.DEC)
local lower_disp_limit_short = ProtoField.int16("ca.data.lower_disp_limit", "Lower Display Limit", base.DEC)
local upper_alarm_limit_short = ProtoField.int16("ca.data.upper_alarm_limit", "Upper Alarm Limit", base.DEC)
local upper_warning_limit_short = ProtoField.int16("ca.data.upper_warning_limit", "Upper Warning Limit", base.DEC)
local lower_warning_limit_short = ProtoField.int16("ca.data.lower_warning_limit", "Lower Warning Limit", base.DEC)
local lower_alarm_limit_short = ProtoField.int16("ca.data.lower_alarm_limit", "Lower Alarm Limit", base.DEC)
local upper_ctrl_limit_short = ProtoField.int16("ca.data.upper_ctr_limit", "Upper Control Limit", base.DEC)
local lower_ctrl_limit_short = ProtoField.int16("ca.data.lower_ctrl_limit", "Lower Control Limit", base.DEC)

local upper_disp_limit_long = ProtoField.int32("ca.data.upper_disp_limit", "Upper Display Limit", base.DEC)
local lower_disp_limit_long = ProtoField.int32("ca.data.lower_disp_limit", "Lower Display Limit", base.DEC)
local upper_alarm_limit_long = ProtoField.int32("ca.data.upper_alarm_limit", "Upper Alarm Limit", base.DEC)
local upper_warning_limit_long = ProtoField.int32("ca.data.upper_warning_limit", "Upper Warning Limit", base.DEC)
local lower_warning_limit_long = ProtoField.int32("ca.data.lower_warning_limit", "Lower Warning Limit", base.DEC)
local lower_alarm_limit_long = ProtoField.int32("ca.data.lower_alarm_limit", "Lower Alarm Limit", base.DEC)
local upper_ctrl_limit_long = ProtoField.int32("ca.data.upper_ctr_limit", "Upper Control Limit", base.DEC)
local lower_ctrl_limit_long = ProtoField.int32("ca.data.lower_ctrl_limit", "Lower Control Limit", base.DEC)

local upper_disp_limit_float = ProtoField.float("ca.data.upper_disp_limit", "Upper Display Limit", base.DEC)
local lower_disp_limit_float = ProtoField.float("ca.data.lower_disp_limit", "Lower Display Limit", base.DEC)
local upper_alarm_limit_float = ProtoField.float("ca.data.upper_alarm_limit", "Upper Alarm Limit", base.DEC)
local upper_warning_limit_float = ProtoField.float("ca.data.upper_warning_limit", "Upper Warning Limit", base.DEC)
local lower_warning_limit_float = ProtoField.float("ca.data.lower_warning_limit", "Lower Warning Limit", base.DEC)
local lower_alarm_limit_float = ProtoField.float("ca.data.lower_alarm_limit", "Lower Alarm Limit", base.DEC)
local upper_ctrl_limit_float = ProtoField.float("ca.data.upper_ctr_limit", "Upper Control Limit", base.DEC)
local lower_ctrl_limit_float = ProtoField.float("ca.data.lower_ctrl_limit", "Lower Control Limit", base.DEC)

local upper_disp_limit_double = ProtoField.double("ca.data.upper_disp_limit", "Upper Display Limit", base.DEC)
local lower_disp_limit_double = ProtoField.double("ca.data.lower_disp_limit", "Lower Display Limit", base.DEC)
local upper_alarm_limit_double = ProtoField.double("ca.data.upper_alarm_limit", "Upper Alarm Limit", base.DEC)
local upper_warning_limit_double = ProtoField.double("ca.data.upper_warning_limit", "Upper Warning Limit", base.DEC)
local lower_warning_limit_double = ProtoField.double("ca.data.lower_warning_limit", "Lower Warning Limit", base.DEC)
local lower_alarm_limit_double = ProtoField.double("ca.data.lower_alarm_limit", "Lower Alarm Limit", base.DEC)
local upper_ctrl_limit_double = ProtoField.double("ca.data.upper_ctr_limit", "Upper Control Limit", base.DEC)
local lower_ctrl_limit_double = ProtoField.double("ca.data.lower_ctrl_limit", "Lower Control Limit", base.DEC)

local value_string = ProtoField.string("ca.data.value", "Value", base.UNICODE)
local value_char = ProtoField.uint8("ca.data.value", "Value", base.DEC)
local value_short = ProtoField.int16("ca.data.value", "Value", base.DEC)
local value_long = ProtoField.int32("ca.data.value", "Value", base.DEC)
local value_enum = ProtoField.uint16("ca.data.value", "Value", base.DEC)
local value_float = ProtoField.float("ca.data.value", "Value")
local value_double = ProtoField.double("ca.data.value", "Value")

-- Data Struct Descriptions
local gr_enum = {status, severity, no_str}
for var=1,max_enum_states do
    table.insert(gr_enum, enum_str)
end
table.insert(gr_enum, value_enum)

local dbrtypes = {
  [0] = {"STRING", {value_string}},
  [1] = {"INT", {value_short}},
  [1] = {"SHORT", {value_short}},
  [2] = {"FLOAT", {value_float}},
  [3] = {"ENUM", {value_enum}},
  [4] = {"CHAR", {value_char}},
  [5] = {"LONG", {value_long}},
  [6] = {"DOUBLE", {value_double}},
  [7] = {"STS_STRING", {status, severity, value_string}},
  [8] = {"STS_INT", {status, severity, value_short}},
  [8] = {"STS_SHORT", {status, severity, value_short}},
  [9] = {"STS_FLOAT", {status, severity, value_long}},
  [10] = {"STS_ENUM", {status, severity, value_enum}},
  [11] = {"STS_CHAR", {status, severity, value_char}},
  [12] = {"STS_LONG", {status, severity, value_long}},
  [13] = {"STS_DOUBLE", {status, severity, value_double}},
  [14] = {"TIME_STRING", {status, severity, timestamp_sec, timestamp_nsec, value_string}},
  [15] = {"TIME_INT", {status, severity, timestamp_sec, timestamp_nsec, padding_short, value_short}},
  [15] = {"TIME_SHORT", {status, severity, timestamp_sec, timestamp_nsec, padding_short, value_short}},
  [16] = {"TIME_FLOAT", {status, severity, timestamp_sec, timestamp_nsec, value_float}},
  [17] = {"TIME_ENUM", {status, severity, timestamp_sec, timestamp_nsec, padding_short, value_enum}},
  [18] = {"TIME_CHAR", {status, severity, timestamp_sec, timestamp_nsec, padding_short, padding_char, value_char}},
  [19] = {"TIME_LONG", {status, severity, timestamp_sec, timestamp_nsec, value_long}},
  [20] = {"TIME_DOUBLE", {status, severity, timestamp_sec, timestamp_nsec, padding_long, value_double}},
  [21] = {"GR_STRING", {status, severity, value_string}},
  [22] = {"GR_INT", {status, severity, unit, upper_disp_limit_short, lower_disp_limit_short, upper_alarm_limit_short, upper_warning_limit_short, lower_warning_limit_short, lower_alarm_limit_short, value_short}},
  [22] = {"GR_SHORT", {status, severity, unit, upper_disp_limit_short, lower_disp_limit_short, upper_alarm_limit_short, upper_warning_limit_short, lower_warning_limit_short, lower_alarm_limit_short, value_short}},
  [23] = {"GR_FLOAT", {status, severity, precision, padding_short, unit, upper_disp_limit_float, lower_disp_limit_float, upper_alarm_limit_float, upper_warning_limit_float, lower_warning_limit_float, lower_alarm_limit_float, value_float}},
  [24] = {"GR_ENUM", gr_enum},
  [25] = {"GR_CHAR", {status, severity, unit, upper_disp_limit_char, lower_disp_limit_char, upper_alarm_limit_char, upper_warning_limit_char, lower_warning_limit_char, lower_alarm_limit_char, padding_char, value_char}},
  [26] = {"GR_LONG", {status, severity, unit, upper_disp_limit_long, lower_disp_limit_long, upper_alarm_limit_long, upper_warning_limit_long, lower_warning_limit_long, lower_alarm_limit_long, value_long}},
  [27] = {"GR_DOUBLE", {status, severity, unit, upper_disp_limit_double, lower_disp_limit_double, upper_alarm_limit_double, upper_warning_limit_double, lower_warning_limit_double, lower_alarm_limit_double, value_double}},
  [28] = {"CTRL_STRING", {status, severity, value_string}},
  [29] = {"CTRL_INT", {status, severity, unit, upper_disp_limit_short, lower_disp_limit_short, upper_alarm_limit_short, upper_warning_limit_short, lower_warning_limit_short, lower_alarm_limit_short, upper_ctrl_limit_short, lower_ctrl_limit_short, value_short}},
  [29] = {"CTRL_SHORT", {status, severity, unit, upper_disp_limit_short, lower_disp_limit_short, upper_alarm_limit_short, upper_warning_limit_short, lower_warning_limit_short, lower_alarm_limit_short, upper_ctrl_limit_short, lower_ctrl_limit_short, value_short}},
  [30] = {"CTRL_FLOAT", {status, severity, precision, padding_short, unit, upper_disp_limit_float, lower_disp_limit_float, upper_alarm_limit_float, upper_warning_limit_float, lower_warning_limit_float, lower_alarm_limit_float, upper_ctrl_limit_float, lower_ctrl_limit_float, value_float}},
  [31] = {"CTRL_ENUM", gr_enum},
  [32] = {"CTRL_CHAR", {status, severity, unit, upper_disp_limit_char, lower_disp_limit_char, upper_alarm_limit_char, upper_warning_limit_char, lower_warning_limit_char, lower_alarm_limit_char, upper_ctrl_limit_char, lower_ctrl_limit_char, padding_char, value_char}},
  [33] = {"CTRL_LONG", {status, severity, unit, upper_disp_limit_long, lower_disp_limit_long, upper_alarm_limit_long, upper_warning_limit_long, lower_warning_limit_long, lower_alarm_limit_long, upper_ctrl_limit_long, lower_ctrl_limit_long, value_long}},
  [34] = {"CTRL_DOUBLE", {status, severity, precision, padding_short, unit, upper_disp_limit_double, lower_disp_limit_double, upper_alarm_limit_double, upper_warning_limit_double, lower_warning_limit_double, lower_alarm_limit_double, upper_ctrl_limit_double, lower_ctrl_limit_double, value_double}},
  [35] = {"PUT_ACKT", {}},
  [36] = {"PUT_ACKS", {}},
  [37] = {"STSACK_STRING", {}},
  [38] = {"CLASS_NAME", {}}
}

local function map(func, array)
  local new_array = {}
  for i,v in ipairs(array) do
    new_array[i] = func(v)
  end
  return new_array
end

local bit = {[0] = "Clear", [1] = "Set"}


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
local fdtype= ProtoField.uint16("ca.dtype", "DBR Type", base.DEC, map(function(x) return x[1] end, dbrtypes))
local fright= ProtoField.uint32("ca.rights", "Rights", base.HEX, rights)
local fcid  = ProtoField.uint32("ca.cid", "Client Channel ID")
local fsid  = ProtoField.uint32("ca.sid", "Server Channel ID")
local fioid = ProtoField.uint32("ca.ioid", "Operation ID")
local fsub  = ProtoField.uint32("ca.sub", "Subscription ID")
local fdbr  = ProtoField.bytes ("ca.dbr", "DBR Data")
local fpv   = ProtoField.string("ca.pv", "PV Name")
local fbeac = ProtoField.uint16("ca.beacon", "Beacon number")
local feca  = ProtoField.uint32("ca.eca", "Status", base.HEX, ecacodes)
local fmsg  = ProtoField.string("ca.error", "Error Message")
local fstr  = ProtoField.string("ca.str", "Payload String")

local fmask = ProtoField.uint16("ca.mask", "Event Mask", base.HEX)
local fmask_val = ProtoField.uint16("ca.mask.val", "DBE_VALUE", base.DEC, bit, 0x1)
local fmask_log = ProtoField.uint16("ca.mask.log", "DBE_LOG", base.DEC, bit, 0x2)
local fmask_alm = ProtoField.uint16("ca.mask.alarm", "DBE_ALARM", base.DEC, bit, 0x4)
local fmask_prp = ProtoField.uint16("ca.mask.prop", "DBE_PROP", base.DEC, bit, 0x8)

local element = ProtoField.bytes("ca.data.element", "Element", base.None)

ca.fields = {fcmd, fsize, ftype, fcnt, fp1, fp2, fdata,
    fdbr, fpv, fserv, fport, frep, fver, fdtype, fright, fcid, fsid, fioid, fsub,
    fbeac, feca, fmsg, fstr,
    fmask, fmask_val, fmask_log, fmask_alm, fmask_prp,
    status, severity, timestamp_sec, timestamp_nsec, unit, precision, no_str, enum_str,
    padding_char, padding_short, padding_long,
    upper_disp_limit_char, lower_disp_limit_char, upper_alarm_limit_char, upper_warning_limit_char, lower_warning_limit_char, lower_alarm_limit_char,
    upper_disp_limit_short, lower_disp_limit_short, upper_alarm_limit_short, upper_warning_limit_short, lower_warning_limit_short, lower_alarm_limit_short,
    upper_disp_limit_long, lower_disp_limit_long, upper_alarm_limit_long, upper_warning_limit_long, lower_warning_limit_long, lower_alarm_limit_long,
    upper_disp_limit_float, lower_disp_limit_float, upper_alarm_limit_float, upper_warning_limit_float, lower_warning_limit_float, lower_alarm_limit_float,
    upper_disp_limit_double, lower_disp_limit_double, upper_alarm_limit_double, upper_warning_limit_double, lower_warning_limit_double, lower_alarm_limit_double,
    value_string, value_char, value_short, value_long, value_enum, value_float, value_double,
    element
}

local specials

local function decodeheader(buf)
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
local function decode (buf, pkt, root)
  if buf:len()<16 then return 0 end
    
  local cmd = buf(0,2)
  local msglen
  local dcount
  local hlen
  
  msglen, dcount, hlen = decodeheader(buf)
  --print("CA header "..hlen.." with "..msglen:uint())
  
  if buf:len()<hlen+msglen:uint()
  then
    return (buf:len()-(hlen+msglen:uint()))
  end

  local t = root:add(ca, buf(0,hlen+msglen:uint()))
    
  t:add(fcmd, cmd)
  t:add(fsize,msglen)
  
  cmd=cmd:uint()

  local spec=specials[cmd]
  if spec
  then
    -- use specialized decoder
    spec(buf, pkt, t, hlen, msglen:uint(), dcount)
    msglen=msglen:uint()
  else
    -- generic decode
    local cmd_name = bcommands[cmd]
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
  pkt.cols.info:append(pkt.src_port.."->"..pkt.dst_port.." ")

  local origbuf = buf
  local totalconsumed = 0

  --print(pkt.number.." "..buf:len())

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

local function caversion (buf, pkt, t, hlen, msglen, dcount)
  t:add(fver, buf(6,2))
  pkt.cols.info:append("Version("..buf(6,2):uint().."), ")
end

local function causer (buf, pkt, t, hlen, msglen, dcount)
  t:add(fstr, buf(hlen,msglen))
  pkt.cols.info:append("User('"..buf(hlen,msglen):string())
  pkt.cols.info:append("'), ")
end

local function cahost (buf, pkt, t, hlen, msglen, dcount)
  t:add(fstr, buf(hlen,msglen))
  pkt.cols.info:append("Host('"..buf(hlen,msglen):string())
  pkt.cols.info:append("'), ")
end

local function casearch (buf, pkt, t, hlen, msglen, dcount)
  if msglen==0 or (msglen==8 and buf(hlen,1):uint()==0)
  then
    -- server message
    t:add(fport, buf(4,2))
    t:add(fserv , buf(8,4))
    t:add(fcid , buf(12,4))
    if msglen==8 then
      t:add(fver, buf(hlen+2,2))
    end
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

local function cacreatechan (buf, pkt, t, hlen, msglen, dcount)
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

local function carights (buf, pkt, t, hlen, msglen, dcount)
  t:add(fcid , buf(8,4))
  t:add(fright , buf(12,4))
  local rt = rights[buf(12,4):uint()] or "??"
  pkt.cols.info:append("Rights(cid="..buf(8,4):uint()..", "..rt.."), ")
end

local function cacleanchan (buf, pkt, t, hlen, msglen, dcount)
  t:add(fsid, buf(8,4))
  t:add(fcid, buf(12,4))
  pkt.cols.info:append("Clear Channel(cid="..buf(12,4):uint()..", sid="..buf(8,4):uint().."), ")
end

local function careadnotify (buf, pkt, t, hlen, msglen, dcount)
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

local function cawritenotify (buf, pkt, t, hlen, msglen, dcount)
  t:add(fdtype,buf(4,2))
  t:add(fcnt, dcount)
  t:add(fioid, buf(12,4))
  if msglen==0 and dcount~=0
  then
    -- server message (reply)
    t:add(feca , buf(8,4))
    pkt.cols.info:append("Write Reply(ioid="..buf(12,4):uint().."), ")
  else
    -- client message (request)
    t:add(fsid , buf(8,4))
    t:add(fdata, buf(hlen,msglen))
    pkt.cols.info:append("Write Request(sid="..buf(8,4):uint()..", ioid="..buf(12,4):uint().."), ")
  end
end

local function cawrite (buf, pkt, t, hlen, msglen, dcount)
  -- client message (request)
  t:add(fdtype,buf(4,2))
  t:add(fcnt, dcount)
  t:add(fioid, buf(12,4))
  t:add(fsid , buf(8,4))
  t:add(fdata, buf(hlen,msglen))
  pkt.cols.info:append("Write(sid="..buf(8,4):uint()..", ioid="..buf(12,4):uint().."), ")
end

local function caevent (buf, pkt, t, hlen, msglen, dcount)
  t:add(fdtype,buf(4,2))
  t:add(fcnt, dcount)
  t:add(fsub, buf(12,4))
  if msglen==16
  then
    if buf(16,4):uint()==0 and buf(20,4):uint()==0 and buf(24,4):uint()==0 and buf(28,2):uint()<256
    then
      -- ok, so *probably* a new subscription...
      t:add(fsid , buf(8,4))
      local m = t:add(fmask, buf(28,2))
      m:add(fmask_val, buf(28,2))
      m:add(fmask_log, buf(28,2))
      m:add(fmask_alm, buf(28,2))
      m:add(fmask_prp, buf(28,2))
      pkt.cols.info:append("Event Add(sid="..buf(8,4):uint()..", sub="..buf(12,4):uint()..", mask="..buf(28,2):uint().."), ")
      return
    end
  end
  -- a data update
  t:add(feca , buf(8,4))
  if msglen==0
  then
    -- the last monitor update after subscription cancel
    pkt.cols.info:append("Event Final(sub="..buf(12,4):uint().."), ")
  else
    t:add(fdata, buf(hlen,msglen))
    pkt.cols.info:append("Event(sub="..buf(12,4):uint().."), ")
  end
end

local function caeventcancel (buf, pkt, t, hlen, msglen, dcount)
  t:add(fdtype,buf(4,2))
  t:add(fcnt, dcount)
  t:add(fsid , buf(8,4))
  t:add(fsub, buf(12,4))
  pkt.cols.info:append("Event Cancel(sid="..buf(8,4):uint()..", sub="..buf(12,4):uint().."), ")
end

local function cabeacon (buf, pkt, t, hlen, msglen, dcount)
  t:add(fver,  buf(4,2))
  t:add(fport, buf(6,2))
  t:add(fbeac, buf(8,4))
  t:add(fserv, buf(12,4))
  pkt.cols.info:append("Beacon("..tostring(buf(12,4):ipv4())..":"..buf(6,2):uint()..", "..buf(8,4):uint().."), ")
end

local function caerror (buf, pkt, t, hlen, msglen, dcount)

  t:add(ftype,buf(4,2))
  t:add(fcnt, dcount)
  t:add(fcid, buf(8,4))
  t:add(feca, buf(12,4))

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
 [0] = caversion,
 [1] = caevent,
 [2] = caeventcancel,
 [4] = cawrite,
 [6] = casearch,
 [0x0b] = caerror,
 [0x0c] = cacleanchan,
 [0x0d] = cabeacon,
 [0x0f] = careadnotify,
 [0x12] = cacreatechan,
 [0x13] = cawritenotify,
 [0x14] = causer,
 [0x15] = cahost,
 [0x16] = carights
}

print("Loaded CA")
