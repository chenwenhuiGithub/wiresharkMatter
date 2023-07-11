local version_str = string.match(_VERSION, "%d+[.]%d*")
local version_num = version_str and tonumber(version_str) or 5.1
local bit = (version_num >= 5.2) and require("bit32") or require("bit")


local MASK_BTP_FLAGS_H          = 0x40
local MASK_BTP_FLAGS_M          = 0x20
local MASK_BTP_FLAGS_A          = 0x08
local MASK_BTP_FLAGS_E          = 0x04
local MASK_BTP_FLAGS_B          = 0x01
local MASK_BTP_RESERVE          = 0xf0
local MASK_BTP_FINAL_VER        = 0x0f
local MASK_FRAME_FLAGS_VER      = 0xf0
local MASK_FRAME_FLAGS_S        = 0x04
local MASK_FRAME_FLAGS_DSIZ     = 0x03
local MASK_FRAME_FLAGS_P        = 0x80
local MASK_FRAME_FLAGS_C        = 0x40
local MASK_FRAME_FLAGS_MX       = 0x20
local MASK_FRAME_FLAGS_RESERVE  = 0x1c
local MASK_FRAME_FLAGS_ST       = 0x03
local MASK_PROTO_FLAGS_V        = 0x10
local MASK_PROTO_FLAGS_SX       = 0x08
local MASK_PROTO_FLAGS_R        = 0x04
local MASK_PROTO_FLAGS_A        = 0x02
local MASK_PROTO_FLAGS_I        = 0x01


local PROTO_PID_SECURE_CHANNEL           = 0x0000
local PROTO_PID_INTERACTION_MODEL        = 0x0001
local PROTO_PID_BDX                      = 0x0002
local PROTO_PID_USER_DIRECTED_COMMISSION = 0x0003
local PROTO_PID_ECHO                     = 0x0004
local PROTO_OPCODE_PBKDFParamRequest     = 0x20
local PROTO_OPCODE_PBKDFParamResponse    = 0x21
local PROTO_OPCODE_PASE_Pake1            = 0x22
local PROTO_OPCODE_PASE_Pake2            = 0x23
local PROTO_OPCODE_PASE_Pake3            = 0x24
local PROTO_OPCODE_StatusReport          = 0x40


proto_matter_ble = Proto("matter_ble", "matter protocol over ble")


f_btp_flags_h           = ProtoField.uint8("matter.btp.flags.H", "H", base.HEX, Payload_type, MASK_BTP_FLAGS_H)
f_btp_flags_m           = ProtoField.uint8("matter.btp.flags.M", "M", base.HEX, Payload_type, MASK_BTP_FLAGS_M)
f_btp_flags_a           = ProtoField.uint8("matter.btp.flags.A", "A", base.HEX, Payload_type, MASK_BTP_FLAGS_A)
f_btp_flags_e           = ProtoField.uint8("matter.btp.flags.E", "E", base.HEX, Payload_type, MASK_BTP_FLAGS_E)
f_btp_flags_b           = ProtoField.uint8("matter.btp.flags.B", "B", base.HEX, Payload_type, MASK_BTP_FLAGS_B)
f_btp_opcode            = ProtoField.uint8("matter.btp.opcode", "Management Opcode", base.HEX)
f_btp_ack               = ProtoField.uint8("matter.btp.ack", "Ack Number", base.DEC)
f_btp_seq               = ProtoField.uint8("matter.btp.seq", "Sequence Number", base.DEC)
f_btp_len               = ProtoField.uint16("matter.btp.len", "Message Length", base.DEC)
f_btp_ver               = ProtoField.bytes("matter.btp.ver", "Version")
f_btp_rMtu              = ProtoField.uint16("matter.btp.rMtu", "Requested ATT_MTU", base.DEC)
f_btp_cWinSize          = ProtoField.uint8("matter.btp.cWinSize", "Client Window Size", base.DEC)
f_btp_reserve           = ProtoField.uint8("matter.btp.reserve", "Reserved", base.HEX, Payload_type, MASK_BTP_RESERVE)
f_btp_fVer              = ProtoField.uint8("matter.btp.fVer", "Final Protocol Version", base.HEX, Payload_type, MASK_BTP_FINAL_VER)
f_btp_sMtu              = ProtoField.uint16("matter.btp.sMtu", "Selected ATT_MTU", base.DEC)
f_btp_sWinSize          = ProtoField.uint8("matter.btp.sWinSize", "Selected Window Size", base.DEC)
f_frame_flags_ver       = ProtoField.uint8("matter.frame.flags.ver", "Version", base.HEX, Payload_type, MASK_FRAME_FLAGS_VER)
f_frame_flags_s         = ProtoField.uint8("matter.frame.flags.s", "S", base.HEX, Payload_type, MASK_FRAME_FLAGS_S)
f_frame_flags_dsiz      = ProtoField.uint8("matter.frame.flags.dsiz", "DSIZ", base.HEX, Payload_type, MASK_FRAME_FLAGS_DSIZ)
f_frame_sId             = ProtoField.uint16("matter.frame.sId", "Session Id", base.HEX)
f_frame_flags_p         = ProtoField.uint8("matter.frame.flags.p", "P", base.HEX, Payload_type, MASK_FRAME_FLAGS_P)
f_frame_flags_c         = ProtoField.uint8("matter.frame.flags.c", "C", base.HEX, Payload_type, MASK_FRAME_FLAGS_C)
f_frame_flags_mx        = ProtoField.uint8("matter.frame.flags.mx", "MX", base.HEX, Payload_type, MASK_FRAME_FLAGS_MX)
f_frame_flags_reserve   = ProtoField.uint8("matter.frame.flags.reserve", "Reserved", base.HEX, Payload_type, MASK_FRAME_FLAGS_RESERVE)
f_frame_flags_st        = ProtoField.uint8("matter.frame.flags.st", "Session Type", base.HEX, Payload_type, MASK_FRAME_FLAGS_ST)
f_frame_cnt             = ProtoField.uint32("matter.frame.cnt", "Message Counter", base.DEC)
f_frame_sNodeId         = ProtoField.uint64("matter.frame.snid", "Source Node Id", base.HEX)
f_frame_dNodeId         = ProtoField.uint64("matter.frame.dnid", "Destination Node Id", base.HEX)
f_frame_dGroupId        = ProtoField.uint16("matter.frame.dgid", "Destination Group Id", base.HEX)
f_frame_extLen          = ProtoField.uint16("matter.frame.extLen", "Message Extensions Length", base.HEX)
f_frame_extData         = ProtoField.bytes("matter.frame.extData", "Message Extensions Data")
f_proto_flags_v         = ProtoField.uint8("matter.proto.flags.v", "V", base.HEX, Payload_type, MASK_PROTO_FLAGS_V)
f_proto_flags_sx        = ProtoField.uint8("matter.proto.flags.sx", "SX", base.HEX, Payload_type, MASK_PROTO_FLAGS_SX)
f_proto_flags_r         = ProtoField.uint8("matter.proto.flags.r", "R", base.HEX, Payload_type, MASK_PROTO_FLAGS_R)
f_proto_flags_a         = ProtoField.uint8("matter.proto.flags.a", "A", base.HEX, Payload_type, MASK_PROTO_FLAGS_A)
f_proto_flags_i         = ProtoField.uint8("matter.proto.flags.i", "I", base.HEX, Payload_type, MASK_PROTO_FLAGS_I)
f_proto_opcode          = ProtoField.uint8("matter.proto.opcode", "Protocol Opcode", base.HEX)
f_proto_ecId            = ProtoField.uint16("matter.proto.ecId", "Exchange Id", base.HEX)
f_proto_pvId            = ProtoField.uint16("matter.proto.pvId", "Protocol Vendor Id", base.HEX)
f_proto_pId             = ProtoField.uint16("matter.proto.pId", "Protocol Id", base.HEX)
f_proto_ackCnt          = ProtoField.uint32("matter.proto.ackCnt", "Acknowledged Message Counter", base.HEX)
f_proto_extLen          = ProtoField.uint16("matter.proto.extLen", "Security Extensions Length", base.HEX)
f_proto_extData         = ProtoField.bytes("matter.proto.extData", "Security Extensions Data")


proto_matter_ble.fields = {
    f_btp_flags_h,
    f_btp_flags_m,
    f_btp_flags_a,
    f_btp_flags_e,
    f_btp_flags_b,
    f_btp_opcode,
    f_btp_ack,
    f_btp_seq,
    f_btp_len,
    f_btp_ver,
    f_btp_rMtu,
    f_btp_cWinSize,
    f_btp_reserve,
    f_btp_fVer,
    f_btp_sMtu,
    f_btp_sWinSize,
    f_frame_flags_ver,
    f_frame_flags_s,
    f_frame_flags_dsiz,
    f_frame_sId,
    f_frame_flags_p,
    f_frame_flags_c,
    f_frame_flags_mx,
    f_frame_flags_reserve,
    f_frame_flags_st,
    f_frame_cnt,
    f_frame_sNodeId,
    f_frame_dNodeId,
    f_frame_dGroupId,
    f_frame_extLen,
    f_frame_extData,
    f_proto_flags_v,
    f_proto_flags_sx,
    f_proto_flags_r,
    f_proto_flags_a,
    f_proto_flags_i,
    f_proto_opcode,
    f_proto_ecId,
    f_proto_pvId,
    f_proto_pId,
    f_proto_ackCnt,
    f_proto_extLen,
    f_proto_extData
}

function proto_matter_ble.dissector(tvb, pinfo, tree)
    local offset = 0
    local value_btp_flags = 0
    local value_frame_msg_flags = 0
    local value_frame_sec_flags = 0
    local value_frame_extLen = 0
    local value_proto_flags = 0
    local value_proto_pid = 0
    local value_proto_opcode = 0
    local value_proto_extLen = 0

    local tvb_len = tvb:len()
    if tvb_len < 6 then return end -- BTP handshark response(6B), BTP data(9B = BTP header(1B) + frame header(8B))

    pinfo.cols.protocol = "matter"

    local st = tree:add(proto_matter_ble, tvb(), "Matter Protocol")
    local st_btp_flags = st:add(proto_matter_ble, tvb(offset, 1), "BTP Flags")
    st_btp_flags:add(f_btp_flags_h, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_m, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_a, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_e, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_b, tvb(offset, 1))
    value_btp_flags = tvb(offset, 1):uint()
    offset = offset + 1

    if value_btp_flags == 0x65 then -- BTP handshark PDU
        st:add(f_btp_opcode, tvb(offset, 1))
        offset = offset + 1
        if tvb_len == 9 then
            pinfo.cols.info:prepend("[BTP handshark request] ")

            st:add(f_btp_ver, tvb(offset, 4))
            offset = offset + 4
            st:add_le(f_btp_rMtu, tvb(offset, 2))
            offset = offset + 2
            st:add_le(f_btp_cWinSize, tvb(offset, 1))
            offset = offset + 1
        elseif tvb_len == 6 then
            pinfo.cols.info:prepend("[BTP handshark response] ")

            local st_btp_fVer = st:add(proto_matter_ble, tvb(offset, 1), "Version")
            st_btp_fVer:add(f_btp_reserve, tvb(offset, 1))
            st_btp_fVer:add_le(f_btp_fVer, tvb(offset, 1))
            offset = offset + 1
            st:add_le(f_btp_sMtu, tvb(offset, 2))
            offset = offset + 2
            st:add_le(f_btp_sWinSize, tvb(offset, 1))
            offset = offset + 1
        end
    else -- BTP data PDU
        if bit.band(value_btp_flags, MASK_BTP_FLAGS_A) ~= 0 then
            st:add(f_btp_ack, tvb(offset, 1))
            offset = offset + 1
        end

        st:add(f_btp_seq, tvb(offset, 1))
        offset = offset + 1

        if bit.band(value_btp_flags, MASK_BTP_FLAGS_B) ~= 0 then
            st:add_le(f_btp_len, tvb(offset, 2))
            offset = offset + 2
        end

        if bit.band(value_btp_flags, MASK_BTP_FLAGS_E) ~= 0 then
            local st_btp_segment_payload = st:add(proto_matter_ble, tvb(offset, tvb:len() - offset), "Segment Payload")
            local st_frame_msg_flags = st_btp_segment_payload:add(proto_matter_ble, tvb(offset, 1), "Message Flags")
            st_frame_msg_flags:add(f_frame_flags_ver, tvb(offset, 1))
            st_frame_msg_flags:add(f_frame_flags_s, tvb(offset, 1))
            st_frame_msg_flags:add(f_frame_flags_dsiz, tvb(offset, 1))
            value_frame_msg_flags = tvb(offset, 1):uint()
            offset = offset + 1

            st_btp_segment_payload:add_le(f_frame_sId, tvb(offset, 2))
            offset = offset + 2

            local st_frame_sec_flags = st_btp_segment_payload:add(proto_matter_ble, tvb(offset, 1), "Security Flags")
            st_frame_sec_flags:add(f_frame_flags_p, tvb(offset, 1))
            st_frame_sec_flags:add(f_frame_flags_c, tvb(offset, 1))
            st_frame_sec_flags:add(f_frame_flags_mx, tvb(offset, 1))
            st_frame_sec_flags:add(f_frame_flags_reserve, tvb(offset, 1))
            st_frame_sec_flags:add(f_frame_flags_st, tvb(offset, 1))
            value_frame_sec_flags = tvb(offset, 1):uint()
            offset = offset + 1

            st_btp_segment_payload:add_le(f_frame_cnt, tvb(offset, 4))
            offset = offset + 4

            if bit.band(value_frame_msg_flags, MASK_FRAME_FLAGS_S) ~= 0 then
                st_btp_segment_payload:add(f_frame_sNodeId, tvb(offset, 8))
                offset = offset + 8
            end

            if bit.band(value_frame_msg_flags, MASK_FRAME_FLAGS_DSIZ) == 0x01 then
                st_btp_segment_payload:add(f_frame_dNodeId, tvb(offset, 8))
                offset = offset + 8                
            elseif bit.band(value_frame_msg_flags, MASK_FRAME_FLAGS_DSIZ) == 0x02 then
                st_btp_segment_payload:add(f_frame_dGroupId, tvb(offset, 2))
                offset = offset + 2                 
            end

            if bit.band(value_frame_sec_flags, MASK_FRAME_FLAGS_MX) ~= 0 then
                value_frame_extLen = tvb(offset, 2):le_uint()
                st_btp_segment_payload:add(f_frame_extLen, tvb(offset, 2))
                offset = offset + 2
                st_btp_segment_payload:add(f_frame_extData, tvb(offset, value_frame_extLen))
                offset = offset + value_frame_extLen
            end

            local st_frame_payload = st_btp_segment_payload:add(proto_matter_ble, tvb(offset, tvb:len() - offset), "Message Payload")
            local st_proto_header_exchange_flags = st_frame_payload:add(proto_matter_ble, tvb(offset, 1), "Exchange Flags")
            st_proto_header_exchange_flags:add(f_proto_flags_v, tvb(offset, 1))
            st_proto_header_exchange_flags:add(f_proto_flags_sx, tvb(offset, 1))
            st_proto_header_exchange_flags:add(f_proto_flags_r, tvb(offset, 1))
            st_proto_header_exchange_flags:add(f_proto_flags_a, tvb(offset, 1))
            st_proto_header_exchange_flags:add(f_proto_flags_i, tvb(offset, 1))
            value_proto_flags = tvb(offset, 1):uint()
            offset = offset + 1

            st_frame_payload:add(f_proto_opcode, tvb(offset, 1))
            value_proto_opcode = tvb(offset, 1):uint()
            offset = offset + 1

            st_frame_payload:add_le(f_proto_ecId, tvb(offset, 2))
            offset = offset + 2

            if bit.band(value_proto_flags, MASK_PROTO_FLAGS_V) ~= 0 then
                st_frame_payload:add_le(f_proto_pvId, tvb(offset, 2))
                offset = offset + 2
            end

            st_frame_payload:add_le(f_proto_pId, tvb(offset, 2))
            value_proto_pid = tvb(offset, 2):le_uint()
            offset = offset + 2

            if bit.band(value_proto_flags, MASK_PROTO_FLAGS_A) ~= 0 then
                st_frame_payload:add_le(f_proto_ackCnt, tvb(offset, 4))
                offset = offset + 4
            end

            if bit.band(value_proto_flags, MASK_PROTO_FLAGS_SX) ~= 0 then
                value_proto_extLen = tvb(offset, 2):le_uint()
                st_frame_payload:add(f_proto_extLen, tvb(offset, 2))
                offset = offset + 2
                st_frame_payload:add(f_proto_extData, tvb(offset, value_proto_extLen))
                offset = offset + value_proto_extLen
            end

            if value_proto_pid == PROTO_PID_SECURE_CHANNEL then
                if value_proto_opcode == PROTO_OPCODE_PBKDFParamRequest then
                    pinfo.cols.info:prepend("[SecureChannel:PBKDFParamRequest] ")
                elseif value_proto_opcode == PROTO_OPCODE_PBKDFParamResponse then
                    pinfo.cols.info:prepend("[SecureChannel:PBKDFParamResponse] ")
                elseif value_proto_opcode == PROTO_OPCODE_PASE_Pake1 then
                    pinfo.cols.info:prepend("[SecureChannel:PASE_Pake1] ")
                elseif value_proto_opcode == PROTO_OPCODE_PASE_Pake2 then
                    pinfo.cols.info:prepend("[SecureChannel:PASE_Pake2] ")
                elseif value_proto_opcode == PROTO_OPCODE_PASE_Pake3 then
                    pinfo.cols.info:prepend("[SecureChannel:PASE_Pake3] ")
                elseif value_proto_opcode == PROTO_OPCODE_StatusReport then
                    pinfo.cols.info:prepend("[SecureChannel:StatusReport] ")        
                end
            end

            local st_proto_app_payload = st_frame_payload:add(proto_matter_ble, tvb(offset, tvb:len() - offset), "Application Payload")
        end
    end
end


btatt_table = DissectorTable.get("btatt.handle")
btatt_table:add(0x0012, proto_matter_ble) -- 0x0012(C1),0x0014(C2) TODO: how to get handle automatically?
btatt_table:add(0x0014, proto_matter_ble)
