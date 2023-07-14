local version_str = string.match(_VERSION, "%d+[.]%d*")
local version_num = version_str and tonumber(version_str) or 5.1
local bit = (version_num >= 5.2) and require("bit32") or require("bit")


local MASK_BTP_FLAGS_H                      = 0x40
local MASK_BTP_FLAGS_M                      = 0x20
local MASK_BTP_FLAGS_A                      = 0x08
local MASK_BTP_FLAGS_E                      = 0x04
local MASK_BTP_FLAGS_B                      = 0x01
local MASK_BTP_RESERVE                      = 0xf0
local MASK_BTP_FINAL_VER                    = 0x0f
local MASK_FRAME_FLAGS_VER                  = 0xf0
local MASK_FRAME_FLAGS_S                    = 0x04
local MASK_FRAME_FLAGS_DSIZ                 = 0x03
local MASK_FRAME_FLAGS_P                    = 0x80
local MASK_FRAME_FLAGS_C                    = 0x40
local MASK_FRAME_FLAGS_MX                   = 0x20
local MASK_FRAME_FLAGS_RESERVE              = 0x1c
local MASK_FRAME_FLAGS_ST                   = 0x03
local MASK_PROTO_FLAGS_V                    = 0x10
local MASK_PROTO_FLAGS_SX                   = 0x08
local MASK_PROTO_FLAGS_R                    = 0x04
local MASK_PROTO_FLAGS_A                    = 0x02
local MASK_PROTO_FLAGS_I                    = 0x01


local PROTO_PID_SECURE_CHANNEL              = 0x0000
local PROTO_PID_INTERACTION_MODEL           = 0x0001
local PROTO_PID_BDX                         = 0x0002
local PROTO_PID_USER_DIRECTED_COMMISSION    = 0x0003
local PROTO_PID_ECHO                        = 0x0004
local PROTO_OPCODE_HANDSHARK                = 0x6c
local PROTO_OPCODE_PBKDFParamRequest        = 0x20
local PROTO_OPCODE_PBKDFParamResponse       = 0x21
local PROTO_OPCODE_PASE_Pake1               = 0x22
local PROTO_OPCODE_PASE_Pake2               = 0x23
local PROTO_OPCODE_PASE_Pake3               = 0x24
local PROTO_OPCODE_StatusReport             = 0x40


local TLV_END_OF_CONTAINER                  = 0x18
local TLV_CONTEXT_TAG_FALSE                 = 0x28
local TLV_CONTEXT_TAG_TRUE                  = 0x29


local BLE_ATT_OPCODE_WRITE_REQUEST          = 0x12
local BLE_ATT_OPCODE_INDICATION             = 0x1d


local vs_btp_flags_h        = {[0] = "Normal packet", [1] = "Handshake packet"}
local vs_btp_flags_m        = {[0] = "Management Opcode:Absence", [1] = "Management Opcode:Presence"}
local vs_btp_flags_a        = {[0] = "Ack Number:Absence", [1] = "Ack Number:Presence"}
local vs_btp_flags_e        = {[0] = "Last segment:Not", [1] = "Last segment:Yes"}
local vs_btp_flags_b        = {[0] = "First segment:Not", [1] = "First segment:Yes"}
local vs_btp_mOpcode        = {[PROTO_OPCODE_HANDSHARK] = "Handshake"}
local vs_frame_flags_s      = {[0] = "Source Node Id:Absence", [1] = "Source Node Id:Presence"}
local vs_frame_flags_dsiz   = {[0] = "Destination Node Id:Absence", [1] = "Destination Node Id:Node Id", [2] = "Destination Node Id:Group Id"}
local vs_frame_flags_p      = {[0] = "Privacy enhancement:Not", [1] = "Privacy enhancement:Yes"}
local vs_frame_flags_c      = {[0] = "Control message:Not", [1] = "Control message:Yes"}
local vs_frame_flags_mx     = {[0] = "Message Extensions:Absence", [1] = "Message Extensions:Presence"}
local vs_frame_flags_st     = {[0] = "Unicast Session", [1] = "Group Session"}
local vs_proto_flags_v      = {[0] = "Protocol Vendor Id:Absence", [1] = "Protocol Vendor Id:Presence"}
local vs_proto_flags_sx     = {[0] = "Security Extensions:Absence", [1] = "Security Extensions:Presence"}
local vs_proto_flags_r      = {[0] = "Wish ack:Not", [1] = "Wish ack:Yes"}
local vs_proto_flags_a      = {[0] = "Ack message:Not", [1] = "Ack message:Yes"}
local vs_proto_flags_i      = {[0] = "Initiator:Not", [1] = "Initiator:Yes"}
local vs_proto_opcode       = {[PROTO_OPCODE_PBKDFParamRequest] = "PBKDFParamRequest",
                               [PROTO_OPCODE_PBKDFParamResponse] = "PBKDFParamResponse",
                               [PROTO_OPCODE_PASE_Pake1] = "PASE_Pake1",
                               [PROTO_OPCODE_PASE_Pake2] = "PASE_Pake2",
                               [PROTO_OPCODE_PASE_Pake3] = "PASE_Pake3",
                               [PROTO_OPCODE_StatusReport] = "StatusReport"}
local vs_pbkdfParamReq_hasParam = {[TLV_CONTEXT_TAG_FALSE] = "false", [TLV_CONTEXT_TAG_TRUE] = "true"}


f_btp_flags_h               = ProtoField.uint8("matter.btp.flags.H", "H", base.HEX, vs_btp_flags_h, MASK_BTP_FLAGS_H)
f_btp_flags_m               = ProtoField.uint8("matter.btp.flags.M", "M", base.HEX, vs_btp_flags_m, MASK_BTP_FLAGS_M)
f_btp_flags_a               = ProtoField.uint8("matter.btp.flags.A", "A", base.HEX, vs_btp_flags_a, MASK_BTP_FLAGS_A)
f_btp_flags_e               = ProtoField.uint8("matter.btp.flags.E", "E", base.HEX, vs_btp_flags_e, MASK_BTP_FLAGS_E)
f_btp_flags_b               = ProtoField.uint8("matter.btp.flags.B", "B", base.HEX, vs_btp_flags_b, MASK_BTP_FLAGS_B)
f_btp_mOpcode               = ProtoField.uint8("matter.btp.mOpcode", "Management Opcode", base.HEX, vs_btp_mOpcode)
f_btp_ack                   = ProtoField.uint8("matter.btp.ack", "Ack Number", base.HEX)
f_btp_seq                   = ProtoField.uint8("matter.btp.seq", "Sequence Number", base.HEX)
f_btp_len                   = ProtoField.uint16("matter.btp.len", "Message Length", base.DEC)
f_btp_ver                   = ProtoField.bytes("matter.btp.ver", "Version")
f_btp_rMtu                  = ProtoField.uint16("matter.btp.rMtu", "Requested ATT_MTU", base.DEC)
f_btp_cWinSize              = ProtoField.uint8("matter.btp.cWinSize", "Client Window Size", base.DEC)
f_btp_reserve               = ProtoField.uint8("matter.btp.reserve", "Reserved", base.HEX, Payload_type, MASK_BTP_RESERVE)
f_btp_fVer                  = ProtoField.uint8("matter.btp.fVer", "Final Protocol Version", base.HEX, Payload_type, MASK_BTP_FINAL_VER)
f_btp_sMtu                  = ProtoField.uint16("matter.btp.sMtu", "Selected ATT_MTU", base.DEC)
f_btp_sWinSize              = ProtoField.uint8("matter.btp.sWinSize", "Selected Window Size", base.DEC)
f_frame_flags_ver           = ProtoField.uint8("matter.frame.flags.ver", "Version", base.HEX, Payload_type, MASK_FRAME_FLAGS_VER)
f_frame_flags_s             = ProtoField.uint8("matter.frame.flags.s", "S", base.HEX, vs_frame_flags_s, MASK_FRAME_FLAGS_S)
f_frame_flags_dsiz          = ProtoField.uint8("matter.frame.flags.dsiz", "DSIZ", base.HEX, vs_frame_flags_dsiz, MASK_FRAME_FLAGS_DSIZ)
f_frame_sId                 = ProtoField.uint16("matter.frame.sId", "Session Id", base.HEX)
f_frame_flags_p             = ProtoField.uint8("matter.frame.flags.p", "P", base.HEX, vs_frame_flags_p, MASK_FRAME_FLAGS_P)
f_frame_flags_c             = ProtoField.uint8("matter.frame.flags.c", "C", base.HEX, vs_frame_flags_c, MASK_FRAME_FLAGS_C)
f_frame_flags_mx            = ProtoField.uint8("matter.frame.flags.mx", "MX", base.HEX, vs_frame_flags_mx, MASK_FRAME_FLAGS_MX)
f_frame_flags_reserve       = ProtoField.uint8("matter.frame.flags.reserve", "Reserved", base.HEX, Payload_type, MASK_FRAME_FLAGS_RESERVE)
f_frame_flags_st            = ProtoField.uint8("matter.frame.flags.st", "Session Type", base.HEX, vs_frame_flags_st, MASK_FRAME_FLAGS_ST)
f_frame_cnt                 = ProtoField.uint32("matter.frame.cnt", "Message Counter", base.DEC)
f_frame_sNodeId             = ProtoField.uint64("matter.frame.snid", "Source Node Id", base.HEX)
f_frame_dNodeId             = ProtoField.uint64("matter.frame.dnid", "Destination Node Id", base.HEX)
f_frame_dGroupId            = ProtoField.uint16("matter.frame.dgid", "Destination Group Id", base.HEX)
f_frame_extLen              = ProtoField.uint16("matter.frame.extLen", "Message Extensions Length", base.DEC)
f_frame_extData             = ProtoField.bytes("matter.frame.extData", "Message Extensions Data")
f_proto_flags_v             = ProtoField.uint8("matter.proto.flags.v", "V", base.HEX, vs_proto_flags_v, MASK_PROTO_FLAGS_V)
f_proto_flags_sx            = ProtoField.uint8("matter.proto.flags.sx", "SX", base.HEX, vs_proto_flags_sx, MASK_PROTO_FLAGS_SX)
f_proto_flags_r             = ProtoField.uint8("matter.proto.flags.r", "R", base.HEX, vs_proto_flags_r, MASK_PROTO_FLAGS_R)
f_proto_flags_a             = ProtoField.uint8("matter.proto.flags.a", "A", base.HEX, vs_proto_flags_a, MASK_PROTO_FLAGS_A)
f_proto_flags_i             = ProtoField.uint8("matter.proto.flags.i", "I", base.HEX, vs_proto_flags_i, MASK_PROTO_FLAGS_I)
f_proto_opcode              = ProtoField.uint8("matter.proto.opcode", "Protocol Opcode", base.HEX, vs_proto_opcode)
f_proto_ecId                = ProtoField.uint16("matter.proto.ecId", "Exchange Id", base.HEX)
f_proto_pvId                = ProtoField.uint16("matter.proto.pvId", "Protocol Vendor Id", base.HEX)
f_proto_pId                 = ProtoField.uint16("matter.proto.pId", "Protocol Id", base.HEX)
f_proto_ackCnt              = ProtoField.uint32("matter.proto.ackCnt", "Acknowledged Message Counter", base.DEC)
f_proto_extLen              = ProtoField.uint16("matter.proto.extLen", "Security Extensions Length", base.DEC)
f_proto_extData             = ProtoField.bytes("matter.proto.extData", "Security Extensions Data")
f_pbkdfParamReq_iRand       = ProtoField.bytes("matter.pbkdfParamReq.iRand", "initiatorRandom")
f_pbkdfParamReq_iSessId     = ProtoField.uint16("matter.pbkdfParamReq.iSessId", "initiatorSessionId", base.HEX)
f_pbkdfParamReq_pCodeId     = ProtoField.uint8("matter.pbkdfParamReq.pCodeId", "passcodeId", base.HEX)
f_pbkdfParamReq_hasParam    = ProtoField.uint8("matter.pbkdfParamReq.hasParam", "hasPBKDFParameters", base.HEX, vs_pbkdfParamReq_hasParam)
f_pbkdfParamReq_idle        = ProtoField.uint16("matter.pbkdfParamReq.idle", "sleepIdleInterval", base.DEC)
f_pbkdfParamReq_active      = ProtoField.uint16("matter.pbkdfParamReq.active", "sleepActiveInterval", base.DEC)
f_pbkdfParamResp_iRand      = ProtoField.bytes("matter.pbkdfParamResp.iRand", "initiatorRandom")
f_pbkdfParamResp_rRand      = ProtoField.bytes("matter.pbkdfParamResp.rRand", "responderRandom")
f_pbkdfParamResp_rSessId    = ProtoField.uint16("matter.pbkdfParamResp.rSessId", "responderSessionId", base.HEX)
f_pbkdfParamResp_iterCnt    = ProtoField.uint16("matter.pbkdfParamResp.count", "iterationCount", base.DEC)
f_pbkdfParamResp_salt       = ProtoField.bytes("matter.pbkdfParamResp.salt", "salt")
f_pbkdfParamResp_idle       = ProtoField.uint16("matter.pbkdfParamResp.idle", "sleepIdleInterval", base.DEC)
f_pbkdfParamResp_active     = ProtoField.uint16("matter.pbkdfParamResp.active", "sleepActiveInterval", base.DEC)
f_pase_pake1_pA             = ProtoField.bytes("matter.pase.pake1.pA", "pA")
f_pase_pake2_pB             = ProtoField.bytes("matter.pase.pake2.pB", "pB")
f_pase_pake2_cB             = ProtoField.bytes("matter.pase.pake2.cB", "cB")
f_pase_pake3_cA             = ProtoField.bytes("matter.pase.pake3.cA", "cA")


proto_matter_ble = Proto("matter", "matter protocol over ble")

proto_matter_ble.fields = {
    f_btp_flags_h,
    f_btp_flags_m,
    f_btp_flags_a,
    f_btp_flags_e,
    f_btp_flags_b,
    f_btp_mOpcode,
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
    f_proto_extData,
    f_pbkdfParamReq_iRand,
    f_pbkdfParamReq_iSessId,
    f_pbkdfParamReq_pCodeId,
    f_pbkdfParamReq_hasParam,
    f_pbkdfParamReq_idle,
    f_pbkdfParamReq_active,
    f_pbkdfParamResp_iRand,
    f_pbkdfParamResp_rRand,
    f_pbkdfParamResp_rSessId,
    f_pbkdfParamResp_iterCnt,
    f_pbkdfParamResp_salt,
    f_pbkdfParamResp_idle,
    f_pbkdfParamResp_active,
    f_pase_pake1_pA,
    f_pase_pake2_pB,
    f_pase_pake2_cB,
    f_pase_pake3_cA
}

function proto_matter_ble.dissector(tvb, pinfo, tree)
    local offset = 0
    local value_btp_flags = 0
    local value_frame_msg_flags = 0
    local value_frame_sec_flags = 0
    local value_frame_sessionId = 0
    local value_frame_extLen = 0
    local value_proto_flags = 0
    local value_proto_pid = 0
    local value_proto_opcode = 0
    local value_proto_extLen = 0
    local value_pbkdfParam_salt_len = 0
    local value_btatt_opcode = 0

    local att_dissector = Dissector.get("btatt") -- use default btatt dissector to process ble att header:opcode(1B),handle(2B)
    att_dissector:call(tvb, pinfo, tree)

    value_btatt_opcode = tvb(offset, 1):uint()
    if value_btatt_opcode == BLE_ATT_OPCODE_WRITE_REQUEST or value_btatt_opcode == BLE_ATT_OPCODE_INDICATION then
        tvb = tvb(3):tvb() -- skip ble att header 3B

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

        if value_btp_flags == 0x65 then -- BTP Handshark PDU
            st:add(f_btp_mOpcode, tvb(offset, 1))
            offset = offset + 1
            if tvb_len == 9 then
                pinfo.cols.info:prepend("[BTP Handshark Request] ")
                st:add(f_btp_ver, tvb(offset, 4))
                offset = offset + 4
                st:add_le(f_btp_rMtu, tvb(offset, 2))
                offset = offset + 2
                st:add_le(f_btp_cWinSize, tvb(offset, 1))
                offset = offset + 1
            elseif tvb_len == 6 then
                pinfo.cols.info:prepend("[BTP Handshark Response] ")
                local st_btp_fVer = st:add(proto_matter_ble, tvb(offset, 1), "Version")
                st_btp_fVer:add(f_btp_reserve, tvb(offset, 1))
                st_btp_fVer:add(f_btp_fVer, tvb(offset, 1))
                offset = offset + 1
                st:add_le(f_btp_sMtu, tvb(offset, 2))
                offset = offset + 2
                st:add_le(f_btp_sWinSize, tvb(offset, 1))
                offset = offset + 1
            end
        else -- BTP Data PDU
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

            if bit.band(value_btp_flags, MASK_BTP_FLAGS_E) ~= 0 then -- recv sub segments complete
                local st_btp_segment_payload = st:add(proto_matter_ble, tvb(offset, tvb:len() - offset), "Segment Payload")
                local st_frame_msg_flags = st_btp_segment_payload:add(proto_matter_ble, tvb(offset, 1), "Message Flags")
                st_frame_msg_flags:add(f_frame_flags_ver, tvb(offset, 1))
                st_frame_msg_flags:add(f_frame_flags_s, tvb(offset, 1))
                st_frame_msg_flags:add(f_frame_flags_dsiz, tvb(offset, 1))
                value_frame_msg_flags = tvb(offset, 1):uint()
                offset = offset + 1

                st_btp_segment_payload:add_le(f_frame_sId, tvb(offset, 2))
                value_frame_sessionId = tvb(offset, 2):le_uint()
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
                    st_btp_segment_payload:add_le(f_frame_extLen, tvb(offset, 2))
                    offset = offset + 2
                    st_btp_segment_payload:add(f_frame_extData, tvb(offset, value_frame_extLen))
                    offset = offset + value_frame_extLen
                end

                if value_frame_sessionId == 0 and bit.band(value_frame_sec_flags, MASK_FRAME_FLAGS_ST) == 0 then -- not encrypt message
                    local st_frame_payload_plaintext = st_btp_segment_payload:add(proto_matter_ble, tvb(offset, tvb:len() - offset), "Message Payload")
                    local st_proto_header_exchange_flags = st_frame_payload_plaintext:add(proto_matter_ble, tvb(offset, 1), "Exchange Flags")
                    st_proto_header_exchange_flags:add(f_proto_flags_v, tvb(offset, 1))
                    st_proto_header_exchange_flags:add(f_proto_flags_sx, tvb(offset, 1))
                    st_proto_header_exchange_flags:add(f_proto_flags_r, tvb(offset, 1))
                    st_proto_header_exchange_flags:add(f_proto_flags_a, tvb(offset, 1))
                    st_proto_header_exchange_flags:add(f_proto_flags_i, tvb(offset, 1))
                    value_proto_flags = tvb(offset, 1):uint()
                    offset = offset + 1

                    st_frame_payload_plaintext:add(f_proto_opcode, tvb(offset, 1))
                    value_proto_opcode = tvb(offset, 1):uint()
                    offset = offset + 1

                    st_frame_payload_plaintext:add_le(f_proto_ecId, tvb(offset, 2))
                    offset = offset + 2

                    if bit.band(value_proto_flags, MASK_PROTO_FLAGS_V) ~= 0 then
                        st_frame_payload_plaintext:add_le(f_proto_pvId, tvb(offset, 2))
                        offset = offset + 2
                    end

                    st_frame_payload_plaintext:add_le(f_proto_pId, tvb(offset, 2))
                    value_proto_pid = tvb(offset, 2):le_uint()
                    offset = offset + 2

                    if bit.band(value_proto_flags, MASK_PROTO_FLAGS_A) ~= 0 then
                        st_frame_payload_plaintext:add_le(f_proto_ackCnt, tvb(offset, 4))
                        offset = offset + 4
                    end

                    if bit.band(value_proto_flags, MASK_PROTO_FLAGS_SX) ~= 0 then
                        value_proto_extLen = tvb(offset, 2):le_uint()
                        st_frame_payload_plaintext:add_le(f_proto_extLen, tvb(offset, 2))
                        offset = offset + 2
                        st_frame_payload_plaintext:add(f_proto_extData, tvb(offset, value_proto_extLen))
                        offset = offset + value_proto_extLen
                    end

                    local st_proto_app_payload = st_frame_payload_plaintext:add(proto_matter_ble, tvb(offset, tvb:len() - offset), "Application Payload")
                    if value_proto_pid == PROTO_PID_SECURE_CHANNEL then
                        if value_proto_opcode == PROTO_OPCODE_PBKDFParamRequest then
                            pinfo.cols.info:prepend("[SecureChannel:PBKDFParamRequest] ") -- assume tag value sorted
                            offset = offset + 4
                            st_proto_app_payload:add(f_pbkdfParamReq_iRand, tvb(offset, 32))
                            offset = offset + 34
                            st_proto_app_payload:add_le(f_pbkdfParamReq_iSessId, tvb(offset, 2))
                            offset = offset + 4
                            st_proto_app_payload:add(f_pbkdfParamReq_pCodeId, tvb(offset, 1))
                            offset = offset + 1
                            st_proto_app_payload:add(f_pbkdfParamReq_hasParam, tvb(offset, 1))
                            offset = offset + 2
                            if TLV_END_OF_CONTAINER ~= tvb(offset, 1):uint() then
                                local st_pbkdfParamReq_iSedParam = st_proto_app_payload:add(proto_matter_ble, tvb(offset, 11), "initiatorSEDParams")
                                offset = offset + 4
                                st_pbkdfParamReq_iSedParam:add_le(f_pbkdfParamReq_idle, tvb(offset, 2))
                                offset = offset + 4
                                st_pbkdfParamReq_iSedParam:add_le(f_pbkdfParamReq_active, tvb(offset, 2))
                                offset = offset + 2
                            end
                        elseif value_proto_opcode == PROTO_OPCODE_PBKDFParamResponse then
                            pinfo.cols.info:prepend("[SecureChannel:PBKDFParamResponse] ")
                            offset = offset + 4
                            st_proto_app_payload:add(f_pbkdfParamResp_iRand, tvb(offset, 32))
                            offset = offset + 35
                            st_proto_app_payload:add(f_pbkdfParamResp_rRand, tvb(offset, 32))
                            offset = offset + 34
                            st_proto_app_payload:add_le(f_pbkdfParamResp_rSessId, tvb(offset, 2))
                            offset = offset + 2
                            if TLV_END_OF_CONTAINER ~= tvb(offset, 1):uint() then
                                if tvb(offset + 1, 1):uint() == 4 then -- pbkdf_parameters exist
                                    value_pbkdfParam_salt_len = tvb(offset + 8, 1):uint()
                                    local st_pbkdfParamResp_param = st_proto_app_payload:add(proto_matter_ble, tvb(offset, value_pbkdfParam_salt_len + 10), "pbkdf_parameters")
                                    offset = offset + 4
                                    st_pbkdfParamResp_param:add_le(f_pbkdfParamResp_iterCnt, tvb(offset, 2))
                                    offset = offset + 5
                                    st_pbkdfParamResp_param:add(f_pbkdfParamResp_salt, tvb(offset, value_pbkdfParam_salt_len))
                                    offset = offset + value_pbkdfParam_salt_len + 1
                                end

                                if TLV_END_OF_CONTAINER ~= tvb(offset, 1):uint() then -- responderSEDParams exist
                                    local st_pbkdfParamResp_rSedParam = st_proto_app_payload:add(proto_matter_ble, tvb(offset, 11), "responderSEDParams")
                                    offset = offset + 4
                                    st_pbkdfParamResp_rSedParam:add_le(f_pbkdfParamResp_idle, tvb(offset, 2))
                                    offset = offset + 4
                                    st_pbkdfParamResp_rSedParam:add_le(f_pbkdfParamResp_active, tvb(offset, 2))
                                    offset = offset + 2
                                end
                            end
                        elseif value_proto_opcode == PROTO_OPCODE_PASE_Pake1 then
                            pinfo.cols.info:prepend("[SecureChannel:PASE_Pake1] ")
                            offset = offset + 4
                            st_proto_app_payload:add(f_pase_pake1_pA, tvb(offset, 65))
                            offset = offset + 65 + 1
                        elseif value_proto_opcode == PROTO_OPCODE_PASE_Pake2 then
                            pinfo.cols.info:prepend("[SecureChannel:PASE_Pake2] ")
                            offset = offset + 4
                            st_proto_app_payload:add(f_pase_pake2_pB, tvb(offset, 65))
                            offset = offset + 68
                            st_proto_app_payload:add(f_pase_pake2_cB, tvb(offset, 32))
                            offset = offset + 32 + 1
                        elseif value_proto_opcode == PROTO_OPCODE_PASE_Pake3 then
                            pinfo.cols.info:prepend("[SecureChannel:PASE_Pake3] ")
                            offset = offset + 4
                            st_proto_app_payload:add(f_pase_pake3_cA, tvb(offset, 32))
                            offset = offset + 32 + 1
                        elseif value_proto_opcode == PROTO_OPCODE_StatusReport then
                            pinfo.cols.info:prepend("[SecureChannel:StatusReport] ")
                        end
                    end
                else -- encrypt message
                    local st_frame_payload_ciphertext = st_btp_segment_payload:add(proto_matter_ble, tvb(offset, tvb:len() - offset), "Message Payload(Encryption)")
                    -- TODO: decrypt message
                end
            end
        end
    end
end


btatt_table = DissectorTable.get("btl2cap.cid")
btatt_table:add(0x0004, proto_matter_ble) -- ble att cid

-- btatt_dissector = Dissector.get("btatt") - nok, because Dissector has no "add" function
-- btatt_dissector:add(0x12, proto_matter_ble) -- att opcode Write Request
-- btatt_dissector:add(0x1d, proto_matter_ble) -- att opcode Handle Value Indication


-- TODO:
-- 1. support sub segments
-- 2. support parse CASE msg
-- 3. support parse encrypt msg
-- 4. support parse wifi link msg
