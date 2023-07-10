local version_str = string.match(_VERSION, "%d+[.]%d*")
local version_num = version_str and tonumber(version_str) or 5.1
local bit = (version_num >= 5.2) and require("bit32") or require("bit")


proto_matter_ble = Proto("MATTER_BLE", "matter protocol over ble")

f_btp_flags_h   = ProtoField.uint8("matter.btp.flags.H", "H", base.HEX, Payload_type, 0x40)
f_btp_flags_m   = ProtoField.uint8("matter.btp.flags.M", "M", base.HEX, Payload_type, 0x20)
f_btp_flags_a   = ProtoField.uint8("matter.btp.flags.A", "A", base.HEX, Payload_type, 0x08)
f_btp_flags_e   = ProtoField.uint8("matter.btp.flags.E", "E", base.HEX, Payload_type, 0x04)
f_btp_flags_b   = ProtoField.uint8("matter.btp.flags.B", "B", base.HEX, Payload_type, 0x01)
f_btp_opcode    = ProtoField.uint8("matter.btp.opcode", "Management Opcode", base.HEX)
f_btp_ack       = ProtoField.uint8("matter.btp.ack", "Ack Number", base.DEC)
f_btp_seq       = ProtoField.uint8("matter.btp.seq", "Sequence Number", base.DEC)
f_btp_len       = ProtoField.uint16("matter.btp.len", "Message Length", base.DEC)
f_btp_ver       = ProtoField.bytes("matter.btp.ver", "Version")
f_btp_rMtu      = ProtoField.uint16("matter.btp.rMtu", "Requested ATT_MTU", base.DEC)
f_btp_cWinSize  = ProtoField.uint8("matter.btp.cWinSize", "Client Window Size", base.DEC)
f_btp_reserve   = ProtoField.uint8("matter.btp.reserve", "Reserved", base.HEX, Payload_type, 0xf0)
f_btp_fVer      = ProtoField.uint8("matter.btp.fVer", "Final Protocol Version", base.HEX, Payload_type, 0x0f)
f_btp_sMtu      = ProtoField.uint16("matter.btp.sMtu", "Selected ATT_MTU", base.DEC)
f_btp_sWinSize  = ProtoField.uint8("matter.btp.sWinSize", "Selected Window Size", base.DEC)
f_frame_msg_flags_ver   = ProtoField.uint8("matter.frame.msg.flags.ver", "Version", base.HEX, Payload_type, 0xf0)
f_frame_msg_flags_s     = ProtoField.uint8("matter.frame.msg.flags.s", "S", base.HEX, Payload_type, 0x04)
f_frame_msg_flags_dsiz  = ProtoField.uint8("matter.frame.msg.flags.dsiz", "DSIZ", base.HEX, Payload_type, 0x03)
f_frame_sId             = ProtoField.uint16("matter.frame.sId", "Session Id", base.HEX)
f_frame_sec_flags_p     = ProtoField.uint8("matter.frame.sec.flags.p", "P", base.HEX, Payload_type, 0x80)
f_frame_sec_flags_c     = ProtoField.uint8("matter.frame.sec.flags.c", "C", base.HEX, Payload_type, 0x40)
f_frame_sec_flags_mx    = ProtoField.uint8("matter.frame.sec.flags.mx", "MX", base.HEX, Payload_type, 0x20)
f_frame_sec_flags_reserve = ProtoField.uint8("matter.frame.sec.flags.reserve", "Reserved", base.HEX, Payload_type, 0x1c)
f_frame_sec_flags_st    = ProtoField.uint8("matter.frame.sec.flags.st", "Session Type", base.HEX, Payload_type, 0x03)
f_frame_counter         = ProtoField.uint32("matter.frame.counter", "Message Counter", base.DEC)
f_frame_srcNodeId       = ProtoField.uint64("matter.frame.snid", "Source Node Id", base.HEX)
f_frame_dstNodeId       = ProtoField.uint64("matter.frame.dnid", "Destination Node Id", base.HEX)
f_frame_dstGroupId      = ProtoField.uint16("matter.frame.dgid", "Destination Group Id", base.HEX)
f_frame_ext_len         = ProtoField.uint16("matter.frame.extLen", "Message Extensions Length", base.HEX)
f_frame_ext_data        = ProtoField.bytes("matter.frame.extData", "Message Extensions Data")



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
    f_frame_msg_flags_ver,
    f_frame_msg_flags_s,
    f_frame_msg_flags_dsiz,
    f_frame_sId,
    f_frame_sec_flags_p,
    f_frame_sec_flags_c,
    f_frame_sec_flags_mx,
    f_frame_sec_flags_reserve,
    f_frame_sec_flags_st,
    f_frame_counter,
    f_frame_srcNodeId,
    f_frame_dstNodeId,
    f_frame_dstGroupId,
    f_frame_ext_len,
    f_frame_ext_data
}

function proto_matter_ble.dissector(tvb, pinfo, tree)
    local tvb_len = tvb:len()
    if tvb_len < 6 then return end -- btp handshark response(6B), btp header(1B) + frame header(8B)
        
    pinfo.cols.protocol = proto_matter_ble.name

    local offset = 0
    local st = tree:add(proto_matter_ble, tvb(), "Matter Protocol")
    local st_btp_flags = st:add(proto_matter_ble, tvb(offset, 1), "BTP Flags")
    st_btp_flags:add(f_btp_flags_h, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_m, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_a, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_e, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_b, tvb(offset, 1))

    local btp_flags_value = tvb(offset, 1):uint()
    offset = offset + 1
    if btp_flags_value == 0x65 then -- btp handshark PDU
        st:add(f_btp_opcode, tvb(offset, 1))
        offset = offset + 1
        if tvb_len == 9 then -- btp handshark req
            pinfo.cols.info:append(" -- BTP handshark request")
            st:add(f_btp_ver, tvb(offset, 4))
            offset = offset + 4
            st:add_le(f_btp_rMtu, tvb(offset, 2))
            offset = offset + 2
            st:add_le(f_btp_cWinSize, tvb(offset, 1))
            offset = offset + 1
        elseif tvb_len == 6 then -- btp handshark resp
            pinfo.cols.info:append(" -- BTP handshark response")
            local st_btp_fVer = st:add(proto_matter_ble, tvb(offset, 1), "Version")
            st_btp_fVer:add(f_btp_reserve, tvb(offset, 1))
            st_btp_fVer:add_le(f_btp_fVer, tvb(offset, 1))
            offset = offset + 1
            st:add_le(f_btp_sMtu, tvb(offset, 2))
            offset = offset + 2
            st:add_le(f_btp_sWinSize, tvb(offset, 1))
            offset = offset + 1
        end
    else -- btp data PDU
        if bit.band(btp_flags_value, 0x08) == 0x08 then
            st:add(f_btp_ack, tvb(offset, 1))
            offset = offset + 1
        end

        st:add(f_btp_seq, tvb(offset, 1))
        offset = offset + 1

        if bit.band(btp_flags_value, 0x01) == 0x01 then
            st:add_le(f_btp_len, tvb(offset, 2))
            offset = offset + 2
        end

        if bit.band(btp_flags_value, 0x04) == 0x04 then
            local st_btp_segment_payload = st:add(proto_matter_ble, tvb(offset, tvb:len() - offset), "Segment Payload")
            local st_frame_msg_flags = st_btp_segment_payload:add(proto_matter_ble, tvb(offset, 1), "Message Flags")
            st_frame_msg_flags:add(f_frame_msg_flags_ver, tvb(offset, 1))
            st_frame_msg_flags:add(f_frame_msg_flags_s, tvb(offset, 1))
            st_frame_msg_flags:add(f_frame_msg_flags_dsiz, tvb(offset, 1))
            local frame_msg_flags_value = tvb(offset, 1):uint()
            offset = offset + 1
            st_btp_segment_payload:add_le(f_frame_sId, tvb(offset, 2))
            offset = offset + 2
            local st_frame_sec_flags = st_btp_segment_payload:add(proto_matter_ble, tvb(offset, 1), "Security Flags")
            st_frame_sec_flags:add(f_frame_sec_flags_p, tvb(offset, 1))
            st_frame_sec_flags:add(f_frame_sec_flags_c, tvb(offset, 1))
            st_frame_sec_flags:add(f_frame_sec_flags_mx, tvb(offset, 1))
            st_frame_sec_flags:add(f_frame_sec_flags_reserve, tvb(offset, 1))
            st_frame_sec_flags:add(f_frame_sec_flags_st, tvb(offset, 1))
            local frame_sec_flags_value = tvb(offset, 1):uint()
            offset = offset + 1
            st_btp_segment_payload:add_le(f_frame_counter, tvb(offset, 4))
            offset = offset + 4
            if bit.band(frame_msg_flags_value, 0x04) == 0x04 then
                st_btp_segment_payload:add(f_frame_srcNodeId, tvb(offset, 8))
                offset = offset + 8
            end
            if bit.band(frame_msg_flags_value, 0x03) == 0x01 then
                st_btp_segment_payload:add(f_frame_dstNodeId, tvb(offset, 8))
                offset = offset + 8                
            elseif bit.band(frame_msg_flags_value, 0x03) == 0x02 then
                st_btp_segment_payload:add(f_frame_dstGroupId, tvb(offset, 2))
                offset = offset + 2                 
            end
            if bit.band(frame_sec_flags_value, 0x20) == 0x20 then
                local frame_ext_len = tvb(offset, 2):le_uint()
                st_btp_segment_payload:add(f_frame_ext_len, tvb(offset, 2))
                offset = offset + 2
                st_btp_segment_payload:add(f_frame_ext_data, tvb(offset, frame_ext_len))
                offset = offset + frame_ext_len
            end            
        end
    end
end

-- btatt_table = DissectorTable.get("btatt.opcode") -- nok
-- btatt_table = DissectorTable.get("btatt.uuid16") -- nok
btatt_table = DissectorTable.get("btatt.handle") -- ok
btatt_table:add(18, proto_matter_ble) -- handle 0x0012(C1),0x0014(C2)
btatt_table:add(20, proto_matter_ble)

