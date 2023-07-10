
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
    f_btp_sWinSize
}

function proto_matter_ble.dissector(tvb, pinfo, tree)
    local tvb_len = tvb:len()
    if tvb_len < 6 then return end -- btp handshark response(6B), btp header(1B) + frame header(8B)
        
    pinfo.cols.protocol = proto_matter_ble.name

    local offset = 0
    local st = tree:add(proto_matter_ble, tvb(), "Matter Protocol")
    local st_btp_flags = st:add(proto_matter_ble, tvb(offset, 1), "Flags")
    st_btp_flags:add(f_btp_flags_h, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_m, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_a, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_e, tvb(offset, 1))
    st_btp_flags:add(f_btp_flags_b, tvb(offset, 1))

    local btp_flags_value = tvb(offset, 1):uint()
    offset = offset + 1
    if btp_flags_value == 0x65 then -- btp handshark
        st:add(f_btp_opcode, tvb(offset, 1))
        offset = offset + 1
        if tvb_len == 0x09 then -- btp handshark req
            pinfo.cols.info:append(" -- BTP handshark request")
            st:add(f_btp_ver, tvb(offset, 4))
            offset = offset + 4
            st:add_le(f_btp_rMtu, tvb(offset, 2))
            offset = offset + 2
            st:add_le(f_btp_cWinSize, tvb(offset, 1))
            offset = offset + 1
        elseif tvb_len == 0x06 then -- btp handshark resp
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
    end
end

-- btatt_table = DissectorTable.get("btatt.opcode") -- nok
-- btatt_table = DissectorTable.get("btatt.uuid16") -- nok
btatt_table = DissectorTable.get("btatt.handle") -- ok
btatt_table:add(18, proto_matter_ble) -- handle 0x0012(C1),0x0014(C2)
btatt_table:add(20, proto_matter_ble)

