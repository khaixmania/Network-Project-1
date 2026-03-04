local type_map = {
    [0] = "Unknown",
    [1] = "Data",
    [2] = "ACK",
    [3] = "SACK",
}

-- Protocols fields
local type_field        = ProtoField.uint32("srtp.type", "Type" , base.DEC, type_map, 0xC0000000)
local window_field      = ProtoField.uint32("srtp.window", "Window" , base.DEC, NULL, 0x3F000000)
local length_field      = ProtoField.uint32("srtp.length", "Length" , base.DEC, NULL, 0x00FFF800)
local seq_field         = ProtoField.uint32("srtp.seq", "Seq" , base.DEC, NULL, 0x000007FF)
local timestamp_field   = ProtoField.bytes("srtp.timestamp", "Timestamp")
local crc1_field        = ProtoField.uint32("srtp.crc1", "CRC1" , base.HEX)
local payload_field     = ProtoField.bytes("srtp.payload", "Payload")
local crc2_field        = ProtoField.uint32("srtp.crc2", "CRC2" , base.HEX)

-- Errors in format of packet
local header_too_short_msg = "Packet header is too short, should be at least 12 bytes"
local header_too_short = ProtoExpert.new("strp.header_too_short", header_too_short_msg, expert.group.MALFORMED, expert.severity.ERROR)

local payload_too_long_msg = "Packet payload exceed limit of 1024 bytes"
local payload_too_long = ProtoExpert.new("strp.payload_too_long", payload_too_long_msg, expert.group.MALFORMED, expert.severity.ERROR)

local inconsistent_length_msg = "Length in header is inconsistent with segment length"
local inconsistent_length = ProtoExpert.new("strp.inconsistent_length", inconsistent_length_msg, expert.group.MALFORMED, expert.severity.ERROR)

local zero_payload_invalid_length_msg = "Bytes present in packet after header in zero-length packet"
local zero_payload_invalid_length = ProtoExpert.new("strp.zero_payload_invalid_length", zero_payload_invalid_length_msg, expert.group.MALFORMED, expert.severity.ERROR)

local payload_in_ack_msg = "Payload present in (S)ACK packet"
local payload_in_ack = ProtoExpert.new("strp.payload_in_ack", payload_in_ack_msg, expert.group.MALFORMED, expert.severity.ERROR)

-- Protocol creation
protocol = Proto("SRTP", "Simple Reliable Transport Protocol")

protocol.fields = {
    type = type_field,
    window = window_field,
    length = length_field,
    seq = seq_field,
    timestamp = timestamp_field,
    crc1 = crc1_field,
    payload = payload_field,
    crc2 = crc2_field
}

protocol.experts = {
    header_too_short = header_too_short,
    payload_too_long = payload_too_long,
    inconsistent_length = inconsistent_length,
    zero_payload_invalid_length = zero_payload_invalid_length,
    payload_in_ack = payload_in_ack
}

function protocol.dissector(buffer, pinfo, tree)
    local srtp = tree:add(protocol, buffer(), protocol.name)
    pinfo.cols.protocol = protocol.name
    pinfo.cols.info = "SRTP"

    local length = buffer:len()
    if length < 12 then 
        pinfo.cols.info = "SRTP (" .. header_too_short_msg .. ")"
        srtp:add_proto_expert_info(header_too_short)
        return 
    end

    srtp:add(type_field, buffer(0, 4))
    local type = buffer(0, 1):bitfield(0, 2)
    pinfo.cols.info = "SRTP (" .. type_map[type] .. ")"  

    srtp:add(window_field, buffer(0, 4))

    srtp:add(length_field, buffer(0, 4))
    srtp:add(seq_field, buffer(0, 4))

    srtp:add(timestamp_field, buffer(4, 4))
    srtp:add(crc1_field, buffer(8, 4))

    local msg_length = buffer(0, 4):bitfield(8, 13);

    -- perform several checks about message length
    if type ~= 1 and msg_length ~= 0 then
        pinfo.cols.info = "SRTP (" .. payload_in_ack_msg .. ")"
        srtp:add_proto_expert_info(payload_in_ack)
        return
    end

    if msg_length > 1024 then
        pinfo.cols.info = "SRTP (" .. payload_too_long_msg .. ")"
        srtp:add_proto_expert_info(payload_too_long)
        return
    end

    if msg_length == 0 and length ~= 12 then
        pinfo.cols.info = "SRTP (" .. zero_payload_invalid_length_msg .. ")"
        srtp:add_proto_expert_info(zero_payload_invalid_length)
        return
    end

    if msg_length ~= 0 and length ~= 12 + msg_length + 4 then
        pinfo.cols.info = "SRTP (" .. inconsistent_length_msg .. ")"
        srtp:add_proto_expert_info(inconsistent_length)
        return
    end

    if msg_length > 0 then
        srtp:add(payload_field, buffer(12, msg_length))
        srtp:add(crc2_field, buffer(length - 4, 4))
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(8080, protocol)