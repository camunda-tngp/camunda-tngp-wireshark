-- camunda tngp protocol

local DEBUG = false
local TNGP_PORT = 8880

local debug = function() end
local function configureDebug()
    if DEBUG then
        debug = function(...)
            info(table.concat({"TNGP: ", ...}, " "))
        end
    end
end
configureDebug()

-- Protocol constants
--
-- minimum header bytes needed to read length
local MIN_DATA_FRAME_LENGTH = 4
-- tngp header size in bytes
local DATA_FRAME_LENGTH = 12
-- frame alignment
local ALIGNMENT = 8
-- message types
local function register_msg_types()
    local types = {}
    types[0] = "Message"
    types[1] = "Padding"
    types[100] = "Control Close"
    types[101] = "Control End Of Stream"
    types[102] = "Proto Control Frame"
    return types
end
local msgtype_valstr = register_msg_types()

-- Protocol declaration
local data_frame_proto = Proto("camunda-tngp-data-frame","Camunda TNGP Data Frame")
local transport_request_proto = Proto("camunda-tngp-transport-request", "Camunda TNGP Transport Request")
local dummy_proto = Proto("camunda-tngp-dummy", "Camunda TNGP Dummy")

local data_frame_fields = {
    length = ProtoField.uint32("tngp.data.frame.length", "Length"),
    version = ProtoField.uint8("tngp.data.frame.version", "Version"),
    flags = ProtoField.uint8("tngp.data.frame.flags", "Flags"),
    ftype = ProtoField.uint16("tngp.data.frame.type", "Type", base.DEC, msgtype_valstr),
    stream = ProtoField.uint32("tngp.data.frame.stream", "Stream Id"),
    padding = ProtoField.uint32("tngp.transport.request.padding", "Padding"),
}
data_frame_proto.fields = data_frame_fields

local transport_request_fields = {
    connection = ProtoField.uint64("tngp.transport.request.connection", "Connection Id"),
    request = ProtoField.uint64("tngp.transport.request.request", "Request Id"),
    data = ProtoField.bytes("tngp.transport.request.data", "Data"),
}
transport_request_proto.fields = transport_request_fields

local dummy_fields = {
    data = ProtoField.bytes("tngp.dummy.data", "Data"),
}
dummy_proto.fields = dummy_fields

-- helper methods

-- cacluate aligned length
local function align(length)
    return bit32.band(length + DATA_FRAME_LENGTH + ALIGNMENT - 1, bit32.bnot(ALIGNMENT - 1))
end

-- read length from frame, returns a negative number
-- if more bytes are needed
local function read_data_frame_length(tvbuf, offset)
    local msglen = tvbuf:len() - offset

    -- check if capture was only capturing partial packet size
    if msglen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        debug("Captured package was truncated; aborting")
        return 0
    end

    if msglen < MIN_DATA_FRAME_LENGTH then
        debug("Need more bytes to read TNGP length field")
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    local length_tvbr = tvbuf:range(offset, 4)
    local length_val  = length_tvbr:le_uint()
    local length_total = align(length_val)
    if msglen < length_total then
        debug("Need more bytes to read full TNGP packet")
        return -(length_total - msglen)
    end

    return length_total, length_val, length_tvbr
end

-- Protocol dissection
--

local function dissect_transport_request(tvbuf, root, offset, length)
    debug("dissect transport request")
    debug("request:", length)

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(transport_request_proto, tvbuf:range(offset, length))

    -- dissect the connection field
    local connection_tvbr = tvbuf:range(offset, 8)
    tree:add_le(transport_request_fields.connection, connection_tvbr)

    -- dissect the request field
    local request_tvbr = tvbuf:range(offset + 8, 8)
    tree:add_le(transport_request_fields.request, request_tvbr)

    -- dissect the data field
    local data_len = length - 16
    local data_tvbr = tvbuf:range(offset + 16, data_len)
    local data_val = data_tvbr:string()
    tree:add(transport_request_fields.data, data_tvbr, data_val, nil, "(" .. data_len .. " Bytes)")
end

local function dissect_data_frame(tvbuf, pktinfo, root, offset)
    debug("dissect data frame")
    local length_total, length_val, length_tvbr = read_data_frame_length(tvbuf, offset)
    if length_total < 0 then
        return length_total
    end
    debug("data frame found:", length_val, "(", length_total, ")")
    debug("timestamp:", tostring(pktinfo.cols))

    pktinfo.cols.protocol:set("TNGP")

    -- set the INFO column too, but only if we haven't already set it before
    -- for this frame/packet, because this function can be called multiple
    -- times per packet/Tvb
    if string.find(tostring(pktinfo.cols.info), "^Camunda TNGP") == nil then
        pktinfo.cols.info:set("Camunda TNGP")
    end

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(data_frame_proto, tvbuf:range(offset, DATA_FRAME_LENGTH))

    -- add the length field
    tree:add_le(data_frame_fields.length, length_tvbr, length_val, nil, "(Total: " .. length_total .. ")")

    -- dissect the version field
    local version_tvbr = tvbuf:range(offset + 4, 1)
    tree:add_le(data_frame_fields.version, version_tvbr)

    -- dissect the flags field
    local flags_tvbr = tvbuf:range(offset + 5, 1)
    tree:add_le(data_frame_fields.flags, flags_tvbr)

    -- dissect the type field
    local ftype_tvbr = tvbuf:range(offset + 6, 2)
    local ftype_val = ftype_tvbr:le_uint()
    tree:add_le(data_frame_fields.ftype, ftype_tvbr)

    -- dissect the type field
    local stream_id_tvbr = tvbuf:range(offset + 8, 4)
    tree:add_le(data_frame_fields.stream, stream_id_tvbr)

    local body_offset = offset + DATA_FRAME_LENGTH
    -- dissect transport request
    if ftype_val == 0 then
        dissect_transport_request(tvbuf, root, body_offset, length_val)
    elseif length_val > 0 then
        local tree = root:add(dummy_proto, tvbuf:range(body_offset, length_val))
    end

    local padding = length_total - DATA_FRAME_LENGTH - length_val
    debug("padding:", padding)

    -- add padding

    local padding_tvbr = tvbuf:range(offset + DATA_FRAME_LENGTH + length_val, padding)
    root:add(data_frame_fields.padding, padding_tvbr, padding, nill, "Bytes")

    return length_total
end

-- data frame disector loop
function data_frame_proto.dissector(tvbuf, pktinfo, root)
    debug("dissect data frame proto")

    local pktlen = tvbuf:len()
    local bytes_consumed = 0

    while bytes_consumed < pktlen do
        local result = dissect_data_frame(tvbuf, pktinfo, root, bytes_consumed)
        if result > 0 then
            bytes_consumed = bytes_consumed + result
        elseif result == 0 then
            return 0
        else
            pktinfo.desegment_offset = bytes_consumed
            result = -result

            pktinfo.desegment_len = result
            return pktlen
        end
    end

    return bytes_consumed
end

DissectorTable.get("tcp.port"):add(TNGP_PORT, data_frame_proto)
