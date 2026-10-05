-- Copyright (C) 2026 Estudely and contributors
-- SPDX-License-Identifier: GPL-2.0-or-later
-- Estudely Packet Explorer field extractor (Wireshark Lua postdissector).
--
-- Runs inside Wiregasm (Wireshark compiled to WebAssembly). It is inert until
-- the host "arms" it by writing ARM_PATH; the host then triggers one full,
-- tree-building dissection pass (a filtered frame scan) and this script writes
-- compact tab-separated records to an in-memory file. Field values are only
-- read from Wireshark's own dissectors, so TCP/IP reassembly, DNS-over-TCP
-- framing and HTTP header reassembly are handled by Wireshark itself.
--
-- Line formats (fields separated by TAB, lists by \31, escaped with \\ \t \n \r \u):
--   I iface encap ifname
--   P num epoch len caplen iface protos ethsrc ethdst src dst sport dport tcpstream udpstream tcpflags tcplen flags tlsapp quicstream quicshort
--   S num frames(list)                         -- frames that contributed to reassembled data
--   D num proto id isresp opcode rcode qname qtype qclass ancount nscount arcount rrs(list of sec|name|type|ttl|value) flags
--   N num id isresp opcode rcode names(list) addrs(list) qtype
--   H num kind method uri version host ua code phrase ctype clen headers(list) server location
--   J num kind streamid method path authority status ua ctype clen headers(list) server location request_in response_in
--   T num carrier hstype version sni alpn(list) supver(list) ciphers(list) certs(list hex) recver
--   A num opcode srcmac srcip dstmac dstip
--   C num msgtype chaddr hostname yiaddr reqip xid serverid leasetime mask routers(list) dns(list)
--   K num ipver type code typename codename ident seq qproto qsrc qdst qsport qdport   -- ICMP / ICMPv6
--   X num version direction                    -- SSH version string; direction 0 = client to server
--   Q num versions(list) supported(list)       -- QUIC long headers; supported = Version Negotiation list
--   V mac vendor locallyadministered           -- once per source MAC; vendor from Wireshark's built-in OUI table
--   W message                                  -- extractor warnings

local ARM_PATH = "/estx/arm"
local DONE_PATH = "/estx/done"
local PROGRESS_EVERY = 2000

local missing = {}
local function F(name)
  local ok, f = pcall(Field.new, name)
  if ok then return f end
  missing[#missing + 1] = name
  return nil
end

local f = {
  num = F("frame.number"), epoch = F("frame.time_epoch"), len = F("frame.len"), caplen = F("frame.cap_len"),
  iface = F("frame.interface_id"), ifname = F("frame.interface_name"), encap = F("frame.encap_type"),
  protos = F("frame.protocols"),
  ethsrc = F("eth.src"), ethdst = F("eth.dst"),
  ethvendor = F("eth.src.oui_resolved"), ethlocal = F("eth.src.lg"),
  ipsrc = F("ip.src"), ipdst = F("ip.dst"), ip6src = F("ipv6.src"), ip6dst = F("ipv6.dst"),
  ipmf = F("ip.flags.mf"), ipfrag = F("ip.frag_offset"), ip6frag = F("ipv6.fraghdr.offset"), ip6mf = F("ipv6.fraghdr.more"),
  tcpsport = F("tcp.srcport"), tcpdport = F("tcp.dstport"), udpsport = F("udp.srcport"), udpdport = F("udp.dstport"),
  tcpstream = F("tcp.stream"), udpstream = F("udp.stream"), tcpflags = F("tcp.flags"), tcplen = F("tcp.len"),
  retrans = F("tcp.analysis.retransmission"), fastretrans = F("tcp.analysis.fast_retransmission"),
  spurious = F("tcp.analysis.spurious_retransmission"), ooo = F("tcp.analysis.out_of_order"),
  lost = F("tcp.analysis.lost_segment"), dupack = F("tcp.analysis.duplicate_ack"), zerowin = F("tcp.analysis.zero_window"),
  malformed = F("_ws.malformed"), severity = F("_ws.expert.severity"),
  tcpseg = F("tcp.segment"), ipfragment = F("ip.fragment"),
  tls_app_data = F("tls.app_data"),
  quic_stream_data = F("quic.stream_data"), quic_short = F("quic.short"),
  -- DNS / mDNS / LLMNR share the DNS dissector's fields
  p_dns = F("dns"), p_mdns = F("mdns"), p_llmnr = F("llmnr"),
  dns_id = F("dns.id"), dns_resp = F("dns.flags.response"), dns_opcode = F("dns.flags.opcode"), dns_rcode = F("dns.flags.rcode"),
  dns_trunc = F("dns.flags.truncated"),
  dns_qname = F("dns.qry.name"), dns_qtype = F("dns.qry.type"), dns_qclass = F("dns.qry.class"),
  dns_an = F("dns.count.answers"), dns_ns = F("dns.count.auth_rr"), dns_ar = F("dns.count.add_rr"),
  dns_rname = F("dns.resp.name"), dns_rtype = F("dns.resp.type"), dns_ttl = F("dns.resp.ttl"),
  dns_a = F("dns.a"), dns_aaaa = F("dns.aaaa"), dns_cname = F("dns.cname"), dns_ptr = F("dns.ptr.domain_name"),
  dns_nsv = F("dns.ns"), dns_mx = F("dns.mx.mail_exchange"), dns_txt = F("dns.txt"), dns_srv = F("dns.srv.target"),
  dns_soa = F("dns.soa.mname"),
  -- NBNS
  nb_id = F("nbns.id"), nb_resp = F("nbns.flags.response"), nb_opcode = F("nbns.flags.opcode"), nb_rcode = F("nbns.flags.rcode"),
  nb_name = F("nbns.name"), nb_addr = F("nbns.addr"), nb_type = F("nbns.type"),
  -- HTTP/1.x
  p_http = F("http"),
  http_method = F("http.request.method"), http_uri = F("http.request.uri"), http_reqver = F("http.request.version"),
  http_host = F("http.host"), http_ua = F("http.user_agent"), http_code = F("http.response.code"),
  http_phrase = F("http.response.phrase"), http_respver = F("http.response.version"), http_ctype = F("http.content_type"),
  http_clen = F("http.content_length_header"), http_reqline = F("http.request.line"), http_respline = F("http.response.line"),
  http_server = F("http.server"), http_location = F("http.location"),
  http_request_in = F("http.request_in"), http_response_in = F("http.response_in"),
  -- HTTP/2
  h2_streamid = F("http2.streamid"), h2_type = F("http2.type"), h2_flags = F("http2.flags"),
  h2_method = F("http2.headers.method"), h2_path = F("http2.headers.path"),
  h2_authority = F("http2.headers.authority"), h2_status = F("http2.headers.status"),
  h2_name = F("http2.header.name"), h2_value = F("http2.header.value"),
  h2_header_count = F("http2.header.count"),
  h2_ua = F("http2.headers.user_agent"), h2_ctype = F("http2.headers.content_type"),
  h2_clen = F("http2.headers.content_length"), h2_server = F("http2.headers.server"),
  h2_location = F("http2.headers.location"), h2_request_in = F("http2.request_in"), h2_response_in = F("http2.response_in"),
  -- TLS handshakes (also used by QUIC Initial packets, which Wireshark can decode)
  tls_hstype = F("tls.handshake.type"), tls_hsver = F("tls.handshake.version"), tls_sni = F("tls.handshake.extensions_server_name"),
  tls_alpn = F("tls.handshake.extensions_alpn_str"), tls_supver = F("tls.handshake.extensions.supported_version"),
  tls_cipher = F("tls.handshake.ciphersuite"), tls_cert = F("tls.handshake.certificate"), tls_recver = F("tls.record.version"),
  -- ARP / DHCP
  arp_op = F("arp.opcode"), arp_smac = F("arp.src.hw_mac"), arp_sip = F("arp.src.proto_ipv4"),
  arp_tmac = F("arp.dst.hw_mac"), arp_tip = F("arp.dst.proto_ipv4"),
  dhcp_type = F("dhcp.option.dhcp"), dhcp_mac = F("dhcp.hw.mac_addr"), dhcp_host = F("dhcp.option.hostname"),
  dhcp_yi = F("dhcp.ip.your"), dhcp_req = F("dhcp.option.requested_ip_address"),
  dhcp_xid = F("dhcp.id"), dhcp_sid = F("dhcp.option.dhcp_server_id"), dhcp_lease = F("dhcp.option.ip_address_lease_time"),
  dhcp_mask = F("dhcp.option.subnet_mask"), dhcp_router = F("dhcp.option.router"), dhcp_dns = F("dhcp.option.domain_name_server"),
  -- ICMP / ICMPv6 (quoted headers of error messages are read from the second ip/ipv6 layer)
  ipproto = F("ip.proto"), ip6nxt = F("ipv6.nxt"),
  icmp_type = F("icmp.type"), icmp_code = F("icmp.code"), icmp_id = F("icmp.ident"), icmp_seq = F("icmp.seq"),
  icmp6_type = F("icmpv6.type"), icmp6_code = F("icmpv6.code"),
  icmp6_id = F("icmpv6.echo.identifier"), icmp6_seq = F("icmpv6.echo.sequence_number"),
  -- SSH / QUIC
  ssh_proto = F("ssh.protocol"), ssh_dir = F("ssh.direction"),
  quic_ver = F("quic.version"), quic_sup = F("quic.supported_version"),
}

local esc_map = { ["\\"] = "\\\\", ["\t"] = "\\t", ["\n"] = "\\n", ["\r"] = "\\r", ["\31"] = "\\u" }
local function esc(s)
  if s == nil then return "" end
  s = tostring(s)
  if s:find("[\\\t\n\r\31]") then s = s:gsub("[\\\t\n\r\31]", esc_map) end
  return s
end

local function all(field)
  if not field then return {} end
  return { field() }
end

local function first(field)
  if not field then return nil end
  local v = field()
  if v == nil then return nil end
  return v
end

local function val(field)
  local v = first(field)
  if v == nil then return "" end
  return esc(v.value)
end

-- MAC addresses from their raw bytes. tostring() on an Ethernet address
-- applies Wireshark's name resolution ("Intel_aa:bb:cc", "Broadcast").
local function mac_text(fi)
  if fi == nil then return "" end
  local ok, hex = pcall(function() return fi.range:bytes():tohex() end)
  if not ok or not hex or #hex ~= 12 then return esc(fi.value) end
  return hex:lower():gsub("(%x%x)", "%1:"):sub(1, 17)
end

local function mac(field)
  return mac_text(first(field))
end

local function present(field)
  return field ~= nil and field() ~= nil
end

local function vals(fis, display)
  local out = {}
  for i, fi in ipairs(fis) do out[i] = esc(display and fi.display or fi.value) end
  return table.concat(out, "\31")
end

-- Offsets are local to a Tvb, so only compare them when both items came from
-- the same data source. Keep the offset fallback only when neither source is
-- available; if exactly one is missing, there is no safe identity comparison.
local function same_source(anchor, fi)
  if anchor.source == nil and fi.source == nil then return true end
  return anchor.source ~= nil and fi.source ~= nil and anchor.source == fi.source
end

local function anchors_from(list)
  local groups = {}
  local groupCount = 0
  for i, anchor in ipairs(list) do
    anchor.order = i
    local group
    for _, candidate in ipairs(groups) do
      if same_source(candidate, anchor) then group = candidate break end
    end
    if not group then
      groupCount = groupCount + 1
      group = { source = anchor.source, order = groupCount }
      groups[#groups + 1] = group
    end
    anchor.sourceOrder = group.order
  end
  -- Order sources by their first occurrence, and compare offsets only inside
  -- each source group. Different reassembly buffers have no shared byte order.
  table.sort(list, function(a, b)
    if a.sourceOrder ~= b.sourceOrder then return a.sourceOrder < b.sourceOrder end
    if a.offset == b.offset then return a.order < b.order end
    return a.offset < b.offset
  end)
  return list
end

local function bucket(anchors, fis, by_start, include_generated)
  local n = #anchors
  local out = {}
  for i = 1, n do out[i] = {} end
  if n == 0 then return out end
  for _, fi in ipairs(fis) do
    -- Synthetic (generated, zero-length) items have no meaningful offset.
    -- Some real fields are flagged generated too (e.g. dns.id on unanswered queries).
    if include_generated or not (fi.generated and fi.len == 0) then
      local idx = nil
      local off = fi.offset
      if by_start then
        local first
        for i = n, 1, -1 do
          local a = anchors[i]
          if same_source(a, fi) then
            first = i
            if off >= a.offset then idx = i break end
          end
        end
        idx = idx or first
      else
        for i = 1, n do
          local a = anchors[i]
          if same_source(a, fi) and (n == 1 or (off >= a.offset and off < a.offset + math.max(a.len, 1))) then
            idx = i
            break
          end
        end
      end
      if idx then local b = out[idx]; b[#b + 1] = fi end
    end
  end
  return out
end

local function has(protos, name)
  return protos:find(":" .. name .. ":", 1, true) ~= nil
end

local state = { armed = false, out = nil, total = 0, ifaces = {}, macs = {} }

local function progress(phase, n)
  io.stdout:write("@@ESTX " .. phase .. " " .. n .. "\n")
  io.stdout:flush()
end

local function try_arm()
  local fh = io.open(ARM_PATH, "r")
  if not fh then return end
  local spec = fh:read("*a")
  fh:close()
  os.remove(ARM_PATH)
  local path, total = spec:match("^(%S+)%s+(%d+)")
  state.out = io.open(path, "w")
  state.total = tonumber(total)
  state.armed = state.out ~= nil
  state.ifaces = {}
  state.macs = {}
  if state.armed and #missing > 0 then
    state.out:write("W\tmissing fields: " .. esc(table.concat(missing, ", ")) .. "\n")
  end
end

local function finish()
  state.out:close()
  state.out = nil
  state.armed = false
  local d = io.open(DONE_PATH, "w")
  if d then d:write("ok") d:close() end
end

local function emit_dns(w, num)
  local anchors = {}
  for _, pair in ipairs({ { f.p_dns, "dns" }, { f.p_mdns, "mdns" }, { f.p_llmnr, "llmnr" } }) do
    for _, fi in ipairs(all(pair[1])) do anchors[#anchors + 1] = { offset = fi.offset, len = fi.len, source = fi.source, proto = pair[2] } end
  end
  if #anchors == 0 then return end
  anchors_from(anchors)
  local B = function(field) return bucket(anchors, all(field), false) end
  local ids, resp, opc, rc, tr = B(f.dns_id), B(f.dns_resp), B(f.dns_opcode), B(f.dns_rcode), B(f.dns_trunc)
  local qn, qt, qc = B(f.dns_qname), B(f.dns_qtype), B(f.dns_qclass)
  local an, ns, ar = B(f.dns_an), B(f.dns_ns), B(f.dns_ar)
  local rname, rtype, rttl = B(f.dns_rname), B(f.dns_rtype), B(f.dns_ttl)
  local valfields = { f.dns_a, f.dns_aaaa, f.dns_cname, f.dns_ptr, f.dns_nsv, f.dns_mx, f.dns_txt, f.dns_srv, f.dns_soa }
  local values = {}
  for i = 1, #anchors do values[i] = {} end
  for _, vf in ipairs(valfields) do
    local b = B(vf)
    for i = 1, #anchors do for _, fi in ipairs(b[i]) do local t = values[i]; t[#t + 1] = fi end end
  end
  for i, a in ipairs(anchors) do
    local function v1(list, display)
      local fi = list[i][1]
      if not fi then return "" end
      return esc(display and fi.display or fi.value)
    end
    -- Resource records: name/type/ttl anchors in order; each value belongs to the RR whose name precedes it.
    local names = rname[i]
    table.sort(names, function(x, y) return x.offset < y.offset end)
    local vs = values[i]
    local types, ttls = rtype[i], rttl[i]
    local nan = tonumber(an[i][1] and an[i][1].value) or 0
    local nns = tonumber(ns[i][1] and ns[i][1].value) or 0
    local rrs = {}
    for k, nm in ipairs(names) do
      local nxt = names[k + 1] and names[k + 1].offset or math.huge
      local parts = {}
      for _, fi in ipairs(vs) do
        if fi.offset >= nm.offset and fi.offset < nxt then parts[#parts + 1] = tostring(fi.value) end
      end
      local ty, tl = "", ""
      for _, fi in ipairs(types) do if fi.offset >= nm.offset and fi.offset < nxt then ty = fi.display break end end
      for _, fi in ipairs(ttls) do if fi.offset >= nm.offset and fi.offset < nxt then tl = tostring(fi.value) break end end
      local sec = (k <= nan) and "an" or ((k <= nan + nns) and "ns" or "ar")
      rrs[#rrs + 1] = esc(sec .. "|" .. tostring(nm.value) .. "|" .. ty .. "|" .. tl .. "|" .. table.concat(parts, ", "))
    end
    w:write(table.concat({ "D", num, a.proto, v1(ids), v1(resp), v1(opc), v1(rc), v1(qn), v1(qt, true), v1(qc, true),
      v1(an), v1(ns), v1(ar), table.concat(rrs, "\31"), v1(tr) }, "\t"), "\n")
  end
end

local function emit_nbns(w, num)
  if not present(f.nb_id) then return end
  w:write(table.concat({ "N", num, val(f.nb_id), val(f.nb_resp), val(f.nb_opcode), val(f.nb_rcode),
    vals(all(f.nb_name)), vals(all(f.nb_addr)), (first(f.nb_type) and esc(first(f.nb_type).display) or "") }, "\t"), "\n")
end

local function emit_http(w, num)
  local anchors = {}
  for _, fi in ipairs(all(f.p_http)) do anchors[#anchors + 1] = { offset = fi.offset, len = fi.len, source = fi.source } end
  if #anchors == 0 then return end
  anchors_from(anchors)
  local B = function(field) return bucket(anchors, all(field), false) end
  local m, u, rv, h, ua, c, ph, sv, ct, cl, rql, rsl, srv, loc, request_in, response_in =
    B(f.http_method), B(f.http_uri), B(f.http_reqver), B(f.http_host), B(f.http_ua), B(f.http_code), B(f.http_phrase),
    B(f.http_respver), B(f.http_ctype), B(f.http_clen), B(f.http_reqline), B(f.http_respline), B(f.http_server), B(f.http_location),
    bucket(anchors, all(f.http_request_in), true, true), bucket(anchors, all(f.http_response_in), true, true)
  for i = 1, #anchors do
    local function v1(list) local fi = list[i][1]; return fi and esc(fi.value) or "" end
    local kind
    if m[i][1] then kind = "req" elseif c[i][1] then kind = "resp" end
    if kind then
      local headers = kind == "req" and rql[i] or rsl[i]
      w:write(table.concat({ "H", num, kind, v1(m), v1(u), (kind == "req") and v1(rv) or v1(sv), v1(h), v1(ua), v1(c), v1(ph),
        v1(ct), v1(cl), vals(headers), v1(srv), v1(loc), v1(request_in), v1(response_in) }, "\t"), "\n")
    end
  end
end

local function emit_http2(w, num)
  local anchors = {}
  for _, fi in ipairs(all(f.h2_streamid)) do
    anchors[#anchors + 1] = { offset = fi.offset, len = fi.len, source = fi.source, id = fi.value }
  end
  if #anchors == 0 then return end
  anchors_from(anchors)
  local types = all(f.h2_type)
  local flags = all(f.h2_flags)
  -- The frame fields (stream ID/type) are sourced from the packet Tvb, while
  -- HPACK-decoded fields are sourced from a generated header-block Tvb. Their
  -- offsets cannot be compared. header.count gives one source per decoded
  -- HEADERS/CONTINUATION fragment; collect those sources through END_HEADERS.
  local groups = {}
  for _, fi in ipairs(all(f.h2_header_count)) do groups[#groups + 1] = { source = fi.source } end
  local function for_sources(field, sources)
    local out = {}
    for _, fi in ipairs(all(field)) do
      for _, source in ipairs(sources) do
        if same_source({ source = source }, fi) then
          out[#out + 1] = fi
          break
        end
      end
    end
    return out
  end
  local function firstValue(values, display)
    local fi = values[1]
    return fi and esc(display and fi.display or fi.value) or ""
  end
  local groupIndex = 1
  local headerSources = {}
  for i, a in ipairs(anchors) do
    local frameType = tonumber(types[i] and types[i].value)
    local frameFlags = tonumber(flags[i] and flags[i].value) or 0
    local endHeaders = math.floor(frameFlags / 4) % 2 == 1
    if (frameType == 1 or frameType == 9) and groups[groupIndex] then
      headerSources[#headerSources + 1] = groups[groupIndex].source
      groupIndex = groupIndex + 1
    end
    if endHeaders then
      if #headerSources == 0 then goto continue end
      local method = firstValue(for_sources(f.h2_method, headerSources))
      local status = firstValue(for_sources(f.h2_status, headerSources))
      local paths = for_sources(f.h2_path, headerSources)
      local authorities = for_sources(f.h2_authority, headerSources)
      local userAgents = for_sources(f.h2_ua, headerSources)
      local contentTypes = for_sources(f.h2_ctype, headerSources)
      local contentLengths = for_sources(f.h2_clen, headerSources)
      local servers = for_sources(f.h2_server, headerSources)
      local locations = for_sources(f.h2_location, headerSources)
      local requestIn = for_sources(f.h2_request_in, headerSources)
      local responseIn = for_sources(f.h2_response_in, headerSources)
      local names = for_sources(f.h2_name, headerSources)
      local values = for_sources(f.h2_value, headerSources)
      headerSources = {}
      if method ~= "" or status ~= "" then
        local headers = {}
        for k, name in ipairs(names) do
          local value = values[k]
          local headerName = tostring(name.value)
          if value and headerName:sub(1, 1) ~= ":" then headers[#headers + 1] = esc(headerName .. ": " .. tostring(value.value)) end
        end
        w:write(table.concat({ "J", num, method ~= "" and "req" or "resp", a.id, method, firstValue(paths),
          firstValue(authorities), status, firstValue(userAgents), firstValue(contentTypes), firstValue(contentLengths),
          table.concat(headers, "\31"), firstValue(servers), firstValue(locations),
          firstValue(requestIn), firstValue(responseIn) }, "\t"), "\n")
      end
    end
    ::continue::
  end
end

local function emit_tls(w, num, carrier)
  local types = all(f.tls_hstype)
  if #types == 0 then return end
  local anchors = {}
  for _, fi in ipairs(types) do
    if not fi.generated then anchors[#anchors + 1] = { offset = fi.offset, len = 0, source = fi.source, t = fi.value } end
  end
  if #anchors == 0 then return end
  anchors_from(anchors)
  local B = function(field) return bucket(anchors, all(field), true) end
  local ver, sni, alpn, sup, ciph, cert = B(f.tls_hsver), B(f.tls_sni), B(f.tls_alpn), B(f.tls_supver), B(f.tls_cipher), B(f.tls_cert)
  local recver = first(f.tls_recver)
  for i, a in ipairs(anchors) do
    local t = a.t
    if t == 1 or t == 2 or t == 11 then
      local certs = {}
      for k, fi in ipairs(cert[i]) do certs[k] = fi.range:bytes():tohex() end
      local v = ver[i][1]
      w:write(table.concat({ "T", num, carrier, t, v and esc(v.display) or "", (sni[i][1] and esc(sni[i][1].value) or ""),
        vals(alpn[i]), vals(sup[i], true), vals(ciph[i], true), table.concat(certs, "\31"),
        recver and esc(recver.display) or "" }, "\t"), "\n")
    end
  end
end

local function emit_arp(w, num)
  if not present(f.arp_op) then return end
  w:write(table.concat({ "A", num, val(f.arp_op), mac(f.arp_smac), val(f.arp_sip), mac(f.arp_tmac), val(f.arp_tip) }, "\t"), "\n")
end

local function emit_dhcp(w, num)
  if not present(f.dhcp_mac) then return end
  w:write(table.concat({ "C", num, val(f.dhcp_type), mac(f.dhcp_mac), val(f.dhcp_host), val(f.dhcp_yi), val(f.dhcp_req),
    val(f.dhcp_xid), val(f.dhcp_sid), val(f.dhcp_lease), val(f.dhcp_mask), vals(all(f.dhcp_router)), vals(all(f.dhcp_dns)) }, "\t"), "\n")
end

-- "3 (Destination unreachable)" or "Destination Unreachable (1)" -> the name only
local function code_name(fi)
  if fi == nil then return "" end
  local d = tostring(fi.display)
  return esc(d:match("^%d+ %((.*)%)$") or d:match("^(.-) %(%d+%)$") or d)
end

-- One line per ICMP message (the outer one). Error messages quote the packet
-- that caused them; its addresses come from the second (inner) IP layer and
-- its ports from the only TCP/UDP layer present.
local function emit_icmp(w, num, v6)
  local ty, co, id, sq = f.icmp_type, f.icmp_code, f.icmp_id, f.icmp_seq
  local src, dst, proto = f.ipsrc, f.ipdst, f.ipproto
  if v6 then
    ty, co, id, sq = f.icmp6_type, f.icmp6_code, f.icmp6_id, f.icmp6_seq
    src, dst, proto = f.ip6src, f.ip6dst, f.ip6nxt
  end
  local t = first(ty)
  if not t then return end
  local c = first(co)
  -- The quoted packet is whatever IP and TCP/UDP header follows the ICMP
  -- header; tunnels (VXLAN, GRE, IP-in-IP) put more IP headers before it.
  local function after(field)
    for _, fi in ipairs(all(field)) do
      if fi.offset > t.offset then return fi end
    end
    return nil
  end
  local qs, qd, qp = after(src), after(dst), after(proto)
  local sport, dport = after(f.tcpsport), after(f.tcpdport)
  if not sport then sport, dport = after(f.udpsport), after(f.udpdport) end
  local inner = qs ~= nil
  w:write(table.concat({ "K", num, v6 and "6" or "4", tostring(t.value), c and tostring(c.value) or "", code_name(t), code_name(c),
    val(id), val(sq), (inner and qp) and code_name(qp) or "", inner and esc(qs.value) or "", (inner and qd) and esc(qd.value) or "",
    (inner and sport) and tostring(sport.value) or "", (inner and dport) and tostring(dport.value) or "" }, "\t"), "\n")
end

local function emit_ssh(w, num)
  for _, fi in ipairs(all(f.ssh_proto)) do
    local d = first(f.ssh_dir)
    w:write(table.concat({ "X", num, esc(fi.value), d == nil and "" or (d.value and "1" or "0") }, "\t"), "\n")
  end
end

local function emit_quic(w, num)
  local vs = all(f.quic_ver)
  if #vs == 0 then return end
  w:write(table.concat({ "Q", num, vals(vs, true), vals(all(f.quic_sup), true) }, "\t"), "\n")
end

local function flag_str()
  local s = ""
  if present(f.retrans) or present(f.fastretrans) then s = s .. "R" end
  if present(f.spurious) then s = s .. "r" end
  if present(f.ooo) then s = s .. "O" end
  if present(f.lost) then s = s .. "L" end
  if present(f.dupack) then s = s .. "D" end
  if present(f.zerowin) then s = s .. "Z" end
  local mf, fo = first(f.ipmf), first(f.ipfrag)
  if (mf and mf.value) or (fo and fo.value ~= 0) or present(f.ip6frag) then s = s .. "F" end
  if present(f.ipfragment) then s = s .. "f" end
  if present(f.malformed) then s = s .. "M" end
  for _, fi in ipairs(all(f.severity)) do
    if fi.value >= 0x00800000 then s = s .. "E" break end
  end
  return s
end

local p = Proto("estudely_extract", "Estudely Packet Explorer extractor")

function p.dissector(tvb, pinfo, tree)
  local num = pinfo.number
  if num == 1 then try_arm() end
  if not state.armed then
    -- Not our extraction pass (initial load, packet details, filtering).
    if not pinfo.visited and num % PROGRESS_EVERY == 0 then progress("load", num) end
    return
  end
  local w = state.out
  local protos_fi = first(f.protos)
  local protos = protos_fi and tostring(protos_fi.value) or ""
  local wrapped = ":" .. protos .. ":"

  local iface = first(f.iface)
  local ifid = iface and tostring(iface.value) or ""
  if not state.ifaces[ifid] then
    state.ifaces[ifid] = true
    local enc = first(f.encap)
    w:write(table.concat({ "I", ifid, enc and esc(enc.display) or "", val(f.ifname) }, "\t"), "\n")
  end

  local src, dst = first(f.ipsrc), first(f.ipdst)
  if not src then src, dst = first(f.ip6src), first(f.ip6dst) end
  local sport, dport = first(f.tcpsport), first(f.tcpdport)
  if not sport then sport, dport = first(f.udpsport), first(f.udpdport) end
  local epoch = first(f.epoch)

  w:write(table.concat({ "P", num, epoch and tostring(epoch.value) or tostring(pinfo.abs_ts), val(f.len), val(f.caplen), ifid,
    esc(protos), mac(f.ethsrc), mac(f.ethdst), src and esc(src.value) or "", dst and esc(dst.value) or "",
    sport and tostring(sport.value) or "", dport and tostring(dport.value) or "",
    val(f.tcpstream), val(f.udpstream), val(f.tcpflags), val(f.tcplen), flag_str(),
    present(f.tls_app_data) and "1" or "0", present(f.quic_stream_data) and "1" or "0",
    present(f.quic_short) and "1" or "0" }, "\t"), "\n")

  local srcmac = mac(f.ethsrc)
  if srcmac ~= "" and not state.macs[srcmac] then
    state.macs[srcmac] = true
    local lg = first(f.ethlocal)
    w:write(table.concat({ "V", srcmac, val(f.ethvendor), (lg and lg.value) and "1" or "0" }, "\t"), "\n")
  end

  local segs = all(f.tcpseg)
  if #segs <= 1 then segs = all(f.ipfragment) end
  if #segs > 1 then w:write("S\t", num, "\t", vals(segs), "\n") end

  -- ICMP error messages quote the offending packet; do not treat quoted headers as traffic.
  local quoted = has(wrapped, "icmp") or has(wrapped, "icmpv6")
  if not quoted then
    if has(wrapped, "dns") or has(wrapped, "mdns") or has(wrapped, "llmnr") then emit_dns(w, num) end
    if has(wrapped, "nbns") then emit_nbns(w, num) end
    if has(wrapped, "http") then emit_http(w, num) end
    if has(wrapped, "http2") then emit_http2(w, num) end
    if has(wrapped, "tls") then emit_tls(w, num, has(wrapped, "quic") and "quic" or "tcp") end
    if has(wrapped, "dhcp") then emit_dhcp(w, num) end
    if has(wrapped, "ssh") then emit_ssh(w, num) end
    if has(wrapped, "quic") then emit_quic(w, num) end
  end
  if has(wrapped, "icmp") then emit_icmp(w, num, false) elseif has(wrapped, "icmpv6") then emit_icmp(w, num, true) end
  if has(wrapped, "arp") then emit_arp(w, num) end

  if num % PROGRESS_EVERY == 0 then progress("extract", num) end
  if num >= state.total then finish() end
end

register_postdissector(p)
