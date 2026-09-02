/* ═══════════════════════════════════════════════════════════════
   Wireshark Hub — Vanilla JS App
   Data models + Rendering + Navigation + Search + Copy
   ═══════════════════════════════════════════════════════════════ */

/* ───────── DATA: FILTERS (400+) ───────── */
// Multi-term search: every whitespace-separated term must appear somewhere in
// the entry's command, description or category. A single term behaves exactly
// as before, so "ssl" is unchanged, while "ssl profile" now matches
// "list ltm profile client-ssl" — previously it matched nothing, because the
// whole query had to occur as one contiguous substring.
function matchesQuery(item, query) {
  var hay = ((item.code || "") + " " + (item.desc || "") + " " + (item.cat || "")).toLowerCase();
  var terms = String(query == null ? "" : query).toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return false;
  for (var i = 0; i < terms.length; i++) if (hay.indexOf(terms[i]) === -1) return false;
  return true;
}

const FILTERS = [
  // ═════════════════════ PORT ═════════════════════
  { cat: "Port", code: "tcp.port == 443", desc: "TCP 443 (iki yön) — HTTPS trafiği", sev: "i" },
  { cat: "Port", code: "tcp.srcport == 443", desc: "Source port 443 — HTTPS sunucudan gelen", sev: "i" },
  { cat: "Port", code: "tcp.dstport == 443", desc: "Dest port 443 — HTTPS sunucuya giden", sev: "i" },
  { cat: "Port", code: "tcp.port == 80", desc: "HTTP (düz) trafik", sev: "i" },
  { cat: "Port", code: "tcp.port == 8080", desc: "Alt HTTP portu", sev: "i" },
  { cat: "Port", code: "tcp.port == 8443", desc: "Alt HTTPS portu", sev: "i" },
  { cat: "Port", code: "tcp.port in {80 443 8080 8443}", desc: "Tüm web portları", sev: "i" },
  { cat: "Port", code: "tcp.srcport in {80 443}", desc: "Web sunuculardan gelen", sev: "i" },
  { cat: "Port", code: "tcp.dstport in {80 443}", desc: "Web sunuculara giden", sev: "i" },
  { cat: "Port", code: "tcp.port == 22", desc: "SSH trafiği", sev: "i" },
  { cat: "Port", code: "tcp.port == 3389", desc: "RDP trafiği", sev: "i" },
  { cat: "Port", code: "tcp.port == 3306", desc: "MySQL/MariaDB", sev: "i" },
  { cat: "Port", code: "tcp.port == 5432", desc: "PostgreSQL", sev: "i" },
  { cat: "Port", code: "tcp.port == 1433", desc: "MSSQL", sev: "i" },
  { cat: "Port", code: "tcp.port == 1521", desc: "Oracle DB", sev: "i" },
  { cat: "Port", code: "tcp.port == 27017", desc: "MongoDB", sev: "i" },
  { cat: "Port", code: "tcp.port == 6379", desc: "Redis", sev: "i" },
  { cat: "Port", code: "tcp.port == 9200", desc: "Elasticsearch HTTP", sev: "i" },
  { cat: "Port", code: "tcp.port == 5060", desc: "SIP (UDP genelde ama TCP de olur)", sev: "i" },
  { cat: "Port", code: "udp.port == 5060", desc: "SIP UDP", sev: "i" },
  { cat: "Port", code: "udp.port == 53", desc: "DNS", sev: "i" },
  { cat: "Port", code: "tcp.port == 53", desc: "DNS over TCP (zone transfer / büyük response)", sev: "i" },
  { cat: "Port", code: "udp.port == 123", desc: "NTP", sev: "i" },
  { cat: "Port", code: "udp.port == 67 || udp.port == 68", desc: "DHCP server/client", sev: "i" },
  { cat: "Port", code: "udp.port == 161 || udp.port == 162", desc: "SNMP query/trap", sev: "i" },
  { cat: "Port", code: "udp.portrange 10000-20000", desc: "RTP medya aralığı (VoIP)", sev: "i" },
  { cat: "Port", code: "tcp.portrange 8000-8999", desc: "Port aralığı örnek", sev: "i" },
  { cat: "Port", code: "tcp && !tcp.port in {80 443 22 53}", desc: "Standart portlar dışı TCP", sev: "i" },
  { cat: "Port", code: "tcp.port > 49152", desc: "Ephemeral port aralığı (Windows)", sev: "i" },
  { cat: "Port", code: "tcp.port < 1024", desc: "Well-known portlar", sev: "i" },

  // ═════════════════════ ETHERNET / MAC ═════════════════════
  { cat: "Ethernet", code: "eth.addr == aa:bb:cc:dd:ee:ff", desc: "Belirli MAC (iki yön)", sev: "i" },
  { cat: "Ethernet", code: "eth.src == aa:bb:cc:dd:ee:ff", desc: "Kaynak MAC", sev: "i" },
  { cat: "Ethernet", code: "eth.dst == aa:bb:cc:dd:ee:ff", desc: "Hedef MAC", sev: "i" },
  { cat: "Ethernet", code: "eth.addr == ff:ff:ff:ff:ff:ff", desc: "Broadcast trafiği", sev: "i" },
  { cat: "Ethernet", code: "eth.dst[0] & 1", desc: "Multicast MAC (broadcast dahil)", sev: "i" },
  { cat: "Ethernet", code: "eth.type == 0x0800", desc: "IPv4 (Ethertype)", sev: "i" },
  { cat: "Ethernet", code: "eth.type == 0x0806", desc: "ARP", sev: "i" },
  { cat: "Ethernet", code: "eth.type == 0x86dd", desc: "IPv6", sev: "i" },
  { cat: "Ethernet", code: "eth.type == 0x8100", desc: "802.1Q VLAN tagged", sev: "i" },
  { cat: "Ethernet", code: "eth.type == 0x8847", desc: "MPLS unicast", sev: "i" },
  { cat: "Ethernet", code: "eth.src[0:3] == 00:50:56", desc: "VMware ESXi OUI", sev: "i" },
  { cat: "Ethernet", code: "eth.src[0:3] == 00:0c:29", desc: "VMware Workstation OUI", sev: "i" },

  // ═════════════════════ ARP ═════════════════════
  { cat: "ARP", code: "arp", desc: "Tüm ARP trafiği", sev: "i" },
  { cat: "ARP", code: "arp.opcode == 1", desc: "ARP Request (who-has)", sev: "i" },
  { cat: "ARP", code: "arp.opcode == 2", desc: "ARP Reply (is-at)", sev: "i" },
  { cat: "ARP", code: "arp.src.proto_ipv4 == 10.0.0.1", desc: "Belirli IP'den ARP", sev: "i" },
  { cat: "ARP", code: "arp.dst.proto_ipv4 == 10.0.0.1", desc: "Belirli IP için ARP", sev: "i" },
  { cat: "ARP", code: "arp.duplicate-address-detected", desc: "Duplicate IP tespit (çakışma!)", sev: "e" },
  { cat: "ARP", code: "arp.duplicate-address-frame", desc: "Aynı IP farklı MAC'lerde", sev: "e" },
  { cat: "ARP", code: "arp.isannouncement", desc: "Gratuitous ARP", sev: "i" },
  { cat: "ARP", code: "arp.src.hw_mac == aa:bb:cc:dd:ee:ff", desc: "Belirli MAC'ten ARP", sev: "i" },

  // ═════════════════════ IP (v4 + v6) ═════════════════════
  { cat: "IP", code: "ip.addr == 10.0.0.1", desc: "IP (iki yön)", sev: "i" },
  { cat: "IP", code: "ip.src == 10.0.0.1", desc: "Kaynak IP", sev: "i" },
  { cat: "IP", code: "ip.dst == 10.0.0.1", desc: "Hedef IP", sev: "i" },
  { cat: "IP", code: "ip.addr == 10.0.0.0/24", desc: "Subnet (CIDR)", sev: "i" },
  { cat: "IP", code: "ip.addr == 10.0.0.1/32", desc: "Tek host (/32)", sev: "i" },
  { cat: "IP", code: "ip.src == 10.0.0.0/8 && ip.dst == 192.168.0.0/16", desc: "Subnet → subnet", sev: "i" },
  { cat: "IP", code: "!(ip.addr == 10.0.0.0/8)", desc: "Subnet HARİÇ", sev: "i" },
  { cat: "IP", code: "ip.proto == 6", desc: "TCP (protocol 6)", sev: "i" },
  { cat: "IP", code: "ip.proto == 17", desc: "UDP (protocol 17)", sev: "i" },
  { cat: "IP", code: "ip.proto == 1", desc: "ICMP (protocol 1)", sev: "i" },
  { cat: "IP", code: "ip.proto == 47", desc: "GRE (protocol 47)", sev: "i" },
  { cat: "IP", code: "ip.proto == 50", desc: "ESP (IPsec protocol 50)", sev: "i" },
  { cat: "IP", code: "ip.ttl == 1", desc: "TTL 1 — hop sonu (traceroute)", sev: "w" },
  { cat: "IP", code: "ip.ttl < 10", desc: "Düşük TTL — loop şüphesi", sev: "w" },
  { cat: "IP", code: "ip.ttl == 255", desc: "Başlangıç TTL (local)", sev: "i" },
  { cat: "IP", code: "ip.flags.df == 1", desc: "Don't Fragment bit set", sev: "i" },
  { cat: "IP", code: "ip.flags.mf == 1", desc: "More Fragments (fragmented)", sev: "w" },
  { cat: "IP", code: "ip.frag_offset > 0", desc: "Fragment parçası", sev: "w" },
  { cat: "IP", code: "ip.checksum_bad == 1", desc: "Hatalı checksum (NIC offload?)", sev: "w" },
  { cat: "IP", code: "ip.dsfield.dscp != 0", desc: "DSCP (QoS) işaretli", sev: "i" },
  { cat: "IP", code: "ipv6", desc: "Tüm IPv6 trafiği", sev: "i" },
  { cat: "IP", code: "ipv6.addr == fe80::1", desc: "IPv6 adres", sev: "i" },
  { cat: "IP", code: "ipv6.src == 2001:db8::1", desc: "IPv6 kaynak", sev: "i" },
  { cat: "IP", code: "ipv6.dst == 2001:db8::1", desc: "IPv6 hedef", sev: "i" },
  { cat: "IP", code: "ipv6.addr == ::1", desc: "IPv6 localhost", sev: "i" },
  { cat: "IP", code: "ip.version == 4", desc: "Sadece IPv4", sev: "i" },
  { cat: "IP", code: "ip.version == 6", desc: "Sadece IPv6", sev: "i" },

  // ═════════════════════ ICMP ═════════════════════
  { cat: "ICMP", code: "icmp", desc: "Tüm ICMPv4", sev: "i" },
  { cat: "ICMP", code: "icmp.type == 0", desc: "Echo Reply (ping yanıtı)", sev: "i" },
  { cat: "ICMP", code: "icmp.type == 8", desc: "Echo Request (ping)", sev: "i" },
  { cat: "ICMP", code: "icmp.type == 3", desc: "Destination Unreachable", sev: "e" },
  { cat: "ICMP", code: "icmp.type == 3 && icmp.code == 0", desc: "Net Unreachable", sev: "e" },
  { cat: "ICMP", code: "icmp.type == 3 && icmp.code == 1", desc: "Host Unreachable", sev: "e" },
  { cat: "ICMP", code: "icmp.type == 3 && icmp.code == 3", desc: "Port Unreachable", sev: "e" },
  { cat: "ICMP", code: "icmp.type == 3 && icmp.code == 4", desc: "Fragmentation Needed (MTU)", sev: "e" },
  { cat: "ICMP", code: "icmp.type == 5", desc: "Redirect (güvenlik riski)", sev: "w" },
  { cat: "ICMP", code: "icmp.type == 11", desc: "Time Exceeded (TTL=0 / traceroute)", sev: "w" },
  { cat: "ICMP", code: "icmpv6", desc: "Tüm ICMPv6", sev: "i" },
  { cat: "ICMP", code: "icmpv6.type == 135", desc: "Neighbor Solicitation (IPv6 ARP)", sev: "i" },
  { cat: "ICMP", code: "icmpv6.type == 136", desc: "Neighbor Advertisement", sev: "i" },
  { cat: "ICMP", code: "icmpv6.type == 133", desc: "Router Solicitation", sev: "i" },
  { cat: "ICMP", code: "icmpv6.type == 134", desc: "Router Advertisement", sev: "i" },

  // ═════════════════════ TCP GENEL ═════════════════════
  { cat: "TCP", code: "tcp", desc: "Tüm TCP", sev: "i" },
  { cat: "TCP", code: "tcp.stream eq 0", desc: "İlk TCP stream", sev: "i" },
  { cat: "TCP", code: "tcp.stream eq 5", desc: "Belirli stream", sev: "i" },
  { cat: "TCP", code: "tcp.seq == 0", desc: "İlk sequence (genelde SYN)", sev: "i" },
  { cat: "TCP", code: "tcp.window_size_value < 1000", desc: "Küçük window (throughput sorunu)", sev: "w" },
  { cat: "TCP", code: "tcp.window_size_value == 0", desc: "Zero window ham paketi", sev: "e" },
  { cat: "TCP", code: "tcp.analysis.flags && !tcp.analysis.window_update", desc: "Tüm TCP sorunları", sev: "e" },
  { cat: "TCP", code: "tcp.analysis.retransmission", desc: "Yeniden iletim", sev: "w" },
  { cat: "TCP", code: "tcp.analysis.fast_retransmission", desc: "Fast retransmission", sev: "w" },
  { cat: "TCP", code: "tcp.analysis.spurious_retransmission", desc: "Sahte retransmission", sev: "i" },
  { cat: "TCP", code: "tcp.analysis.duplicate_ack", desc: "Duplicate ACK", sev: "w" },
  { cat: "TCP", code: "tcp.analysis.lost_segment", desc: "Kayıp segment", sev: "e" },
  { cat: "TCP", code: "tcp.analysis.out_of_order", desc: "Sıra dışı paket", sev: "w" },
  { cat: "TCP", code: "tcp.analysis.zero_window", desc: "Zero Window event", sev: "e" },
  { cat: "TCP", code: "tcp.analysis.zero_window_probe", desc: "Zero window probe", sev: "w" },
  { cat: "TCP", code: "tcp.analysis.window_full", desc: "Window Full", sev: "w" },
  { cat: "TCP", code: "tcp.analysis.window_update", desc: "Window Update", sev: "i" },
  { cat: "TCP", code: "tcp.analysis.keep_alive", desc: "Keepalive probe", sev: "i" },
  { cat: "TCP", code: "tcp.analysis.keep_alive_ack", desc: "Keepalive yanıtı", sev: "i" },
  { cat: "TCP", code: "tcp.analysis.rto", desc: "Retransmission Timeout", sev: "e" },
  { cat: "TCP", code: "tcp.analysis.ack_rtt > 0.5", desc: "ACK 500ms+ geç", sev: "w" },
  { cat: "TCP", code: "tcp.analysis.bytes_in_flight", desc: "Uçuştaki byte", sev: "i" },
  { cat: "TCP", code: "tcp.len > 0", desc: "Veri taşıyan paketler", sev: "i" },
  { cat: "TCP", code: "tcp.len == 0", desc: "Veri taşımayan (ACK/SYN/FIN)", sev: "i" },
  { cat: "TCP", code: "tcp.options.mss_val < 1400", desc: "Küçük MSS (tunnel/VPN?)", sev: "w" },
  { cat: "TCP", code: "tcp.options.sack_perm == 1", desc: "SACK supported", sev: "i" },
  { cat: "TCP", code: "tcp.options.wscale.multiplier > 1", desc: "Window scaling aktif", sev: "i" },
  { cat: "TCP", code: "tcp.hdr_len > 20", desc: "TCP options var", sev: "i" },
  { cat: "TCP", code: "tcp.connection.syn", desc: "Yeni bağlantı", sev: "i" },
  { cat: "TCP", code: "tcp.connection.fin", desc: "Düzgün kapanış", sev: "i" },
  { cat: "TCP", code: "tcp.connection.rst", desc: "RST kapanışı", sev: "e" },
  { cat: "TCP", code: "tcp.connection.sack", desc: "SACK kullanıldı", sev: "i" },

  // ═════════════════════ TCP FLAGS ═════════════════════
  { cat: "TCP Flags", code: "tcp.flags.syn == 1 && tcp.flags.ack == 0", desc: "SYN — yeni bağlantı", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags.syn == 1 && tcp.flags.ack == 1", desc: "SYN-ACK — kabul", sev: "ok" },
  { cat: "TCP Flags", code: "tcp.flags.ack == 1 && tcp.flags.syn == 0 && tcp.flags.fin == 0 && tcp.flags.rst == 0", desc: "Sadece ACK", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags.fin == 1", desc: "FIN — düzgün kapanış", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags.fin == 1 && tcp.flags.ack == 1", desc: "FIN-ACK", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags.reset == 1", desc: "RST — zorla kesme", sev: "e" },
  { cat: "TCP Flags", code: "tcp.flags.reset == 1 && tcp.flags.ack == 1", desc: "RST-ACK", sev: "e" },
  { cat: "TCP Flags", code: "tcp.flags.reset == 1 && tcp.flags.ack == 0", desc: "RST only (port kapalı)", sev: "e" },
  { cat: "TCP Flags", code: "tcp.flags.push == 1", desc: "PSH — hemen ilet", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags.push == 1 && tcp.flags.ack == 1", desc: "PSH-ACK", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags.urg == 1", desc: "URG — acil (nadir)", sev: "w" },
  { cat: "TCP Flags", code: "tcp.flags.ece == 1", desc: "ECE — congestion echo", sev: "w" },
  { cat: "TCP Flags", code: "tcp.flags.cwr == 1", desc: "CWR — congestion reduced", sev: "w" },
  { cat: "TCP Flags", code: "tcp.flags == 0x02", desc: "0x02 = SYN", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags == 0x12", desc: "0x12 = SYN-ACK", sev: "ok" },
  { cat: "TCP Flags", code: "tcp.flags == 0x10", desc: "0x10 = ACK only", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags == 0x04", desc: "0x04 = RST", sev: "e" },
  { cat: "TCP Flags", code: "tcp.flags == 0x14", desc: "0x14 = RST-ACK", sev: "e" },
  { cat: "TCP Flags", code: "tcp.flags == 0x11", desc: "0x11 = FIN-ACK", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags == 0x18", desc: "0x18 = PSH-ACK", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags == 0x019", desc: "0x019 = FIN-PSH-ACK", sev: "i" },
  { cat: "TCP Flags", code: "tcp.flags == 0x000", desc: "NULL scan", sev: "e" },
  { cat: "TCP Flags", code: "tcp.flags == 0x029", desc: "XMAS scan", sev: "e" },

  // ═════════════════════ UDP ═════════════════════
  { cat: "UDP", code: "udp", desc: "Tüm UDP", sev: "i" },
  { cat: "UDP", code: "udp.port == 53", desc: "DNS UDP", sev: "i" },
  { cat: "UDP", code: "udp.port == 123", desc: "NTP", sev: "i" },
  { cat: "UDP", code: "udp.srcport == 5060", desc: "SIP kaynağı UDP", sev: "i" },
  { cat: "UDP", code: "udp.length > 1400", desc: "Büyük UDP (fragment riski)", sev: "w" },
  { cat: "UDP", code: "udp.length < 50", desc: "Küçük UDP", sev: "i" },
  { cat: "UDP", code: "udp.checksum == 0", desc: "Checksum kapalı UDP", sev: "w" },
  { cat: "UDP", code: "udp.stream eq 0", desc: "İlk UDP stream", sev: "i" },

  // ═════════════════════ TLS / SSL ═════════════════════
  { cat: "TLS", code: "tls", desc: "Tüm TLS", sev: "i" },
  { cat: "TLS", code: "ssl", desc: "Eski SSL alias'ı", sev: "i" },
  { cat: "TLS", code: "tls.alert_message", desc: "TLS hata — İLK bakılacak", sev: "e" },
  { cat: "TLS", code: 'tls.alert_message.desc == "Handshake Failure"', desc: "Alert 40 — cipher uyumsuz", sev: "e" },
  { cat: "TLS", code: 'tls.alert_message.desc == "Certificate Expired"', desc: "Alert 45 — süre dolmuş", sev: "e" },
  { cat: "TLS", code: 'tls.alert_message.desc == "Unknown CA"', desc: "Alert 48 — CA güvenilmez", sev: "e" },
  { cat: "TLS", code: 'tls.alert_message.desc == "Bad Certificate"', desc: "Alert 42 — geçersiz cert", sev: "e" },
  { cat: "TLS", code: 'tls.alert_message.desc == "Close Notify"', desc: "Alert 0 — normal kapanış", sev: "i" },
  { cat: "TLS", code: "tls.handshake.type == 1", desc: "Client Hello", sev: "i" },
  { cat: "TLS", code: "tls.handshake.type == 2", desc: "Server Hello", sev: "i" },
  { cat: "TLS", code: "tls.handshake.type == 11", desc: "Certificate", sev: "i" },
  { cat: "TLS", code: "tls.handshake.type == 12", desc: "Server Key Exchange", sev: "i" },
  { cat: "TLS", code: "tls.handshake.type == 13", desc: "Certificate Request (mTLS)", sev: "i" },
  { cat: "TLS", code: "tls.handshake.type == 14", desc: "Server Hello Done", sev: "i" },
  { cat: "TLS", code: "tls.handshake.type == 15", desc: "Certificate Verify", sev: "i" },
  { cat: "TLS", code: "tls.handshake.type == 16", desc: "Client Key Exchange", sev: "i" },
  { cat: "TLS", code: "tls.handshake.type == 20", desc: "Finished — tamam", sev: "ok" },
  { cat: "TLS", code: "tls.handshake.type == 21", desc: "Alert (fatal)", sev: "e" },
  { cat: "TLS", code: "tls.record.content_type == 23", desc: "Application Data", sev: "i" },
  { cat: "TLS", code: "tls.record.content_type == 22", desc: "Handshake record", sev: "i" },
  { cat: "TLS", code: "tls.record.content_type == 21", desc: "Alert record", sev: "e" },
  { cat: "TLS", code: "tls.record.version == 0x0301", desc: "TLS 1.0 (güvensiz)", sev: "w" },
  { cat: "TLS", code: "tls.record.version == 0x0302", desc: "TLS 1.1 (güvensiz)", sev: "w" },
  { cat: "TLS", code: "tls.record.version == 0x0303", desc: "TLS 1.2", sev: "i" },
  { cat: "TLS", code: "tls.record.version == 0x0304", desc: "TLS 1.3", sev: "i" },
  { cat: "TLS", code: "tls.handshake.version < 0x0303", desc: "Eski TLS (risk)", sev: "e" },
  { cat: "TLS", code: "tls.handshake.extensions_server_name", desc: "SNI (istenen domain)", sev: "i" },
  { cat: "TLS", code: "tls.handshake.ciphersuite", desc: "Seçilen cipher", sev: "i" },
  { cat: "TLS", code: "tls.handshake.session_id_length > 0", desc: "Session resumption", sev: "i" },
  { cat: "TLS", code: "tls.handshake.certificate", desc: "Certificate bytes", sev: "i" },
  { cat: "TLS", code: "tls.change_cipher_spec", desc: "Change Cipher Spec", sev: "i" },

  // ═════════════════════ HTTP ═════════════════════
  { cat: "HTTP", code: "http", desc: "Tüm HTTP", sev: "i" },
  { cat: "HTTP", code: "http.request", desc: "HTTP istekleri", sev: "i" },
  { cat: "HTTP", code: "http.response", desc: "HTTP yanıtları", sev: "i" },
  { cat: "HTTP", code: "http.response.code == 200", desc: "200 OK", sev: "ok" },
  { cat: "HTTP", code: "http.response.code == 301", desc: "Permanent redirect", sev: "i" },
  { cat: "HTTP", code: "http.response.code == 302", desc: "Temporary redirect", sev: "i" },
  { cat: "HTTP", code: "http.response.code == 304", desc: "Not Modified (cache)", sev: "i" },
  { cat: "HTTP", code: "http.response.code >= 400 && http.response.code < 500", desc: "Tüm 4xx", sev: "w" },
  { cat: "HTTP", code: "http.response.code == 400", desc: "Bad Request", sev: "w" },
  { cat: "HTTP", code: "http.response.code == 401", desc: "Unauthorized", sev: "w" },
  { cat: "HTTP", code: "http.response.code == 403", desc: "Forbidden (WAF?)", sev: "w" },
  { cat: "HTTP", code: "http.response.code == 404", desc: "Not Found", sev: "w" },
  { cat: "HTTP", code: "http.response.code == 408", desc: "Request Timeout", sev: "w" },
  { cat: "HTTP", code: "http.response.code == 413", desc: "Payload Too Large", sev: "w" },
  { cat: "HTTP", code: "http.response.code == 429", desc: "Too Many Requests", sev: "w" },
  { cat: "HTTP", code: "http.response.code >= 500", desc: "Tüm 5xx", sev: "e" },
  { cat: "HTTP", code: "http.response.code == 500", desc: "Internal Server Error", sev: "e" },
  { cat: "HTTP", code: "http.response.code == 502", desc: "Bad Gateway", sev: "e" },
  { cat: "HTTP", code: "http.response.code == 503", desc: "Service Unavailable (pool down)", sev: "e" },
  { cat: "HTTP", code: "http.response.code == 504", desc: "Gateway Timeout", sev: "e" },
  { cat: "HTTP", code: "http.response.code == 505", desc: "HTTP Version Not Supported", sev: "w" },
  { cat: "HTTP", code: 'http.request.method == "GET"', desc: "GET istekleri", sev: "i" },
  { cat: "HTTP", code: 'http.request.method == "POST"', desc: "POST istekleri", sev: "i" },
  { cat: "HTTP", code: 'http.request.method == "PUT"', desc: "PUT istekleri", sev: "i" },
  { cat: "HTTP", code: 'http.request.method == "DELETE"', desc: "DELETE istekleri", sev: "w" },
  { cat: "HTTP", code: 'http.request.method == "OPTIONS"', desc: "CORS preflight", sev: "i" },
  { cat: "HTTP", code: 'http.request.method == "PATCH"', desc: "PATCH istekleri", sev: "i" },
  { cat: "HTTP", code: 'http.request.method == "HEAD"', desc: "HEAD istekleri", sev: "i" },
  { cat: "HTTP", code: 'http.request.uri contains "/api/"', desc: "API endpoint'leri", sev: "i" },
  { cat: "HTTP", code: 'http.request.uri contains "/admin"', desc: "Admin panel erişimi", sev: "w" },
  { cat: "HTTP", code: 'http.request.uri contains "/login"', desc: "Login endpoint", sev: "i" },
  { cat: "HTTP", code: 'http.request.uri contains "/payment"', desc: "Ödeme endpoint", sev: "i" },
  { cat: "HTTP", code: "http.request.full_uri", desc: "Tam URI (host+path)", sev: "i" },
  { cat: "HTTP", code: "http.host", desc: "Host header", sev: "i" },
  { cat: "HTTP", code: 'http.host == "api.bank.com"', desc: "Belirli host", sev: "i" },
  { cat: "HTTP", code: "http.user_agent", desc: "User-Agent", sev: "i" },
  { cat: "HTTP", code: 'http.user_agent contains "bot"', desc: "Bot trafiği", sev: "w" },
  { cat: "HTTP", code: "http.referer", desc: "Referer", sev: "i" },
  { cat: "HTTP", code: "http.cookie", desc: "Cookie gönderen istekler", sev: "i" },
  { cat: "HTTP", code: "http.set_cookie", desc: "Cookie set eden yanıtlar", sev: "i" },
  { cat: "HTTP", code: "http.authorization", desc: "Authorization header", sev: "i" },
  { cat: "HTTP", code: 'http.content_type contains "json"', desc: "JSON content", sev: "i" },
  { cat: "HTTP", code: 'http.content_type contains "xml"', desc: "XML content", sev: "i" },
  { cat: "HTTP", code: "http.content_length > 1000000", desc: "1MB+ response", sev: "w" },
  { cat: "HTTP", code: 'http.content_encoding == "gzip"', desc: "Gzip sıkıştırılmış", sev: "i" },
  { cat: "HTTP", code: 'http.server contains "BIG-IP"', desc: "F5 BIG-IP yanıtı", sev: "i" },
  { cat: "HTTP", code: 'http.server contains "nginx"', desc: "Nginx sunucu", sev: "i" },
  { cat: "HTTP", code: 'http.server contains "Apache"', desc: "Apache sunucu", sev: "i" },
  { cat: "HTTP", code: "http.location", desc: "Redirect Location", sev: "i" },
  { cat: "HTTP", code: "http.x_forwarded_for", desc: "X-Forwarded-For header", sev: "i" },
  { cat: "HTTP", code: "http.time > 1", desc: "1sn+ yanıt", sev: "w" },
  { cat: "HTTP", code: "http.time > 5", desc: "5sn+ yanıt", sev: "w" },
  { cat: "HTTP", code: "http.time > 10", desc: "10sn+ yanıt (kritik)", sev: "e" },
  { cat: "HTTP", code: "http.time > 30", desc: "30sn+ yanıt", sev: "e" },
  { cat: "HTTP", code: 'http.connection == "close"', desc: "Connection close", sev: "w" },
  { cat: "HTTP", code: 'http.connection == "keep-alive"', desc: "Keep-alive", sev: "i" },

  // ═════════════════════ HTTP/2 ═════════════════════
  { cat: "HTTP/2", code: "http2", desc: "Tüm HTTP/2", sev: "i" },
  { cat: "HTTP/2", code: "http2.type == 0", desc: "DATA frame", sev: "i" },
  { cat: "HTTP/2", code: "http2.type == 1", desc: "HEADERS frame", sev: "i" },
  { cat: "HTTP/2", code: "http2.type == 3", desc: "RST_STREAM", sev: "w" },
  { cat: "HTTP/2", code: "http2.type == 4", desc: "SETTINGS frame", sev: "i" },
  { cat: "HTTP/2", code: "http2.type == 6", desc: "PING frame", sev: "i" },
  { cat: "HTTP/2", code: "http2.type == 7", desc: "GOAWAY (kapanıyor)", sev: "w" },
  { cat: "HTTP/2", code: "http2.type == 8", desc: "WINDOW_UPDATE", sev: "i" },
  { cat: "HTTP/2", code: 'http2.headers.method == "GET"', desc: "HTTP/2 GET", sev: "i" },
  { cat: "HTTP/2", code: 'http2.headers.method == "POST"', desc: "HTTP/2 POST", sev: "i" },
  { cat: "HTTP/2", code: 'http2.headers.path contains "/api"', desc: "HTTP/2 API path", sev: "i" },
  { cat: "HTTP/2", code: 'http2.headers.status == "200"', desc: "HTTP/2 200 OK", sev: "ok" },
  { cat: "HTTP/2", code: 'http2.headers.status >= "400"', desc: "HTTP/2 4xx/5xx", sev: "w" },
  { cat: "HTTP/2", code: 'http2.headers.status >= "500"', desc: "HTTP/2 5xx", sev: "e" },
  { cat: "HTTP/2", code: "http2.streamid == 1", desc: "İlk stream", sev: "i" },
  { cat: "HTTP/2", code: "http2.flags.end_stream == 1", desc: "Stream sonu", sev: "i" },

  // ═════════════════════ DNS ═════════════════════
  { cat: "DNS", code: "dns", desc: "Tüm DNS", sev: "i" },
  { cat: "DNS", code: "dns.flags.response == 0", desc: "DNS sorguları", sev: "i" },
  { cat: "DNS", code: "dns.flags.response == 1", desc: "DNS yanıtları", sev: "i" },
  { cat: "DNS", code: "dns.flags.rcode == 0", desc: "NOERROR", sev: "ok" },
  { cat: "DNS", code: "dns.flags.rcode != 0", desc: "Tüm DNS hataları", sev: "w" },
  { cat: "DNS", code: "dns.flags.rcode == 1", desc: "FORMERR", sev: "w" },
  { cat: "DNS", code: "dns.flags.rcode == 2", desc: "SERVFAIL", sev: "e" },
  { cat: "DNS", code: "dns.flags.rcode == 3", desc: "NXDOMAIN", sev: "w" },
  { cat: "DNS", code: "dns.flags.rcode == 5", desc: "REFUSED", sev: "w" },
  { cat: "DNS", code: "dns.flags.truncated == 1", desc: "Truncated (TCP fallback)", sev: "w" },
  { cat: "DNS", code: "dns.flags.authoritative == 1", desc: "Authoritative yanıt", sev: "i" },
  { cat: "DNS", code: "dns.qry.type == 1", desc: "A (IPv4)", sev: "i" },
  { cat: "DNS", code: "dns.qry.type == 28", desc: "AAAA (IPv6)", sev: "i" },
  { cat: "DNS", code: "dns.qry.type == 5", desc: "CNAME", sev: "i" },
  { cat: "DNS", code: "dns.qry.type == 15", desc: "MX (email)", sev: "i" },
  { cat: "DNS", code: "dns.qry.type == 16", desc: "TXT (SPF/DKIM)", sev: "i" },
  { cat: "DNS", code: "dns.qry.type == 2", desc: "NS", sev: "i" },
  { cat: "DNS", code: "dns.qry.type == 33", desc: "SRV", sev: "i" },
  { cat: "DNS", code: "dns.qry.type == 12", desc: "PTR (reverse)", sev: "i" },
  { cat: "DNS", code: "dns.qry.type == 252", desc: "AXFR (zone transfer)", sev: "w" },
  { cat: "DNS", code: "dns.qry.name", desc: "Sorgulanan domain", sev: "i" },
  { cat: "DNS", code: 'dns.qry.name contains "bank"', desc: "'bank' geçen sorgular", sev: "i" },
  { cat: "DNS", code: "dns.resp.ttl < 60", desc: "Çok kısa TTL", sev: "w" },
  { cat: "DNS", code: "dns.count.answers == 0 && dns.flags.response == 1", desc: "Boş yanıt", sev: "w" },
  { cat: "DNS", code: "dns.time > 1", desc: "1sn+ DNS yanıt", sev: "w" },

  // ═════════════════════ DHCP ═════════════════════
  { cat: "DHCP", code: "dhcp", desc: "Tüm DHCP", sev: "i" },
  { cat: "DHCP", code: "dhcp.option.dhcp == 1", desc: "Discover", sev: "i" },
  { cat: "DHCP", code: "dhcp.option.dhcp == 2", desc: "Offer", sev: "i" },
  { cat: "DHCP", code: "dhcp.option.dhcp == 3", desc: "Request", sev: "i" },
  { cat: "DHCP", code: "dhcp.option.dhcp == 4", desc: "Decline", sev: "w" },
  { cat: "DHCP", code: "dhcp.option.dhcp == 5", desc: "ACK (lease verildi)", sev: "ok" },
  { cat: "DHCP", code: "dhcp.option.dhcp == 6", desc: "NACK (reddedildi)", sev: "e" },
  { cat: "DHCP", code: "dhcp.option.dhcp == 7", desc: "Release", sev: "i" },
  { cat: "DHCP", code: "dhcp.option.dhcp == 8", desc: "Inform", sev: "i" },
  { cat: "DHCP", code: "dhcp.option.hostname", desc: "Client hostname", sev: "i" },

  // ═════════════════════ SIP ═════════════════════
  { cat: "SIP", code: "sip", desc: "Tüm SIP", sev: "i" },
  { cat: "SIP", code: "sip or rtp or rtcp", desc: "Tüm VoIP", sev: "i" },
  { cat: "SIP", code: 'sip.Method == "INVITE"', desc: "Arama başlatma", sev: "i" },
  { cat: "SIP", code: 'sip.Method == "ACK"', desc: "INVITE onayı", sev: "i" },
  { cat: "SIP", code: 'sip.Method == "BYE"', desc: "Arama kapanması", sev: "i" },
  { cat: "SIP", code: 'sip.Method == "CANCEL"', desc: "Arama iptali", sev: "i" },
  { cat: "SIP", code: 'sip.Method == "REGISTER"', desc: "SIP kayıt", sev: "i" },
  { cat: "SIP", code: 'sip.Method == "OPTIONS"', desc: "Durum/keepalive", sev: "i" },
  { cat: "SIP", code: 'sip.Method == "REFER"', desc: "Transfer", sev: "i" },
  { cat: "SIP", code: 'sip.Method == "NOTIFY"', desc: "Bildirim", sev: "i" },
  { cat: "SIP", code: 'sip.Method == "SUBSCRIBE"', desc: "Abonelik", sev: "i" },
  { cat: "SIP", code: "sip.Status-Code == 100", desc: "100 Trying", sev: "i" },
  { cat: "SIP", code: "sip.Status-Code == 180", desc: "180 Ringing", sev: "i" },
  { cat: "SIP", code: "sip.Status-Code == 183", desc: "183 Session Progress", sev: "i" },
  { cat: "SIP", code: "sip.Status-Code == 200", desc: "200 OK", sev: "ok" },
  { cat: "SIP", code: "sip.Status-Code >= 300 && sip.Status-Code < 400", desc: "3xx redirect", sev: "i" },
  { cat: "SIP", code: "sip.Status-Code >= 400", desc: "Tüm SIP hataları", sev: "e" },
  { cat: "SIP", code: "sip.Status-Code == 401", desc: "Unauthorized", sev: "w" },
  { cat: "SIP", code: "sip.Status-Code == 403", desc: "Forbidden", sev: "e" },
  { cat: "SIP", code: "sip.Status-Code == 404", desc: "Not Found", sev: "w" },
  { cat: "SIP", code: "sip.Status-Code == 407", desc: "Proxy Auth Required", sev: "w" },
  { cat: "SIP", code: "sip.Status-Code == 408", desc: "Request Timeout", sev: "e" },
  { cat: "SIP", code: "sip.Status-Code == 480", desc: "Temporarily Unavailable", sev: "w" },
  { cat: "SIP", code: "sip.Status-Code == 481", desc: "Call Leg Does Not Exist", sev: "e" },
  { cat: "SIP", code: "sip.Status-Code == 486", desc: "Busy Here", sev: "i" },
  { cat: "SIP", code: "sip.Status-Code == 487", desc: "Request Terminated", sev: "i" },
  { cat: "SIP", code: "sip.Status-Code == 488", desc: "Not Acceptable (codec)", sev: "e" },
  { cat: "SIP", code: "sip.Status-Code == 500", desc: "Server Internal Error", sev: "e" },
  { cat: "SIP", code: "sip.Status-Code == 503", desc: "Service Unavailable", sev: "e" },
  { cat: "SIP", code: "sip.Status-Code == 603", desc: "Decline", sev: "i" },
  { cat: "SIP", code: "sip.From.user", desc: "SIP From kullanıcı", sev: "i" },
  { cat: "SIP", code: "sip.To.user", desc: "SIP To kullanıcı", sev: "i" },
  { cat: "SIP", code: "sip.Call-ID", desc: "Call-ID", sev: "i" },
  { cat: "SIP", code: "sip.CSeq.seq", desc: "CSeq numarası", sev: "i" },
  { cat: "SIP", code: "sip.Via", desc: "Via header (proxy)", sev: "i" },
  { cat: "SIP", code: "sdp", desc: "SDP içeriği", sev: "i" },
  { cat: "SIP", code: "sdp.media", desc: "SDP m= satırı", sev: "i" },
  { cat: "SIP", code: "sdp.connection_info", desc: "SDP c= satırı (IP)", sev: "i" },

  // ═════════════════════ RTP / RTCP ═════════════════════
  { cat: "RTP", code: "rtp", desc: "Tüm RTP medya", sev: "i" },
  { cat: "RTP", code: "rtp.ssrc", desc: "RTP SSRC", sev: "i" },
  { cat: "RTP", code: "rtp.p_type == 0", desc: "G.711 mu-law (PCMU)", sev: "i" },
  { cat: "RTP", code: "rtp.p_type == 8", desc: "G.711 A-law (PCMA)", sev: "i" },
  { cat: "RTP", code: "rtp.p_type == 9", desc: "G.722", sev: "i" },
  { cat: "RTP", code: "rtp.p_type == 18", desc: "G.729", sev: "i" },
  { cat: "RTP", code: "rtp.p_type == 111", desc: "OPUS", sev: "i" },
  { cat: "RTP", code: "rtp.p_type >= 96", desc: "Dynamic payload type", sev: "i" },
  { cat: "RTP", code: "rtp.seq", desc: "RTP sequence", sev: "i" },
  { cat: "RTP", code: "rtp.timestamp", desc: "RTP timestamp", sev: "i" },
  { cat: "RTP", code: "rtp.marker == 1", desc: "Marker bit (frame start)", sev: "i" },
  { cat: "RTP", code: "rtcp", desc: "Tüm RTCP", sev: "i" },
  { cat: "RTP", code: "rtcp.pt == 200", desc: "Sender Report", sev: "i" },
  { cat: "RTP", code: "rtcp.pt == 201", desc: "Receiver Report", sev: "i" },
  { cat: "RTP", code: "rtcp.pt == 202", desc: "Source Description", sev: "i" },
  { cat: "RTP", code: "rtcp.pt == 203", desc: "BYE", sev: "i" },

  // ═════════════════════ TIMEOUT / SÜRE ═════════════════════
  { cat: "Timeout", code: "frame.time_delta > 1", desc: "1sn+ boşluk", sev: "w" },
  { cat: "Timeout", code: "frame.time_delta > 5", desc: "5sn+ boşluk", sev: "w" },
  { cat: "Timeout", code: "frame.time_delta > 30", desc: "30sn+ boşluk", sev: "e" },
  { cat: "Timeout", code: "frame.time_delta > 60", desc: "60sn+ boşluk (timeout?)", sev: "e" },
  { cat: "Timeout", code: "tcp.time_delta > 5", desc: "TCP 5sn+ sessizlik", sev: "w" },
  { cat: "Timeout", code: "tcp.time_delta > 30", desc: "TCP 30sn+ sessizlik", sev: "e" },
  { cat: "Timeout", code: "tcp.time_delta > 60", desc: "TCP 60sn+ (idle)", sev: "e" },
  { cat: "Timeout", code: "tcp.time_delta > 120", desc: "TCP 2dk+ sessizlik", sev: "e" },
  { cat: "Timeout", code: "http.time > 1", desc: "HTTP 1sn+ yanıt", sev: "w" },
  { cat: "Timeout", code: "http.time > 5", desc: "HTTP 5sn+ yanıt", sev: "w" },
  { cat: "Timeout", code: "http.time > 10", desc: "HTTP 10sn+ yanıt", sev: "e" },
  { cat: "Timeout", code: "http.time > 30", desc: "HTTP 30sn+ (kritik)", sev: "e" },
  { cat: "Timeout", code: "dns.time > 1", desc: "DNS 1sn+ yanıt", sev: "w" },
  { cat: "Timeout", code: "dns.time > 5", desc: "DNS 5sn+ yanıt", sev: "e" },
  { cat: "Timeout", code: "tcp.analysis.ack_rtt > 0.1", desc: "ACK 100ms+ geç", sev: "w" },
  { cat: "Timeout", code: "tcp.analysis.ack_rtt > 0.5", desc: "ACK 500ms+ geç", sev: "e" },
  { cat: "Timeout", code: 'frame.time > "2024-01-15 10:00:00"', desc: "Belirli saatten sonra", sev: "i" },
  { cat: "Timeout", code: 'frame.time < "2024-01-15 11:00:00"', desc: "Belirli saatten önce", sev: "i" },
  { cat: "Timeout", code: "frame.time_relative > 60", desc: "Capture başlangıcından 60sn sonra", sev: "i" },

  // ═════════════════════ F5 ÖZEL ═════════════════════
  { cat: "F5", code: "tcp.flags.reset == 1", desc: "Tüm RST (kaynağa bak)", sev: "e" },
  { cat: "F5", code: "tcp.flags.reset == 1 && ip.src == 10.0.0.1", desc: "F5 self IP'den RST", sev: "e" },
  { cat: "F5", code: "tcp.analysis.keep_alive", desc: "F5 idle probe", sev: "i" },
  { cat: "F5", code: 'http.server contains "BIG-IP"', desc: "F5 yanıtı", sev: "i" },
  { cat: "F5", code: "http.response.code == 503", desc: "Pool down (F5)", sev: "e" },
  { cat: "F5", code: "http.response.code == 504", desc: "Backend timeout (F5)", sev: "e" },
  { cat: "F5", code: "http.response.code == 400", desc: "Bad Request (F5)", sev: "w" },
  { cat: "F5", code: "tcp.time_delta > 60", desc: "Idle timeout şüphesi", sev: "e" },
  { cat: "F5", code: "f5ethtrailer", desc: "F5 ethernet trailer", sev: "i" },
  { cat: "F5", code: "f5ethtrailer.tls.keylog", desc: "F5 sslprovider key log", sev: "i" },
  { cat: "F5", code: "f5ethtrailer.low.rstcause", desc: "F5 RST cause kodu", sev: "i" },
  { cat: "F5", code: "f5ethtrailer.slot", desc: "F5 slot (cluster)", sev: "i" },
  { cat: "F5", code: "f5ethtrailer.tmm", desc: "F5 TMM ID", sev: "i" },
  { cat: "F5", code: "f5ethtrailer.low.flowid", desc: "F5 flow ID", sev: "i" },

  // ═════════════════════ ROUTING ═════════════════════
  { cat: "Routing", code: "bgp", desc: "BGP protokolü", sev: "i" },
  { cat: "Routing", code: "bgp.type == 1", desc: "BGP Open", sev: "i" },
  { cat: "Routing", code: "bgp.type == 2", desc: "BGP Update", sev: "i" },
  { cat: "Routing", code: "bgp.type == 3", desc: "BGP Notification (hata)", sev: "e" },
  { cat: "Routing", code: "bgp.type == 4", desc: "BGP Keepalive", sev: "i" },
  { cat: "Routing", code: "ospf", desc: "OSPF", sev: "i" },
  { cat: "Routing", code: "ospf.msg == 1", desc: "OSPF Hello", sev: "i" },
  { cat: "Routing", code: "ospf.msg == 4", desc: "OSPF LSU", sev: "i" },
  { cat: "Routing", code: "eigrp", desc: "EIGRP", sev: "i" },
  { cat: "Routing", code: "eigrp.opcode == 5", desc: "EIGRP Hello", sev: "i" },
  { cat: "Routing", code: "rip", desc: "RIP", sev: "i" },
  { cat: "Routing", code: "vrrp", desc: "VRRP", sev: "i" },
  { cat: "Routing", code: "hsrp", desc: "HSRP (Cisco)", sev: "i" },
  { cat: "Routing", code: "glbp", desc: "GLBP (Cisco)", sev: "i" },

  // ═════════════════════ VLAN / MPLS ═════════════════════
  { cat: "VLAN/MPLS", code: "vlan", desc: "802.1Q VLAN", sev: "i" },
  { cat: "VLAN/MPLS", code: "vlan.id == 10", desc: "Belirli VLAN ID", sev: "i" },
  { cat: "VLAN/MPLS", code: "vlan.id != 0", desc: "Tagged paketler", sev: "i" },
  { cat: "VLAN/MPLS", code: "vlan.priority == 5", desc: "VLAN priority 5 (voice)", sev: "i" },
  { cat: "VLAN/MPLS", code: "mpls", desc: "MPLS paketler", sev: "i" },
  { cat: "VLAN/MPLS", code: "mpls.label", desc: "MPLS label", sev: "i" },
  { cat: "VLAN/MPLS", code: "mpls.exp", desc: "MPLS EXP (QoS)", sev: "i" },
  { cat: "VLAN/MPLS", code: "cdp", desc: "Cisco Discovery Protocol", sev: "i" },
  { cat: "VLAN/MPLS", code: "lldp", desc: "LLDP", sev: "i" },
  { cat: "VLAN/MPLS", code: "stp", desc: "Spanning Tree", sev: "i" },
  { cat: "VLAN/MPLS", code: "stp.flags.tc == 1", desc: "STP Topology Change", sev: "w" },

  // ═════════════════════ SERVİSLER ═════════════════════
  { cat: "Servisler", code: "ssh", desc: "SSH trafiği (22)", sev: "i" },
  { cat: "Servisler", code: "ssh.message_code", desc: "SSH handshake mesajları", sev: "i" },
  { cat: "Servisler", code: "ssh.protocol", desc: "SSH protocol version", sev: "i" },
  { cat: "Servisler", code: "snmp", desc: "SNMP (161/162)", sev: "i" },
  { cat: "Servisler", code: "snmp.version == 0", desc: "SNMPv1 (güvensiz)", sev: "w" },
  { cat: "Servisler", code: "snmp.version == 3", desc: "SNMPv3 (güvenli)", sev: "i" },
  { cat: "Servisler", code: "ntp", desc: "NTP (123)", sev: "i" },
  { cat: "Servisler", code: "ntp.flags.mode == 3", desc: "NTP client request", sev: "i" },
  { cat: "Servisler", code: "ntp.flags.mode == 4", desc: "NTP server response", sev: "i" },
  { cat: "Servisler", code: "ftp", desc: "FTP control (21)", sev: "i" },
  { cat: "Servisler", code: "ftp.request.command", desc: "FTP komutları", sev: "i" },
  { cat: "Servisler", code: 'ftp.request.command == "USER"', desc: "FTP username", sev: "i" },
  { cat: "Servisler", code: 'ftp.request.command == "PASS"', desc: "FTP password (düz metin!)", sev: "e" },
  { cat: "Servisler", code: "ftp.response.code >= 400", desc: "FTP hataları", sev: "w" },
  { cat: "Servisler", code: "ftp-data", desc: "FTP data transferi (20)", sev: "i" },
  { cat: "Servisler", code: "smb", desc: "SMB (SMBv1)", sev: "i" },
  { cat: "Servisler", code: "smb2", desc: "SMBv2/3", sev: "i" },
  { cat: "Servisler", code: "smb.cmd", desc: "SMB komutları", sev: "i" },
  { cat: "Servisler", code: "smb2.cmd", desc: "SMB2 komutları", sev: "i" },
  { cat: "Servisler", code: "nfs", desc: "NFS", sev: "i" },
  { cat: "Servisler", code: "nfs.status != 0", desc: "NFS hataları", sev: "w" },
  { cat: "Servisler", code: "smtp", desc: "SMTP (25/587)", sev: "i" },
  { cat: "Servisler", code: "smtp.req.command", desc: "SMTP komutları", sev: "i" },
  { cat: "Servisler", code: "smtp.response.code >= 400", desc: "SMTP hataları", sev: "w" },
  { cat: "Servisler", code: "pop", desc: "POP3 (110)", sev: "i" },
  { cat: "Servisler", code: "imap", desc: "IMAP (143/993)", sev: "i" },
  { cat: "Servisler", code: "ldap", desc: "LDAP (389)", sev: "i" },
  { cat: "Servisler", code: "ldap.resultCode != 0", desc: "LDAP hataları", sev: "w" },
  { cat: "Servisler", code: "kerberos", desc: "Kerberos (88)", sev: "i" },
  { cat: "Servisler", code: "kerberos.error_code", desc: "Kerberos hataları", sev: "w" },
  { cat: "Servisler", code: "radius", desc: "RADIUS (1812/1813)", sev: "i" },
  { cat: "Servisler", code: "radius.code == 3", desc: "RADIUS Access-Reject", sev: "e" },
  { cat: "Servisler", code: "syslog", desc: "Syslog (514)", sev: "i" },

  // ═════════════════════ EXPERT ═════════════════════
  { cat: "Expert", code: "expert", desc: "Tüm tespitler", sev: "i" },
  { cat: "Expert", code: 'expert.severity == "Error"', desc: "Error seviyesi", sev: "e" },
  { cat: "Expert", code: 'expert.severity == "Warning"', desc: "Warning", sev: "w" },
  { cat: "Expert", code: 'expert.severity == "Note"', desc: "Bilgi notları", sev: "i" },
  { cat: "Expert", code: 'expert.severity == "Chat"', desc: "Normal akış", sev: "i" },
  { cat: "Expert", code: 'expert.group == "Malformed"', desc: "Malformed paket", sev: "e" },
  { cat: "Expert", code: 'expert.group == "Protocol"', desc: "Protocol ihlali", sev: "w" },
  { cat: "Expert", code: 'expert.group == "Sequence"', desc: "Sequence anomalisi", sev: "w" },
  { cat: "Expert", code: 'expert.group == "Assumption"', desc: "Dissector varsayımı", sev: "i" },
  { cat: "Expert", code: 'expert.group == "Deprecated"', desc: "Deprecated kullanım", sev: "w" },

  // ═════════════════════ GENEL ═════════════════════
  { cat: "Genel", code: "frame.number", desc: "Paket numarası", sev: "i" },
  { cat: "Genel", code: "frame.number == 100", desc: "Belirli paket", sev: "i" },
  { cat: "Genel", code: "frame.number >= 100 && frame.number <= 200", desc: "Paket aralığı", sev: "i" },
  { cat: "Genel", code: "frame.len > 1500", desc: "MTU üstü (jumbo)", sev: "i" },
  { cat: "Genel", code: "frame.len > 1400", desc: "MTU sınırına yakın", sev: "i" },
  { cat: "Genel", code: "frame.len < 100", desc: "Küçük paketler", sev: "i" },
  { cat: "Genel", code: "frame.len < 64", desc: "Kısa Ethernet (illegal)", sev: "w" },
  { cat: "Genel", code: "frame.cap_len != frame.len", desc: "Kısaltılmış capture", sev: "w" },
  { cat: "Genel", code: "frame.protocols", desc: "Protokol yığını", sev: "i" },
  { cat: "Genel", code: 'frame.protocols contains "tls"', desc: "TLS içeren", sev: "i" },
  { cat: "Genel", code: "frame.coloring_rule.name", desc: "Renk kuralıyla eşleşen", sev: "i" },
  { cat: "Genel", code: "frame.interface_id == 0", desc: "İlk interface", sev: "i" },
  { cat: "Genel", code: "_ws.col.info contains \"reset\"", desc: "Info kolonunda arama", sev: "i" },
  { cat: "Genel", code: "!(arp or stp or lldp or cdp)", desc: "Gürültüsüz (L2 ctrl hariç)", sev: "i" },
  { cat: "Genel", code: "!(arp or icmp or dns)", desc: "Gürültü temizle", sev: "i" },
  { cat: "Genel", code: "tcp || udp", desc: "Sadece L4", sev: "i" },
  { cat: "Genel", code: "not broadcast && not multicast", desc: "Unicast", sev: "i" },
  { cat: "Genel", code: "http || http2 || tls", desc: "Tüm web trafiği", sev: "i" },

  // ═════════════════════ GÜVENLİK ═════════════════════
  { cat: "Güvenlik", code: "tcp.flags == 0x000", desc: "NULL scan", sev: "e" },
  { cat: "Güvenlik", code: "tcp.flags == 0x029", desc: "XMAS scan", sev: "e" },
  { cat: "Güvenlik", code: "tcp.flags.syn == 1 && tcp.window_size_value <= 1024", desc: "SYN scan şüphesi", sev: "w" },
  { cat: "Güvenlik", code: "tcp.flags.syn == 1 && tcp.flags.fin == 1", desc: "SYN+FIN (illegal)", sev: "e" },
  { cat: "Güvenlik", code: "tcp.flags.syn == 1 && tcp.flags.rst == 1", desc: "SYN+RST (illegal)", sev: "e" },
  { cat: "Güvenlik", code: "dns.qry.name.len > 50", desc: "Uzun DNS query (exfil?)", sev: "w" },
  { cat: "Güvenlik", code: 'dns.qry.name matches "[0-9a-f]{32}"', desc: "DNS'te hex string (tunnel?)", sev: "w" },
  { cat: "Güvenlik", code: "dns.qry.type == 16 && frame.len > 512", desc: "Büyük TXT query (C2?)", sev: "w" },
  { cat: "Güvenlik", code: 'http.request.uri contains "../"', desc: "Path traversal", sev: "e" },
  { cat: "Güvenlik", code: 'http.request.uri contains "etc/passwd"', desc: "LFI denemesi", sev: "e" },
  { cat: "Güvenlik", code: 'http.request.uri contains "cmd.exe"', desc: "Windows command injection", sev: "e" },
  { cat: "Güvenlik", code: 'http.request.uri contains "<script"', desc: "XSS denemesi", sev: "e" },
  { cat: "Güvenlik", code: 'http.request.uri matches "(union|select).*from"', desc: "SQLi şüphesi", sev: "e" },
  { cat: "Güvenlik", code: 'http.user_agent contains "sqlmap"', desc: "SQLmap aracı", sev: "e" },
  { cat: "Güvenlik", code: 'http.user_agent contains "nikto"', desc: "Nikto tarayıcı", sev: "e" },
  { cat: "Güvenlik", code: 'http.user_agent contains "nmap"', desc: "Nmap", sev: "w" },
  { cat: "Güvenlik", code: 'http.user_agent contains "masscan"', desc: "Masscan", sev: "w" },
  { cat: "Güvenlik", code: "ja3.hash", desc: "JA3 parmak izi", sev: "i" },
  { cat: "Güvenlik", code: "ja4", desc: "JA4 parmak izi", sev: "i" },
  { cat: "Güvenlik", code: "tls.handshake.version == 0x0301", desc: "TLS 1.0 (zayıf)", sev: "e" },
  { cat: "Güvenlik", code: "arp.duplicate-address-detected", desc: "ARP spoofing şüphesi", sev: "e" },
  { cat: "Güvenlik", code: "icmp.type == 5", desc: "ICMP Redirect (spoof?)", sev: "w" },
  { cat: "Güvenlik", code: "dns.flags.rcode == 3 && dns.count.answers == 0", desc: "NXDOMAIN (DGA?)", sev: "w" }
];

/* ───────── DATA: SCENARIOS ───────── */
const SCENARIOS = [
  {
    id: "timeout-60s",
    title: "60sn+ Timeout — API Donuyor",
    badge: "KRİTİK",
    badgeType: "err",
    symptom: "Client istek gönderdi, yanıt 60 saniyeden uzun sürüyor veya gelmiyor.",
    filters: [
      { code: "tcp.time_delta > 60", desc: "60sn'lik sessizlik paketlerini bul", sev: "e" },
      { code: "tcp.flags.reset == 1", desc: "RST paketi var mı?", sev: "e" },
      { code: "tcp.flags.reset == 1 && ip.src == <F5_IP>", desc: "F5 mi kesiyor?", sev: "e" },
      { code: "tcp.analysis.zero_window", desc: "Backend tampon dolu mu?", sev: "e" },
      { code: "tcp.analysis.retransmission", desc: "Paket kaybı var mı?", sev: "w" },
      { code: "http.response.code == 504", desc: "F5 gateway timeout verdi mi?", sev: "e" },
      { code: "http.response.code == 503", desc: "Pool down mu?", sev: "e" }
    ],
    rootCauses: [
      { finding: "RST F5 self IP'den + HTTP 504", cause: "F5 server-timeout aşıldı", action: "tmsh modify ltm virtual <vs> → connect-timeout/server-timeout ayarla" },
      { finding: "RST F5 self IP'den + HTTP yok", cause: "F5 idle timeout", action: "tmsh modify ltm virtual <vs> idle-timeout 300" },
      { finding: "RST Backend IP'den", cause: "Backend uygulama socket kapatmıyor", action: "App ekibine eskalasyon" },
      { finding: "Zero Window + HTTP 504", cause: "Backend tampon dolu, yavaş işleme", action: "Backend kapasite artırımı" },
      { finding: "HTTP 503", cause: "Pool member down", action: "F5 health monitor kontrol et" }
    ]
  },
  {
    id: "tls-handshake",
    title: "HTTPS/TLS Bağlantı Kurulamıyor",
    badge: "YÜKSEK",
    badgeType: "err",
    symptom: "SSL/TLS handshake başlıyor ama tamamlanamıyor. Connection refused veya timeout.",
    filters: [
      { code: "tls.alert_message", desc: "İlk bakılacak — TLS hata mesajı", sev: "e" },
      { code: "tls.handshake.type == 1", desc: "Client Hello — cipher listesi", sev: "i" },
      { code: "tls.handshake.type == 2", desc: "Server Hello geldi mi?", sev: "i" },
      { code: "tls.handshake.type == 11", desc: "Certificate gönderildi mi?", sev: "i" },
      { code: "tls.handshake.type == 21", desc: "Alert — handshake failed", sev: "e" }
    ],
    rootCauses: [
      { finding: "Client Hello sonrası Server Hello YOK", cause: "Cipher uyumsuz veya TLS versiyon desteksiz", action: "F5 cipher profilini kontrol et (tls 1.3 açık mı?)" },
      { finding: "Alert 40 (handshake_failure)", cause: "Cipher/protocol uyumsuz", action: "Client ve F5 cipher listelerini karşılaştır" },
      { finding: "Alert 42 (bad_certificate)", cause: "Sertifika geçersiz", action: "F5 sertifika zincirini kontrol et" },
      { finding: "Alert 45 (certificate_expired)", cause: "Sertifika süresi dolmuş", action: "Sertifikayı yenile" },
      { finding: "Alert 46 (certificate_unknown)", cause: "Client CA'yı güvenmiyor", action: "Intermediate CA sertifikasını client'a dağıt" },
      { finding: "Alert 48 (unknown_ca)", cause: "Client CA'yı tanımıyor", action: "Root CA sertifikasını client'a yükle" }
    ]
  },
  {
    id: "sip-trunk",
    title: "SIP Trunk — Arama Kurulmuyor",
    badge: "YÜKSEK",
    badgeType: "warn",
    symptom: "SIP INVITE gönderiliyor ama çağrı kurulmuyor veya ses gelmiyor.",
    filters: [
      { code: "sip", desc: "SIP trafiği var mı?", sev: "i" },
      { code: "sip.Status-Code >= 400", desc: "SIP hataları", sev: "e" },
      { code: "sip.Status-Code == 401", desc: "Credential sorunu", sev: "w" },
      { code: "sip.Status-Code == 403", desc: "IP yasaklı mı?", sev: "e" },
      { code: "sip.Status-Code == 503", desc: "SIP server aşırı yüklü", sev: "e" },
      { code: "sdp", desc: "SDP IP adresi (NAT sorunu?)", sev: "i" },
      { code: "rtp", desc: "Ses paketleri geliyor mu?", sev: "i" }
    ],
    rootCauses: [
      { finding: "401 Unauthorized → tekrar INVITE", cause: "Normal auth akışı", action: "Beklenen davranış, devam" },
      { finding: "403 Forbidden", cause: "IP yasaklı (F5/FW access list)", action: "SIP peer IP listesini kontrol et" },
      { finding: "404 Not Found", cause: "Dial plan yanlış", action: "Yönlendirme/routing kontrol" },
      { finding: "503 Service Unavailable", cause: "SIP server aşırı yüklü", action: "Kapasite artırımı" },
      { finding: "Çağrı kuruldu ama ses yok", cause: "SDP'de private IP → NAT", action: "SIP ALG / SNAT kontrol" },
      { finding: "Tek yönlü ses", cause: "RTP port range routing", action: "UDP 10000-20000 firewall kontrolü" }
    ]
  },
  {
    id: "http2-api",
    title: "HTTP/2 API Performans Sorunu",
    badge: "ORTA",
    badgeType: "warn",
    symptom: "API çağrıları yavaş, zaman zaman 500 hatası alıyor.",
    filters: [
      { code: "http2", desc: "TLS deşifre edildiyse HTTP/2 trafik", sev: "i" },
      { code: 'http2.headers.status >= "500"', desc: "Sunucu hataları", sev: "e" },
      { code: 'http2.headers.status == "503"', desc: "Service Unavailable", sev: "e" },
      { code: "frame.time_delta > 1.0", desc: "1sn+ aralıklar", sev: "w" },
      { code: 'http2.headers.path contains "/api/payment"', desc: "Ödeme API'leri", sev: "i" }
    ],
    rootCauses: [
      { finding: "Belirli endpoint'te 500 yoğunluğu", cause: "Backend servis arıza", action: "App ekibi + log korelasyonu" },
      { finding: "Saat X'te 503 spike", cause: "Kapasite dolması / cron job", action: "Saat korelasyonu + monitoring" },
      { finding: "Tutarlı yavaş yanıt", cause: "DB sorgu performansı", action: "Backend DB analizi" },
      { finding: "Zaman zaman timeout", cause: "Pool member sağlıksız", action: "F5 health monitor çekimi" }
    ]
  },
  {
    id: "tcp-perf",
    title: "TCP Performans — Yavaş Transfer",
    badge: "ORTA",
    badgeType: "warn",
    symptom: "Bağlantı kuruldu ama veri transferi beklenenden yavaş.",
    filters: [
      { code: "tcp.analysis.flags && !tcp.analysis.window_update", desc: "Tüm TCP sorunları", sev: "e" },
      { code: "tcp.analysis.retransmission", desc: "Paket kaybı", sev: "w" },
      { code: "tcp.analysis.zero_window", desc: "Buffer doldu", sev: "e" },
      { code: "tcp.analysis.duplicate_ack", desc: "Kayıp sinyali", sev: "w" },
      { code: "tcp.window_size_value < 1000", desc: "Küçük window", sev: "w" }
    ],
    rootCauses: [
      { finding: "Yüksek retransmission (%3+)", cause: "Path'te paket kaybı", action: "Fiziksel/network ekibi" },
      { finding: "Zero Window sık görülüyor", cause: "Alıcı uygulama yavaş okuyor", action: "Backend app ekibi" },
      { finding: "RTT > 100ms", cause: "Fiziksel gecikme / congestion", action: "Path analizi, MPLS kontrolü" },
      { finding: "Küçük window + düz time-seq", cause: "Throughput darboğazı", action: "TCP window scaling kontrol" }
    ]
  }
];

/* ───────── DATA: F5 PCAP & TLS ───────── */
const F5_COMMANDS = [
  { title: "Genel Capture", cmd: "tcpdump -i 0.0:nnnp -nn -s 0 -w /var/tmp/cap.pcap" },
  { title: "Belirli Client", cmd: "tcpdump -i 0.0:nnnp -nn -s 0 host 10.0.0.1 -w /var/tmp/cap.pcap" },
  { title: "HTTPS Portu", cmd: "tcpdump -i 0.0:nnnp -nn -s 0 port 443 -w /var/tmp/cap.pcap" },
  { title: "Ring Buffer (3×50MB)", cmd: "tcpdump -i 0.0:nnnp -nn -s 0 -C 50 -W 3 -w /var/tmp/cap.pcap" },
  { title: "Süre Sınırlı (5dk)", cmd: "tcpdump -i 0.0:nnnp -nn -s 0 -G 300 -w /var/tmp/cap.pcap" },
  { title: "SSH Pipe → Wireshark", cmd: "ssh root@f5 \"tcpdump -i 0.0:nnnp -s 0 -w - host 10.0.0.1\" | wireshark -k -i -" },
  { title: "PCAP İndir (SCP)", cmd: "scp root@f5:/var/tmp/cap.pcap ./" },
  { title: "PCAP Bilgisi", cmd: "capinfos cap.pcap" }
];

const TLS_METHODS = [
  {
    platform: "F5 BIG-IP",
    method: "sslprovider (v15+)",
    pros: "En temiz, iRule gereksiz, TLS 1.3 ✓",
    cons: "F5 v15+ gerekli",
    steps: [
      "tmsh modify sys db tcpdump.sslprovider value enable",
      "tcpdump -nni 0.0:nnnp -s0 --f5 ssl -vvv -w /var/tmp/decrypt.pcap host 10.0.0.1",
      "tmsh modify sys db tcpdump.sslprovider value disable",
      "tshark -r decrypt.pcap -Y \"f5ethtrailer.tls.keylog\" -T fields -e f5ethtrailer.tls.keylog | sed 's/,/\\n/g' > pre_master_log.pms",
      "Wireshark → Preferences → TLS → pre_master_log.pms"
    ]
  },
  {
    platform: "F5 BIG-IP",
    method: "iRule + LTM Log (v13+)",
    pros: "Tüm F5 versiyonlarda çalışır",
    cons: "iRule deploy gerekir, log hacmi dikkat",
    code: `when CLIENTSSL_HANDSHAKE {
    log local0. "CLIENT_RANDOM [SSL::clientrandom] [SSL::sessionsecret]"
}
when SERVERSSL_HANDSHAKE {
    log local0. "CLIENT_RANDOM [SSL::clientrandom] [SSL::sessionsecret]"
}`,
    steps: [
      "Yukarıdaki iRule'u LTM'e ekle",
      "Virtual server'a attach et",
      "grep \"CLIENT_RANDOM\" /var/log/ltm | sed 's/.*CLIENT_RANDOM /CLIENT_RANDOM /' > session.pms",
      "Wireshark → Preferences → TLS → session.pms"
    ]
  },
  {
    platform: "Client (Lab)",
    method: "SSLKEYLOGFILE",
    pros: "Kolay, browser native destek",
    cons: "Client erişimi şart, production'da güvenlik riski",
    steps: [
      "export SSLKEYLOGFILE=/tmp/tls-keys.log",
      "firefox veya google-chrome",
      "HTTPS sitesini ziyaret et → key dosyaya yazılır",
      "tcpdump ile PCAP al",
      "Wireshark → Preferences → TLS → tls-keys.log"
    ]
  }
];

/* ───────── DATA: FortiGate ───────── */
const FORTIGATE_COMMANDS = [
  { title: "GUI Packet Capture", cmd: "Network → Packet Capture → Create New → Interface + Filter → Start → Download" },
  { title: "CLI Sniffer (ekran)", cmd: "diagnose sniffer packet wan1 'host 10.0.0.1' 4 100 l" },
  { title: "CLI Verbose (payload)", cmd: "diagnose sniffer packet wan1 'host 10.0.0.1 and port 443' 6 0 a" },
  { title: "Deep Inspection Kontrol", cmd: "config firewall policy → show → ssl-ssh-profile görünür mü?" }
];

const FG_TLS_STEPS = [
  "SSL Inspection profilini kontrol et: Security Profiles → SSL/SSH Inspection → deep-inspection aktif mi?",
  "FortiGate CA sertifikası client'lara dağıtılmış mı? (GPO/MDM)",
  "Policy'de SSL Inspection açık mı? Policy & Objects → Firewall Policy",
  "Network → Packet Capture → PCAP al (deşifreli gelir)",
  "Wireshark'ta aç → filter: http veya http2 (ek ayar gerekmez)"
];

/* ───────── DATA: Check Point ───────── */
const CP_COMMANDS = [
  { title: "fw monitor (temel)", cmd: "fw monitor -e \"accept host(10.0.0.1);\" -o /var/log/dump/cap.pcap" },
  { title: "fw monitor (4 nokta)", cmd: "fw monitor -e \"accept host(10.0.0.1) and port(443);\" -m iIoO -o /var/log/dump/cap.pcap" },
  { title: "tcpdump (Gaia)", cmd: "tcpdump -i eth1 -nn -s 0 host 10.0.0.1 -w /var/log/dump/cap.pcap" },
  { title: "cppcap (R81+)", cmd: "cppcap -i eth1 -f \"host 10.0.0.1 and port 443\" -w /var/log/dump/cap.pcap -c 10000" },
  { title: "Süre Sınırlı", cmd: "timeout 60 fw monitor -e \"accept host(10.0.0.1);\" -o /var/log/dump/cap.pcap" }
];

const CP_MONITOR_POINTS = [
  { pt: "i", name: "Pre-Inbound", use: "NAT öncesi, client orijinal IP'yi görmek için" },
  { pt: "I", name: "Post-Inbound", use: "Policy sonrası (drop'lar görünmez)" },
  { pt: "o", name: "Pre-Outbound", use: "Outbound NAT öncesi" },
  { pt: "O", name: "Post-Outbound", use: "Çıkan trafik, post-NAT" }
];

/* ───────── DATA: PROFILES ───────── */
const PROFILES = [
  { name: "amwalding/wireshark_profiles", desc: "En büyük koleksiyon. HTTP, DNS, IPv6, TCP SACK, WLAN, IEC 60870, RoCE profilleri", url: "https://github.com/amwalding/wireshark_profiles", tags: ["HTTP", "DNS", "TCP", "500K+ indirme"] },
  { name: "akamura/wireshark-profile", desc: "Network Warrior — GeoIP + ASN enrichment. Her IP için AS numarası ve organizasyon adı", url: "https://github.com/akamura/wireshark-profile", tags: ["GeoIP", "ASN", "MaxMind"] },
  { name: "networkforensic.dk", desc: "Security odaklı — JA3, RADIUS, MQTT, ICMP, iSCSI, DHCP, SMB, DDoS, IEC-104", url: "https://networkforensic.dk/Tools/default.html", tags: ["JA3", "Security", "SMB"] },
  { name: "sujit/wireshark_profiles", desc: "CellStream tabanlı kişisel özelleştirme — DNS, HTTP, TLS, BGP, OSPF, EIGRP", url: "https://github.com/sujit/wireshark_profiles", tags: ["Routing", "TLS"] },
  { name: "gaddman/wireshark-profiles", desc: "Günlük troubleshooting için minimal ve pratik profiller", url: "https://github.com/gaddman/wireshark-profiles", tags: ["Troubleshooting"] },
  { name: "bcbrookman/wireshark-profiles", desc: "Troubleshooting + protocol analiz koleksiyonu, temiz organizasyon", url: "https://github.com/bcbrookman/wireshark-profiles", tags: ["Protocol"] },
  { name: "DhaeyerWolf/ICS-OT", desc: "SCADA/OT — S7Comm, Profinet, Modbus, OPC-UA, BACnet, EtherNet/IP, DNP3", url: "https://github.com/DhaeyerWolf/ICS-OT_wireshark_profiles", tags: ["SCADA", "ICS", "OT"] }
];

const IMPORT_STEPS = [
  "GitHub Releases sayfasından ZIP dosyasını indir",
  "Wireshark'ı aç, alt sağ köşedeki 'Profile' yazısına sağ tık",
  "Import → From Zip File seç, indirdiğin ZIP'i göster",
  "Alt sağ köşeden yeni profili seç → renkler/kolonlar değişir"
];

/* ───────── DATA: CHEATSHEETS ───────── */
const CHEATSHEETS = [
  {
    id: "ports",
    name: "Yaygın Port Numaraları",
    icon: "🔌",
    desc: "Well-known ve yaygın kullanılan TCP/UDP portları",
    cols: ["Port", "Proto", "Servis", "Notlar"],
    rows: [
      ["20",    "TCP",    "FTP-DATA",       "FTP veri transferi"],
      ["21",    "TCP",    "FTP",            "FTP control channel"],
      ["22",    "TCP",    "SSH",            "Secure Shell, SFTP, SCP"],
      ["23",    "TCP",    "Telnet",         "Güvensiz — kullanma"],
      ["25",    "TCP",    "SMTP",           "Mail gönderme (düz)"],
      ["53",    "TCP/UDP","DNS",            "UDP yaygın, TCP zone transfer"],
      ["67/68", "UDP",    "DHCP",           "Server 67, Client 68"],
      ["69",    "UDP",    "TFTP",           "Trivial FTP (config backup)"],
      ["80",    "TCP",    "HTTP",           "Web (düz)"],
      ["88",    "TCP/UDP","Kerberos",       "Active Directory auth"],
      ["110",   "TCP",    "POP3",           "Mail alma (eski)"],
      ["123",   "UDP",    "NTP",            "Time sync"],
      ["135",   "TCP",    "MS-RPC",         "Windows RPC endpoint mapper"],
      ["137/138","UDP",   "NetBIOS",        "Name/datagram service"],
      ["139",   "TCP",    "NetBIOS-SSN",    "SMB over NetBIOS"],
      ["143",   "TCP",    "IMAP",           "Mail alma"],
      ["161/162","UDP",   "SNMP",           "161 query, 162 trap"],
      ["179",   "TCP",    "BGP",            "Border Gateway Protocol"],
      ["389",   "TCP",    "LDAP",           "Directory service"],
      ["443",   "TCP",    "HTTPS",          "HTTP over TLS"],
      ["445",   "TCP",    "SMB",            "Direct SMB (modern)"],
      ["465",   "TCP",    "SMTPS",          "SMTP over TLS (deprecated)"],
      ["514",   "UDP",    "Syslog",         "Log toplama"],
      ["515",   "TCP",    "LPD",            "Printer"],
      ["520",   "UDP",    "RIP",            "Routing Information Protocol"],
      ["587",   "TCP",    "SMTP (submit)",  "Mail submission with auth"],
      ["636",   "TCP",    "LDAPS",          "LDAP over TLS"],
      ["873",   "TCP",    "rsync",          "Dosya sync"],
      ["989/990","TCP",   "FTPS",           "FTP over TLS"],
      ["993",   "TCP",    "IMAPS",          "IMAP over TLS"],
      ["995",   "TCP",    "POP3S",          "POP3 over TLS"],
      ["1194",  "UDP",    "OpenVPN",        "Varsayılan port"],
      ["1433",  "TCP",    "MSSQL",          "Microsoft SQL Server"],
      ["1434",  "UDP",    "MSSQL Monitor",  "SQL Browser"],
      ["1521",  "TCP",    "Oracle DB",      "Oracle database"],
      ["1701",  "UDP",    "L2TP",           "VPN"],
      ["1723",  "TCP",    "PPTP",           "VPN (deprecated)"],
      ["1812/1813","UDP", "RADIUS",         "Auth / accounting"],
      ["2049",  "TCP/UDP","NFS",            "Network File System"],
      ["2082/2083","TCP", "cPanel",         "Control panel"],
      ["3128",  "TCP",    "Squid",          "Proxy"],
      ["3268/3269","TCP", "Global Catalog", "AD LDAP"],
      ["3306",  "TCP",    "MySQL/MariaDB",  "Database"],
      ["3389",  "TCP",    "RDP",            "Remote Desktop"],
      ["4500",  "UDP",    "IPsec NAT-T",    "NAT traversal"],
      ["5060",  "TCP/UDP","SIP",            "VoIP signalling"],
      ["5061",  "TCP",    "SIPS",           "SIP over TLS"],
      ["5222",  "TCP",    "XMPP",           "Jabber/instant messaging"],
      ["5432",  "TCP",    "PostgreSQL",     "Database"],
      ["5900",  "TCP",    "VNC",            "Remote desktop"],
      ["5985/5986","TCP", "WinRM",          "Windows Remote Management"],
      ["6379",  "TCP",    "Redis",          "Key-value store"],
      ["6443",  "TCP",    "Kubernetes API", "K8s control plane"],
      ["6514",  "TCP",    "Syslog over TLS","Güvenli syslog"],
      ["8080",  "TCP",    "HTTP-alt",       "Proxy, alt HTTP"],
      ["8443",  "TCP",    "HTTPS-alt",      "Alt HTTPS, F5 GUI"],
      ["9000",  "TCP",    "PHP-FPM / Sonar","Alt servisler"],
      ["9092",  "TCP",    "Kafka",          "Message broker"],
      ["9200",  "TCP",    "Elasticsearch",  "Search API"],
      ["9300",  "TCP",    "Elasticsearch",  "Node transport"],
      ["11211", "TCP",    "Memcached",      "Cache"],
      ["27017", "TCP",    "MongoDB",        "NoSQL database"]
    ]
  },

  {
    id: "tcp-flags-hex",
    name: "TCP Flag Hex Değerleri",
    icon: "🚩",
    desc: "TCP flag kombinasyonlarının hex değerleri — 'tcp.flags == 0x12' gibi filtreler için",
    cols: ["Hex", "Binary", "Flags", "Anlam"],
    rows: [
      ["0x01", "000001", "FIN",              "Düzgün kapanış isteği"],
      ["0x02", "000010", "SYN",              "Yeni bağlantı — handshake 1"],
      ["0x04", "000100", "RST",              "Zorla kes — port kapalı/reddet"],
      ["0x08", "001000", "PSH",              "Hemen ilet (push)"],
      ["0x10", "010000", "ACK",              "Veri onaylama"],
      ["0x20", "100000", "URG",              "Acil veri (nadir)"],
      ["0x11", "010001", "FIN-ACK",          "Kapanış + onay"],
      ["0x12", "010010", "SYN-ACK",          "Bağlantı kabul — handshake 2"],
      ["0x14", "010100", "RST-ACK",          "Reset with ACK"],
      ["0x18", "011000", "PSH-ACK",          "Veri gönder + onay (yaygın)"],
      ["0x19", "011001", "FIN-PSH-ACK",      "Kapanışta son data"],
      ["0x29", "101001", "FIN-PSH-URG",      "XMAS scan"],
      ["0x000","000000","(None)",            "NULL scan — saldırı"],
      ["0xFF", "111111", "All flags",        "Full set — anormal"]
    ]
  },

  {
    id: "tls-versions",
    name: "TLS / SSL Versiyon Numaraları",
    icon: "🔒",
    desc: "TLS record.version alanındaki hex değerleri",
    cols: ["Hex", "Versiyon", "Durum", "Notlar"],
    rows: [
      ["0x0200", "SSL 2.0",   "❌ Yasak",     "Ağır güvenlik sorunları"],
      ["0x0300", "SSL 3.0",   "❌ Yasak",     "POODLE attack"],
      ["0x0301", "TLS 1.0",   "⚠ Eskimiş",    "PCI-DSS yasakladı"],
      ["0x0302", "TLS 1.1",   "⚠ Eskimiş",    "Kullanımdan kalktı"],
      ["0x0303", "TLS 1.2",   "✓ OK",         "Hala yaygın"],
      ["0x0304", "TLS 1.3",   "✓ Önerilen",   "Modern, PFS, hızlı"]
    ]
  },

  {
    id: "tls-alerts",
    name: "TLS Alert Kodları",
    icon: "⚠",
    desc: "TLS handshake hatalarında gelen alert kodları",
    cols: ["Kod", "İsim", "Anlam"],
    rows: [
      ["0",   "close_notify",             "Normal kapanış"],
      ["10",  "unexpected_message",       "Protokol sıra hatası"],
      ["20",  "bad_record_mac",           "MAC doğrulanamadı (MITM?)"],
      ["21",  "decryption_failed",        "Decryption hatası"],
      ["22",  "record_overflow",          "Record limiti aşıldı"],
      ["30",  "decompression_failure",    "Decompression hatası"],
      ["40",  "handshake_failure",        "Cipher/versiyon uyumsuz (EN YAYGIN)"],
      ["41",  "no_certificate",           "Client cert gerekli ama yok"],
      ["42",  "bad_certificate",          "Sertifika bozuk"],
      ["43",  "unsupported_certificate",  "Cert tipi desteksiz"],
      ["44",  "certificate_revoked",      "Cert revoke edildi"],
      ["45",  "certificate_expired",      "Cert süresi doldu"],
      ["46",  "certificate_unknown",      "Cert tanınmayan hata"],
      ["47",  "illegal_parameter",        "Yasa dışı parametre"],
      ["48",  "unknown_ca",               "CA güvenilmez"],
      ["49",  "access_denied",            "Erişim reddedildi"],
      ["50",  "decode_error",             "Decode başarısız"],
      ["51",  "decrypt_error",            "Decrypt hatası"],
      ["70",  "protocol_version",         "TLS versiyonu desteksiz"],
      ["71",  "insufficient_security",    "Zayıf güvenlik"],
      ["80",  "internal_error",           "Server iç hata"],
      ["86",  "inappropriate_fallback",   "Downgrade attack önlendi"],
      ["90",  "user_canceled",            "Kullanıcı iptal"],
      ["100", "no_renegotiation",         "Renegotiation reddedildi"],
      ["110", "unsupported_extension",    "Ext desteksiz"],
      ["112", "unrecognized_name",        "SNI tanınmadı"],
      ["113", "bad_certificate_status",   "OCSP hatası"],
      ["116", "certificate_required",     "mTLS client cert zorunlu"],
      ["120", "no_application_protocol",  "ALPN negotiation fail"]
    ]
  },

  {
    id: "http-codes",
    name: "HTTP Status Kodları",
    icon: "🌐",
    desc: "HTTP yanıt kodları — fintech bağlamıyla",
    cols: ["Kod", "İsim", "Fintech Anlamı"],
    rows: [
      ["200", "OK",                          "Normal başarılı"],
      ["201", "Created",                     "POST → kayıt oluşturuldu"],
      ["204", "No Content",                  "Başarılı, body yok"],
      ["301", "Moved Permanently",           "Kalıcı redirect"],
      ["302", "Found",                       "Geçici redirect (HTTP→HTTPS)"],
      ["304", "Not Modified",                "Cache geçerli"],
      ["307", "Temporary Redirect",          "Method koruyarak"],
      ["308", "Permanent Redirect",          "308 = kalıcı + method korur"],
      ["400", "Bad Request",                 "Malformed request"],
      ["401", "Unauthorized",                "Token missing/invalid"],
      ["402", "Payment Required",            "Nadiren kullanılır"],
      ["403", "Forbidden",                   "WAF/ASM block olabilir"],
      ["404", "Not Found",                   "URL yanlış / backend yok"],
      ["405", "Method Not Allowed",          "GET'e POST yolladın"],
      ["408", "Request Timeout",             "Client yavaş gönderdi"],
      ["409", "Conflict",                    "State conflict (race)"],
      ["413", "Payload Too Large",           "F5 max-body-size aşıldı"],
      ["414", "URI Too Long",                "URL uzunluk limiti"],
      ["415", "Unsupported Media Type",      "Content-Type kabul edilmez"],
      ["422", "Unprocessable Entity",        "Validation error"],
      ["429", "Too Many Requests",           "Rate limit"],
      ["451", "Legal Reasons",               "Yasal sebeplerle block"],
      ["500", "Internal Server Error",       "Backend exception/crash"],
      ["501", "Not Implemented",             "Server method bilmiyor"],
      ["502", "Bad Gateway",                 "Backend geçersiz yanıt"],
      ["503", "Service Unavailable",         "Pool down / overload"],
      ["504", "Gateway Timeout",             "F5 backend'den yanıt yok"],
      ["505", "HTTP Version Not Supported",  "Protokol versiyonu"],
      ["507", "Insufficient Storage",        "Disk dolu"],
      ["511", "Network Auth Required",       "Captive portal"]
    ]
  },

  {
    id: "sip-codes",
    name: "SIP Status Kodları",
    icon: "📞",
    desc: "SIP yanıt kodları — INVITE sonrası dönen cevaplar",
    cols: ["Kod", "İsim", "Anlam"],
    rows: [
      ["100", "Trying",                    "İsteği aldım, işliyorum"],
      ["180", "Ringing",                   "Telefon çalıyor"],
      ["181", "Call Being Forwarded",      "Yönlendiriliyor"],
      ["182", "Queued",                    "Sırada"],
      ["183", "Session Progress",          "Erken medya"],
      ["200", "OK",                        "Kabul edildi / başarılı"],
      ["202", "Accepted",                  "Async kabul"],
      ["300", "Multiple Choices",          "Birden fazla seçenek"],
      ["301", "Moved Permanently",         "Kalıcı yönlendirme"],
      ["302", "Moved Temporarily",         "Geçici yönlendirme"],
      ["305", "Use Proxy",                 "Proxy kullan"],
      ["400", "Bad Request",               "Format hatası"],
      ["401", "Unauthorized",              "Credential gerekli"],
      ["402", "Payment Required",          "Nadir"],
      ["403", "Forbidden",                 "IP yasaklı"],
      ["404", "Not Found",                 "Aranan numara yok"],
      ["405", "Method Not Allowed",        "Method desteksiz"],
      ["406", "Not Acceptable",            "Kabul edilemez"],
      ["407", "Proxy Auth Required",       "Proxy auth gerekli"],
      ["408", "Request Timeout",           "Yanıt yok"],
      ["409", "Conflict",                  "State conflict"],
      ["410", "Gone",                      "Artık erişilemez"],
      ["413", "Request Too Large",         "İstek çok büyük"],
      ["415", "Unsupported Media Type",    "Codec desteksiz"],
      ["420", "Bad Extension",             "Ext desteksiz"],
      ["421", "Extension Required",        "Ext gerekli"],
      ["480", "Temporarily Unavailable",   "Şu an cevap veremiyor"],
      ["481", "Call/Transaction Does Not Exist", "Session yok"],
      ["482", "Loop Detected",             "Routing loop"],
      ["483", "Too Many Hops",             "Max-Forwards aşıldı"],
      ["484", "Address Incomplete",        "Eksik numara"],
      ["485", "Ambiguous",                 "Belirsiz"],
      ["486", "Busy Here",                 "Meşgul"],
      ["487", "Request Terminated",        "CANCEL ile iptal"],
      ["488", "Not Acceptable Here",       "Codec uyumsuz"],
      ["491", "Request Pending",           "Beklemede"],
      ["500", "Server Internal Error",     "Sunucu hatası"],
      ["501", "Not Implemented",           "Desteklenmiyor"],
      ["502", "Bad Gateway",               "Gateway sorunu"],
      ["503", "Service Unavailable",       "Kapasite/down"],
      ["504", "Server Time-out",           "Server timeout"],
      ["505", "Version Not Supported",     "SIP versiyonu"],
      ["513", "Message Too Large",         "Mesaj çok büyük"],
      ["600", "Busy Everywhere",           "Her yerde meşgul"],
      ["603", "Decline",                   "Reddetti"],
      ["604", "Does Not Exist Anywhere",   "Hiçbir yerde yok"],
      ["606", "Not Acceptable",            "Global reddetme"]
    ]
  },

  {
    id: "icmp-types",
    name: "ICMP Tipleri ve Kodları",
    icon: "📡",
    desc: "ICMP message tipleri — ağ sorun sinyalleri",
    cols: ["Tip", "İsim", "Notlar"],
    rows: [
      ["0",  "Echo Reply",              "Ping yanıtı"],
      ["3",  "Destination Unreachable", "Code: 0=net, 1=host, 3=port, 4=frag needed"],
      ["4",  "Source Quench",           "Deprecated — congestion"],
      ["5",  "Redirect",                "Spoofing riski"],
      ["8",  "Echo Request",            "Ping"],
      ["9",  "Router Advertisement",    "RIP-like"],
      ["10", "Router Solicitation",     "Router ara"],
      ["11", "Time Exceeded",           "TTL=0 / traceroute"],
      ["12", "Parameter Problem",       "Header hatası"],
      ["13", "Timestamp Request",       "Eski"],
      ["14", "Timestamp Reply",         "Eski"],
      ["17", "Address Mask Request",    "Subnet mask sorgusu"],
      ["18", "Address Mask Reply",      ""],
      ["30", "Traceroute",              "MS traceroute"]
    ]
  },

  {
    id: "dns-types",
    name: "DNS Record Tipleri",
    icon: "🌍",
    desc: "DNS query type numaraları ve kullanımları",
    cols: ["Tip", "İsim", "Amaç"],
    rows: [
      ["1",   "A",      "IPv4 adresi"],
      ["2",   "NS",     "Name Server"],
      ["5",   "CNAME",  "Canonical name (alias)"],
      ["6",   "SOA",    "Start of Authority (zone metadata)"],
      ["12",  "PTR",    "Reverse DNS (IP → hostname)"],
      ["15",  "MX",     "Mail exchanger"],
      ["16",  "TXT",    "SPF, DKIM, verification"],
      ["24",  "SIG",    "DNSSEC signature"],
      ["25",  "KEY",    "DNSSEC key"],
      ["28",  "AAAA",   "IPv6 adresi"],
      ["33",  "SRV",    "Service record (SIP, LDAP, XMPP)"],
      ["35",  "NAPTR",  "Dinamik delegation"],
      ["41",  "OPT",    "EDNS0 (pseudo)"],
      ["43",  "DS",     "DNSSEC Delegation Signer"],
      ["46",  "RRSIG",  "DNSSEC signed record"],
      ["47",  "NSEC",   "DNSSEC next secure"],
      ["48",  "DNSKEY", "DNSSEC key"],
      ["52",  "TLSA",   "DANE (TLS binding)"],
      ["65",  "HTTPS",  "HTTPS service binding (yeni)"],
      ["252", "AXFR",   "Zone transfer"],
      ["253", "MAILB",  "Mailbox records"],
      ["255", "ANY",    "Tüm kayıtlar"],
      ["257", "CAA",    "Cert Authority Authorization"]
    ]
  },

  {
    id: "dns-rcodes",
    name: "DNS Response Kodları",
    icon: "📋",
    desc: "DNS yanıtındaki RCODE değerleri",
    cols: ["Kod", "İsim", "Anlam"],
    rows: [
      ["0", "NOERROR",  "Başarılı"],
      ["1", "FORMERR",  "Format hatası"],
      ["2", "SERVFAIL", "Server internal hata"],
      ["3", "NXDOMAIN", "Domain yok"],
      ["4", "NOTIMP",   "Not implemented"],
      ["5", "REFUSED",  "Reddedildi (ACL)"],
      ["6", "YXDOMAIN", "Name var olmamalıydı"],
      ["7", "YXRRSET",  "RRset var olmamalıydı"],
      ["8", "NXRRSET",  "RRset yok"],
      ["9", "NOTAUTH",  "Authoritative değil"],
      ["10","NOTZONE",  "Zone'da değil"]
    ]
  },

  {
    id: "ip-protos",
    name: "IP Protocol Numaraları",
    icon: "📋",
    desc: "IP header'daki 'protocol' alanı değerleri",
    cols: ["No", "Protokol", "Notlar"],
    rows: [
      ["1",   "ICMP",     "Internet Control Message"],
      ["2",   "IGMP",     "Multicast"],
      ["4",   "IPv4",     "IP-in-IP tunnel"],
      ["6",   "TCP",      "Transmission Control"],
      ["17",  "UDP",      "User Datagram"],
      ["41",  "IPv6",     "IPv6-in-IPv4 tunnel"],
      ["47",  "GRE",      "Generic Routing Encapsulation"],
      ["50",  "ESP",      "IPsec Encapsulating Security"],
      ["51",  "AH",       "IPsec Authentication Header"],
      ["58",  "ICMPv6",   "ICMP for IPv6"],
      ["89",  "OSPF",     "Open Shortest Path First"],
      ["112", "VRRP",     "Virtual Router Redundancy"],
      ["115", "L2TP",     "Layer 2 Tunneling"],
      ["132", "SCTP",     "Stream Control Transmission"]
    ]
  },

  {
    id: "ethertypes",
    name: "Ethernet Type (Ethertype) Kodları",
    icon: "🔗",
    desc: "Ethernet frame'deki type alanı",
    cols: ["Hex", "Protokol", "Notlar"],
    rows: [
      ["0x0800", "IPv4",         "En yaygın"],
      ["0x0806", "ARP",          "Address Resolution"],
      ["0x0835", "RARP",         "Reverse ARP (eski)"],
      ["0x8035", "RARP",         ""],
      ["0x8100", "802.1Q VLAN",  "VLAN tagged"],
      ["0x8847", "MPLS unicast", ""],
      ["0x8848", "MPLS multicast",""],
      ["0x86dd", "IPv6",         ""],
      ["0x8863", "PPPoE discovery","ADSL discovery"],
      ["0x8864", "PPPoE session", "ADSL data"],
      ["0x888e", "802.1X",       "Port-based auth"],
      ["0x88a8", "802.1ad (QinQ)","Stacked VLAN"],
      ["0x88cc", "LLDP",         "Link Layer Discovery"],
      ["0x8906", "FCoE",         "Fibre Channel over Ethernet"],
      ["0x8912", "TRILL",        "Transparent Interconnection"]
    ]
  },

  {
    id: "tcp-states",
    name: "TCP Bağlantı Durumları",
    icon: "🔄",
    desc: "TCP state machine — netstat/ss çıktısında görünen durumlar",
    cols: ["Durum", "Anlam", "Kalıcılık"],
    rows: [
      ["LISTEN",       "Server port dinliyor",                 "Sürekli"],
      ["SYN-SENT",     "Client SYN gönderdi, yanıt bekliyor",  "~ms"],
      ["SYN-RECEIVED", "Server SYN-ACK gönderdi, ACK bekliyor","~ms"],
      ["ESTABLISHED",  "Bağlantı kurulu, veri akışı",          "Sınırsız"],
      ["FIN-WAIT-1",   "İlk taraf FIN gönderdi",               "~ms"],
      ["FIN-WAIT-2",   "ACK aldı, karşı FIN bekliyor",         "Kısa"],
      ["CLOSE-WAIT",   "FIN aldı, app kapatmadı",              "Uygulama yavaş"],
      ["CLOSING",      "Her iki taraf aynı anda FIN",          "Nadir"],
      ["LAST-ACK",     "Son ACK bekliyor",                      "~ms"],
      ["TIME-WAIT",    "Bağlantı kapandı, port bekletiliyor",  "2*MSL (60-240sn)"],
      ["CLOSED",       "Bağlantı tamamen kapandı",             "-"]
    ]
  },

  {
    id: "http-methods",
    name: "HTTP Method'ları",
    icon: "📨",
    desc: "HTTP request metodları ve idempotency",
    cols: ["Method", "Amaç", "Idempotent", "Body"],
    rows: [
      ["GET",     "Kaynak oku",               "✓", "Hayır"],
      ["HEAD",    "Sadece header iste",        "✓", "Hayır"],
      ["POST",    "Kaynak oluştur/gönder",     "✗", "Evet"],
      ["PUT",     "Kaynak değiştir/oluştur",   "✓", "Evet"],
      ["PATCH",   "Kısmi güncelleme",          "✗", "Evet"],
      ["DELETE",  "Kaynak sil",                "✓", "Nadiren"],
      ["OPTIONS", "Destekli method sor (CORS)","✓", "Hayır"],
      ["CONNECT", "Tunnel aç (proxy)",         "✗", "Hayır"],
      ["TRACE",   "Loopback test",             "✓", "Hayır"]
    ]
  },

  {
    id: "sip-methods",
    name: "SIP Method'ları",
    icon: "📤",
    desc: "SIP request metodları",
    cols: ["Method", "Amaç"],
    rows: [
      ["INVITE",    "Yeni oturum (çağrı) başlat"],
      ["ACK",       "INVITE 200 OK'i onayla"],
      ["BYE",       "Oturumu kapat"],
      ["CANCEL",    "Beklemedeki INVITE'ı iptal et"],
      ["REGISTER",  "Kullanıcı konumu bildir"],
      ["OPTIONS",   "Capability sorgula / keepalive"],
      ["REFER",     "Çağrı transferi"],
      ["NOTIFY",    "Subscription güncellemesi"],
      ["SUBSCRIBE", "Olay aboneliği"],
      ["MESSAGE",   "Instant messaging"],
      ["PUBLISH",   "Olay yayınla"],
      ["INFO",      "Ek bilgi (oturum içinde)"],
      ["PRACK",     "Provisional response ACK"],
      ["UPDATE",    "Oturum parametresi güncelle"]
    ]
  },

  {
    id: "display-operators",
    name: "Display Filter Operatörleri",
    icon: "⚡",
    desc: "Wireshark display filter syntax",
    cols: ["Operatör", "Alternatif", "Anlam", "Örnek"],
    rows: [
      ["==",          "eq",       "Eşit",                   "tcp.port == 443"],
      ["!=",          "ne",       "Eşit değil",             "ip.src != 10.0.0.1"],
      [">",           "gt",       "Büyük",                  "frame.len > 1500"],
      ["<",           "lt",       "Küçük",                  "tcp.window_size < 1000"],
      [">=",          "ge",       "Büyük eşit",             "http.response.code >= 500"],
      ["<=",          "le",       "Küçük eşit",             "tcp.time_delta <= 1"],
      ["&&",          "and",      "VE",                     "ip.src == X && tcp.port == Y"],
      ["||",          "or",       "VEYA",                   "http || http2"],
      ["!",           "not",      "DEĞİL",                  "!arp"],
      ["contains",    "",         "İçerir",                 'http.host contains "api"'],
      ["matches",     "",         "Regex eşleşme",          'dns.qry.name matches "^[a-f0-9]{32}$"'],
      ["in",          "",         "Liste üyeliği",          "tcp.port in {80 443 8080}"],
      ["bitwise_and", "&",        "Bit AND",                "tcp.flags & 0x02"],
      ["~=",          "",         "Approximately equal",    "frame.time ~= ..."],
      ["[n]",         "",         "Byte indeksleme",        "eth.dst[0] & 1"],
      ["[n:m]",       "",         "Byte slice",             "eth.src[0:3] == 00:50:56"]
    ]
  },

  {
    id: "bpf-syntax",
    name: "BPF Capture Filter Syntax",
    icon: "🎯",
    desc: "tcpdump ve Wireshark capture filtrelerinde kullanılan BPF syntax (display filter'dan FARKLI!)",
    cols: ["İfade", "Anlam"],
    rows: [
      ["host 10.0.0.1",                "Belirli IP (iki yön)"],
      ["src host 10.0.0.1",            "Kaynak IP"],
      ["dst host 10.0.0.1",            "Hedef IP"],
      ["net 10.0.0.0/24",              "Subnet"],
      ["port 443",                     "TCP/UDP port (iki yön)"],
      ["src port 443",                 "Source port"],
      ["dst port 443",                 "Destination port"],
      ["portrange 8000-9000",          "Port aralığı"],
      ["tcp",                          "TCP protokolü"],
      ["udp",                          "UDP protokolü"],
      ["icmp",                         "ICMP"],
      ["arp",                          "ARP"],
      ["ether host aa:bb:cc:dd:ee:ff", "MAC adresi"],
      ["ether src aa:bb:cc:dd:ee:ff",  "Kaynak MAC"],
      ["vlan 10",                      "VLAN ID"],
      ["broadcast",                    "Broadcast paketler"],
      ["multicast",                    "Multicast paketler"],
      ["and / &&",                     "VE operatörü"],
      ["or / ||",                      "VEYA"],
      ["not / !",                      "DEĞİL"],
      ["(ifade)",                      "Gruplama"],
      ["host A and host B",            "İki host arasındaki trafik"],
      ["tcp[13]==2",                   "TCP flag byte (SYN)"],
      ["tcp[tcpflags] & tcp-syn != 0", "SYN flag set"],
      ["len > 1400",                   "Paket boyutu"]
    ]
  },

  {
    id: "wireshark-shortcuts",
    name: "Wireshark Klavye Kısayolları",
    icon: "⌨",
    desc: "Wireshark GUI'de verimlilik arttırıcı kısayollar",
    cols: ["Kısayol", "İşlem"],
    rows: [
      ["Ctrl+K / Cmd+K",       "Capture options (yeni capture başlat)"],
      ["Ctrl+E",               "Capture başlat/durdur"],
      ["Ctrl+R",               "Capture yeniden başlat"],
      ["Ctrl+O",               "PCAP dosyası aç"],
      ["Ctrl+S",               "Kaydet"],
      ["Ctrl+Shift+S",         "Farklı kaydet"],
      ["Ctrl+W",               "Kapat"],
      ["Ctrl+F",               "Paket içinde string ara"],
      ["Ctrl+N / Ctrl+B",      "Sonraki / önceki paket"],
      ["Ctrl+G",               "Paket numarasına git"],
      ["Ctrl+M",               "Paketi işaretle/işaret kaldır"],
      ["Shift+Ctrl+N",         "İşaretli sonraki pakete git"],
      ["Ctrl+T",               "Timestamp format değiştir"],
      ["Ctrl+/",               "Display filter input'una odaklan"],
      ["Ctrl+Enter",           "Filtre uygula"],
      ["Ctrl+Shift+L",         "Lua plugin'leri reload et"],
      ["Ctrl+H",               "Follow HTTP Stream"],
      ["Ctrl+Alt+Shift+T",     "Follow TCP Stream"],
      ["Ctrl+Alt+Shift+U",     "Follow UDP Stream"],
      ["Ctrl+Alt+Shift+S",     "Follow TLS Stream"],
      ["Ctrl+I",               "Packet details expand/collapse"],
      ["Ctrl+.",               "Sonraki paket aynı konuşmada"],
      ["Ctrl+,",               "Önceki paket aynı konuşmada"],
      ["Alt+→ / Alt+←",        "Geçmiş navigasyon"]
    ]
  },

  {
    id: "cidr",
    name: "CIDR / Subnet Referansı",
    icon: "🔢",
    desc: "CIDR prefix → host sayısı ve netmask",
    cols: ["CIDR", "Netmask", "Host Sayısı", "Kullanıcı"],
    rows: [
      ["/32", "255.255.255.255", "1",           "Tek host"],
      ["/31", "255.255.255.254", "2",           "Point-to-point"],
      ["/30", "255.255.255.252", "2 host",      "P2P link"],
      ["/29", "255.255.255.248", "6 host",      "Küçük subnet"],
      ["/28", "255.255.255.240", "14 host",     ""],
      ["/27", "255.255.255.224", "30 host",     ""],
      ["/26", "255.255.255.192", "62 host",     ""],
      ["/25", "255.255.255.128", "126 host",    ""],
      ["/24", "255.255.255.0",   "254 host",    "Klasik C sınıfı"],
      ["/23", "255.255.254.0",   "510 host",    ""],
      ["/22", "255.255.252.0",   "1022 host",   ""],
      ["/21", "255.255.248.0",   "2046 host",   ""],
      ["/20", "255.255.240.0",   "4094 host",   ""],
      ["/19", "255.255.224.0",   "8190 host",   ""],
      ["/18", "255.255.192.0",   "16382 host",  ""],
      ["/17", "255.255.128.0",   "32766 host",  ""],
      ["/16", "255.255.0.0",     "65534 host",  "Klasik B sınıfı"],
      ["/12", "255.240.0.0",     "1M host",     ""],
      ["/8",  "255.0.0.0",       "16M host",    "Klasik A sınıfı"]
    ]
  },

  {
    id: "private-ranges",
    name: "Private IP Aralıkları",
    icon: "🏠",
    desc: "RFC 1918, loopback, link-local ve diğer özel aralıklar",
    cols: ["Aralık", "CIDR", "Amaç"],
    rows: [
      ["10.0.0.0 - 10.255.255.255",      "10.0.0.0/8",       "RFC 1918 (büyük private)"],
      ["172.16.0.0 - 172.31.255.255",    "172.16.0.0/12",    "RFC 1918"],
      ["192.168.0.0 - 192.168.255.255",  "192.168.0.0/16",   "RFC 1918 (ev/ofis)"],
      ["127.0.0.0/8",                    "127.0.0.0/8",      "Loopback"],
      ["169.254.0.0/16",                 "169.254.0.0/16",   "Link-local (APIPA)"],
      ["224.0.0.0/4",                    "224.0.0.0/4",      "Multicast"],
      ["240.0.0.0/4",                    "240.0.0.0/4",      "Reserved (Class E)"],
      ["100.64.0.0/10",                  "100.64.0.0/10",    "Carrier-grade NAT (CGNAT)"],
      ["192.0.2.0/24",                   "192.0.2.0/24",     "TEST-NET-1 (docs)"],
      ["198.51.100.0/24",                "198.51.100.0/24",  "TEST-NET-2 (docs)"],
      ["203.0.113.0/24",                 "203.0.113.0/24",   "TEST-NET-3 (docs)"],
      ["::1/128",                        "::1",              "IPv6 loopback"],
      ["fe80::/10",                      "fe80::/10",        "IPv6 link-local"],
      ["fc00::/7",                       "fc00::/7",         "IPv6 unique local (private)"],
      ["2001:db8::/32",                  "2001:db8::/32",    "IPv6 documentation"]
    ]
  },

  {
    id: "tcpdump-flags",
    name: "tcpdump Komut Flag'leri",
    icon: "⚙",
    desc: "tcpdump CLI parametreleri hızlı referans",
    cols: ["Flag", "Anlam"],
    rows: [
      ["-i <iface>",    "Capture interface"],
      ["-w <file>",     "PCAP'i dosyaya yaz"],
      ["-r <file>",     "PCAP'tan oku"],
      ["-s <len>",      "Snaplen (0 = tüm paket)"],
      ["-c <count>",    "N paket sonra dur"],
      ["-C <MB>",       "Ring buffer dosya boyutu (MB)"],
      ["-W <num>",      "Ring buffer dosya adedi"],
      ["-G <sec>",      "Rotation süresi (saniye)"],
      ["-n",            "IP'leri resolve etme"],
      ["-nn",           "Port'ları da resolve etme"],
      ["-v / -vv / -vvv","Verbose seviyeleri"],
      ["-X",            "Payload'u hex+ASCII göster"],
      ["-A",            "Payload'u ASCII göster"],
      ["-e",            "Ethernet header göster"],
      ["-tttt",         "Timestamp full format"],
      ["-q",            "Quiet mode"],
      ["-D",            "Mevcut interface'leri listele"],
      ["-Z <user>",     "Drop to user (security)"],
      ["-K",            "Checksum doğrulamayı kapat"],
      ["-p",            "Promiscuous mode kapalı"]
    ]
  },

  {
    id: "wireshark-colors",
    name: "Wireshark Varsayılan Renkler",
    icon: "🎨",
    desc: "Wireshark'ın default coloring rules'u",
    cols: ["Renk", "Anlam", "Filtre"],
    rows: [
      ["Kırmızı (açık)",  "Bad TCP",              "tcp.analysis.flags && !tcp.analysis.window_update"],
      ["Sarı",            "HTTP",                 "http"],
      ["Mor (açık)",      "TCP SYN/FIN",          "tcp.flags & 0x02 || tcp.flags.fin == 1"],
      ["Gri",             "TCP",                  "tcp"],
      ["Mavi (koyu)",     "UDP",                  "udp"],
      ["Yeşil",           "ARP",                  "arp"],
      ["Sarı (koyu)",     "ICMP",                 "icmp"],
      ["Siyah",           "Checksum hatası",      "eth.fcs_bad || ip.checksum_bad"],
      ["Mor (koyu)",      "SMB/NetBIOS",          "smb || nbss || nbns"],
      ["Pembe",           "HTTP/HTTPS routing",   "http.response || http.request"]
    ]
  }
];

/* ───────── DATA: ECOSYSTEM ───────── */
const ECOSYSTEM = [
  {
    name: "ZUI (Brim)",
    role: "PCAP + Zeek + Suricata",
    desc: "Büyük PCAP'ler için — Zed lake indexleme, SQL benzeri sorgu, Wireshark'a tek tıkla pivot",
    use: "Wireshark yavaşladığında büyük PCAP'leri analiz et",
    install: {
      "macOS": "brew install --cask zui",
      "Linux": "# https://zui.brimdata.io/ → .deb veya .rpm indir\nsudo dpkg -i zui_*.deb",
      "Windows": "zui.brimdata.io → .exe installer indir"
    },
    usage: "PCAP'i ZUI penceresine sürükle-bırak → Zeek + Suricata otomatik çalışır",
    queries: [
      { q: '_path=="http" | status_code >= 500 | count() by host', desc: "HTTP 5xx hataları host bazında" },
      { q: '_path=="conn" | duration > 60s | sort -r duration', desc: "Uzun TCP oturumlar" },
      { q: '_path=="ssl" | established==false | count() by server_name', desc: "Başarısız TLS handshake'ler" },
      { q: 'event_type=="alert" | count() by alert.category', desc: "Suricata alertleri" }
    ]
  },
  {
    name: "Zeek",
    role: "Network Security Monitor",
    desc: "PCAP'i structured log'a çevirir (conn.log, ssl.log, http.log, weird.log)",
    use: "Otomatik anomali tespiti + oturum bazlı analiz",
    install: {
      "macOS": "brew install zeek",
      "Ubuntu": "sudo apt install zeek",
      "RHEL/CentOS": "sudo dnf install zeek"
    },
    usage: "zeek -r cap.pcap  (mevcut dizinde log dosyaları üretir)",
    queries: [
      { q: "cat weird.log | zeek-cut ts id.orig_h id.resp_h name", desc: "Otomatik tespit edilen anomaliler" },
      { q: "cat notice.log | zeek-cut ts note msg", desc: "Güvenlik uyarıları" },
      { q: "cat ssl.log | zeek-cut ts server_name validation_status version", desc: "TLS oturum detayları" },
      { q: "cat conn.log | zeek-cut duration orig_bytes resp_bytes | sort -rn | head", desc: "En uzun bağlantılar" },
      { q: 'cat http.log | zeek-cut -d ts method host uri status_code | awk \'$5 >= 500\'', desc: "HTTP 5xx hataları" }
    ]
  },
  {
    name: "Suricata",
    role: "IDS/IPS",
    desc: "PCAP üzerinde otomatik Emerging Threats kural eşleşmesi",
    use: "ZUI ile birlikte kullan — alertler otomatik gelir",
    install: {
      "macOS": "brew install suricata",
      "Ubuntu": "sudo apt install suricata\nsudo suricata-update  # ET OPEN kurallar"
    },
    usage: "suricata -r cap.pcap -l /tmp/suricata-out/",
    queries: [
      { q: "jq '.alert' /tmp/suricata-out/eve.json | head -50", desc: "Alert özeti" },
      { q: 'jq \'select(.event_type=="alert") | .alert.signature\' eve.json | sort -u', desc: "Tespit edilen tehdit tipleri" },
      { q: 'jq \'select(.alert.severity==1)\' eve.json', desc: "Kritik alertler" }
    ]
  },
  {
    name: "Arkime (Moloch)",
    role: "Enterprise PCAP Arama",
    desc: "PCAP'leri Elasticsearch ile indexler, web arayüzünde Google gibi ara",
    use: "Uzun dönem PCAP saklama + hızlı arama",
    install: {
      "Ubuntu/Debian (easybutton)": "wget https://raw.githubusercontent.com/arkime/arkime/main/easybutton-singlehost.sh\nchmod +x easybutton-singlehost.sh\nsudo ./easybutton-singlehost.sh"
    },
    usage: "http://localhost:8005  (web UI — admin kullanıcı easybutton sırasında oluşturulur)",
    queries: [
      { q: "ip.src == 10.0.0.1 && port == 443", desc: "Arkime arama syntax'ı" },
      { q: "tags == malware && country.dst == CN", desc: "Etiketli trafik + coğrafi filtre" }
    ]
  },
  {
    name: "Malcolm (CISA)",
    role: "Self-hosted Analiz Paketi",
    desc: "Zeek + Arkime + Suricata + OpenSearch — Docker ile tek komut kurulum",
    use: "Fintech offline tam analiz ortamı",
    install: {
      "Docker (herhangi OS)": "git clone https://github.com/cisagov/Malcolm\ncd Malcolm\n./scripts/install.py\n./scripts/start"
    },
    usage: "http://localhost  (web UI) — PCAP'leri upload et, dashboardlarda görüntüle",
    queries: []
  },
  {
    name: "NetworkMiner",
    role: "Forensics",
    desc: "PCAP'ten hosts, dosyalar, resimler, credentials, DNS otomatik çıkarır",
    use: "Wireshark'tan önce hızlı triage",
    install: {
      "Windows": "netresec.com → free edition indir, extract et",
      "Linux/macOS": "mono NetworkMiner.exe cap.pcap"
    },
    usage: "NetworkMiner → File → Open → PCAP seç → sekmeler arası dolaş (Hosts, Files, Credentials, DNS)",
    queries: []
  },
  {
    name: "termshark",
    role: "Terminal Wireshark",
    desc: "SSH üzerinden F5'te tek binary ile PCAP analizi",
    use: "F5'e SSH ile bağlanıp canlı capture analizi",
    install: {
      "macOS": "brew install termshark",
      "Ubuntu/Debian": "sudo apt install termshark",
      "Go ile (herhangi OS)": "go install github.com/gcla/termshark/v2/cmd/termshark@v2.4.0"
    },
    usage: 'ssh root@f5 "tcpdump -i 0.0:nnnp -s 0 -w - host 10.0.0.1" | termshark -i -',
    queries: [
      { q: "termshark -r cap.pcap", desc: "PCAP'i terminal'de aç" },
      { q: 'termshark -r cap.pcap -Y "tls.alert_message"', desc: "Filtreli başlat" }
    ]
  },
  {
    name: "sngrep",
    role: "SIP Terminal Analizi",
    desc: "Terminal'de SIP ladder diyagramı",
    use: "SIP sorunlarında hızlı görsel analiz",
    install: {
      "macOS": "brew install sngrep",
      "Ubuntu/Debian": "sudo apt install sngrep",
      "RHEL/CentOS": "sudo dnf install sngrep"
    },
    usage: "sngrep -I cap.pcap  (PCAP'ten çalıştır)\nsngrep  (canlı capture)",
    queries: [
      { q: "sngrep -I cap.pcap -f 'host 192.168.1.1'", desc: "Filtreli okuma" },
      { q: "sngrep -d eth0 port 5060", desc: "Canlı SIP yakalama" }
    ]
  },
  {
    name: "TraceWrangler",
    role: "F5/LB Trace Analizi",
    desc: "Jasper Bongertz (SharkFest) yapımı — PCAP sanitize + derin anomali",
    use: "F5/load balancer trace'lerinde özel anomali tespiti",
    install: {
      "Windows": "tracewrangler.com → indir, extract (installer yok)"
    },
    usage: "TraceWrangler.exe → PCAP sürükle-bırak → Tasks tab → analiz çalıştır",
    queries: []
  },
  {
    name: "captcp",
    role: "TCP Root Cause",
    desc: "TCP akışlarını analiz eder — RTT, throughput, retransmission istatistikleri",
    use: "TCP sorunlarında 'neden?' sorusuna sayısal cevap",
    install: {
      "Linux/macOS": "git clone https://github.com/hgn/captcp\ncd captcp && sudo python setup.py install"
    },
    usage: "captcp statistic cap.pcap  (tüm akışlar)\ncaptcp show --flow 1 cap.pcap  (detaylı)",
    queries: [
      { q: "captcp statistic cap.pcap", desc: "Tüm TCP flow istatistikleri" },
      { q: "captcp throughput -f 1 cap.pcap", desc: "Flow 1 throughput grafiği" },
      { q: "captcp stacktrace cap.pcap", desc: "Retransmission izleme" }
    ]
  }
];

/* ───────── DATA: LUA PLUGINS ───────── */
const LUA_PLUGINS = [
  {
    name: "JA3 / JA3S Fingerprint",
    desc: "Her TLS Client Hello → MD5 hash. Malware tespiti, client identification, anomaly detection için kritik.",
    files: "ja3.lua + md5.lua",
    install: {
      "Linux (Ubuntu)": "wget https://raw.githubusercontent.com/fullylegit/ja3/master/ja3.lua\nwget https://raw.githubusercontent.com/kikito/md5.lua/master/md5.lua\nsudo cp ja3.lua md5.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/",
      "Windows": "İki dosyayı %APPDATA%\\Wireshark\\plugins\\ klasörüne kopyala\n(klasör yoksa oluştur)",
      "macOS": "cp ja3.lua md5.lua /Applications/Wireshark.app/Contents/PlugIns/wireshark/"
    },
    reload: "Wireshark → Analyze → Reload Lua Plugins (Ctrl+Shift+L)",
    filters: [
      { f: "ja3.hash", desc: "Tüm JA3 hash'leri göster" },
      { f: 'ja3.hash == "66918128f1b9b03303d77c6f2eefd128"', desc: "Bilinen hash ile eşleşme" },
      { f: "ja3.hash && tls.handshake.extensions_server_name", desc: "JA3 + SNI kombinasyonu" }
    ]
  },
  {
    name: "mar0ls Multi-Plugin Koleksiyonu",
    desc: "Çoklu işlevli plugin paketi: JA3/JA3S + IP geolocation + ASN lookup + H.265 RTP extraction.",
    files: "ja3_tls.lua · check_ipinfo.lua · check_asn.lua · rtp_h265_typ33_extractor.lua",
    install: {
      "Linux": "git clone https://github.com/mar0ls/wireshark_plugin\nsudo cp wireshark_plugin/*.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/",
      "Windows": "Repo klonla → .lua dosyalarını %APPDATA%\\Wireshark\\plugins\\ altına kopyala",
      "macOS": "git clone https://github.com/mar0ls/wireshark_plugin\ncp wireshark_plugin/*.lua /Applications/Wireshark.app/Contents/PlugIns/wireshark/"
    },
    reload: "Analyze → Reload Lua Plugins",
    filters: [
      { f: "ja3_tls.hash", desc: "JA3 hash (mar0ls versiyonu)" },
      { f: "ipinfo.country", desc: "IP geolocation - ülke" },
      { f: "asn.number", desc: "ASN numarası" }
    ]
  },
  {
    name: "Open-Markets Exchange Dissectors",
    desc: "Fintech borsa protokolleri — NASDAQ, NYSE, CME, Eurex, LSEG, HKEX, JPX, ICE, Cboe, Coinbase. Toplam 50+ dissector.",
    files: "Her borsa için ayrı .lua (örn: nasdaq_itch.lua, nyse_ouch.lua)",
    install: {
      "Tüm OS": "git clone https://github.com/Open-Markets-Initiative/wireshark-lua\n# İhtiyacın olan exchange'in .lua dosyasını kopyala\n# Örnek (Linux): sudo cp wireshark-lua/Nasdaq/nasdaq_itch_5_0.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/"
    },
    reload: "Analyze → Reload Lua Plugins",
    filters: [
      { f: "nasdaq_itch", desc: "NASDAQ ITCH protokol trafiği" },
      { f: "cme_mdp", desc: "CME Market Data Platform" },
      { f: "fix", desc: "FIX protokolü (built-in)" }
    ]
  }
];

const PLUGIN_LOCATIONS = [
  { os: "Linux (Ubuntu)", path: "/usr/lib/x86_64-linux-gnu/wireshark/plugins/" },
  { os: "Windows", path: "%APPDATA%\\Wireshark\\plugins\\" },
  { os: "macOS", path: "/Applications/Wireshark.app/Contents/PlugIns/wireshark/" }
];

/* ───────── DATA: STATISTICS ───────── */
const STATISTICS_GUIDE = [
  {
    name: "Protocol Hierarchy",
    path: "Statistics → Protocol Hierarchy",
    what: "Trafiğin protokol dağılımını % olarak gösterir",
    when: "PCAP'e ilk baktığında — ne var, ne yok?",
    tip: "TLS altında http çıkıyorsa deşifre yapılmış demektir"
  },
  {
    name: "Conversations",
    path: "Statistics → Conversations",
    what: "Kim kimle konuşmuş, ne kadar trafik",
    when: "En büyük akışı bulmak için — Bytes'a göre sırala",
    tip: "Outlier IP'ler burada kolayca görünür"
  },
  {
    name: "I/O Graphs",
    path: "Statistics → I/O Graphs",
    what: "Zamana göre trafik hacmi grafiği",
    when: "Spike, gap, pattern aramak için",
    tip: "Overlay: tcp.analysis.flags → sorunlar ne zaman?"
  },
  {
    name: "TCP Time-Sequence (tcptrace)",
    path: "Paket seç → Statistics → TCP Stream Graphs → Time-Sequence (tcptrace)",
    what: "Tek TCP akışının sequence/time grafiği",
    when: "Bir akış yavaş/takılı — ne oluyor?",
    tip: "Düz yatay çizgi = zero window veya app yavaş"
  },
  {
    name: "TCP Throughput",
    path: "Statistics → TCP Stream Graphs → Throughput",
    what: "Akışın zamana göre byte/sn throughput'u",
    when: "Performans analizi",
    tip: "Dip noktalar = congestion veya window full"
  },
  {
    name: "TCP Round Trip Time",
    path: "Statistics → TCP Stream Graphs → Round Trip Time",
    what: "Akışın RTT grafiği",
    when: "Gecikme analizi",
    tip: "Artan RTT = queue birikimi, ani spike = packet loss"
  },
  {
    name: "Service Response Time",
    path: "Statistics → Service Response Time → HTTP/DNS",
    what: "İstek-yanıt süre istatistikleri",
    when: "API yanıt süre analizi",
    tip: "Min/Max/Avg + dağılım histogramı"
  },
  {
    name: "VoIP Calls",
    path: "Statistics → VoIP Calls",
    what: "SIP çağrılarının listesi + flow + ses dinleme",
    when: "SIP analizi",
    tip: "Çağrı seç → Flow → Ladder diyagramı"
  },
  {
    name: "RTP Streams",
    path: "Statistics → RTP → RTP Streams → Analyze",
    what: "Ses kalitesi — jitter, loss, delta",
    when: "Ses sorunları",
    tip: "Max delta < 50ms, jitter < 20ms, loss < 1% normaldir"
  }
];

/* ───────── DATA: ROOT CAUSE ───────── */
const METHODOLOGIES = [
  {
    name: "Jasper Bongertz — 5 Adım Trace Analiz (SharkFest)",
    steps: [
      "Overview (30sn): Statistics → Capture File Properties + Protocol Hierarchy → 'Bu PCAP'ta ne var?'",
      "Conversations (1dk): Bytes'a göre sırala → outlier kim? Limit to display filter ile izole et",
      "Expert Info Triage (2dk): Analyze → Expert Info → Error → Warning → Note sırasıyla",
      "IO Graph Overlay (2dk): tcp.analysis.flags overlay → sorunlar zamansal olarak nerede?",
      "Drill-Down (5dk): Follow TCP Stream → TCP Stream Graphs → ayrı PCAP olarak kaydet"
    ]
  },
  {
    name: "Laura Chappell — 7 Adım Troubleshooting",
    steps: [
      "Complaint'i ölçülebilir tanımla — 'yavaş' değil, '10sn+ yanıt, saatte 15 kez'",
      "Doğru noktada capture al — önce şikayetçiye yakın, sonra sunucuya yakın",
      "IO Graph → gap/drop tespiti (interval 0.1s)",
      "Expert Info → severity filtresi (Error öncelikli)",
      "En yavaş konuşmayı takip et — tcp.analysis.ack_rtt ile sırala",
      "Handshake timing — SYN → SYN-ACK < 100ms normal, > 500ms path latency",
      "Baseline ile karşılaştır — 'iyi' bir PCAP ile diff"
    ]
  }
];

const HANDSHAKE_RC = [
  { symptom: "SYN var, SYN-ACK yok", cause: "Firewall drop, routing, sunucu down, port kapalı" },
  { symptom: "SYN → SYN-ACK → RST (client)", cause: "Client policy / cert pinning" },
  { symptom: "Handshake OK, mid-stream RST", cause: "Idle timeout (F5/FortiGate en sık)" },
  { symptom: "Handshake yavaş (>100ms RTT)", cause: "Path latency (sunucu sorunu değil)" },
  { symptom: "ClientHello → sonra TCP FIN", cause: "SNI / cipher / cert uyumsuzluğu" },
  { symptom: "ClientHello → Alert 40", cause: "Handshake failure (cipher mismatch)" },
  { symptom: "ClientHello → Alert 48", cause: "Unknown CA" },
  { symptom: "Retransmitted SYN", cause: "Paket kaybı veya sunucu meşgul" },
  { symptom: "Zero Window", cause: "Backend tampon dolu (yavaş işliyor)" },
  { symptom: "Duplicate ACK 3x → retrans", cause: "Fast retransmission → paket kaybı" }
];

const RC_CHECKLIST = [
  "Capture nerede alındı? (client / F5 / backend)",
  "Ne kadar süre? (Statistics → Capture File Properties)",
  "Protocol dağılımı nedir? (Protocol Hierarchy)",
  "En büyük konuşmacı kim? (Conversations → Bytes sort)",
  "Expert Info'da Error/Warning var mı?",
  "IO Graph'ta spike/gap var mı?",
  "TCP handshake tamamlandı mı? (tcp.flags.syn == 1)",
  "RST var mı, kimden? (tcp.flags.reset == 1 → ip.src)",
  "Retransmission var mı? (tcp.analysis.retransmission)",
  "Zero Window var mı? (tcp.analysis.zero_window)",
  "TLS handshake tamamlandı mı? (tls.handshake.type == 20)",
  "TLS Alert var mı? (tls.alert_message)",
  "HTTP 5xx var mı? (http.response.code >= 500)",
  "Response time uzun mu? (http.time > 5)",
  "'İyi' bir PCAP karşılaştırmam var mı?"
];

/* ───────── DATA: TSHARK ───────── */
const TSHARK_COMMANDS = [
  { title: "Filtreli görüntüleme", cmd: 'tshark -r cap.pcap -Y "tcp.analysis.flags"' },
  { title: "Belirli alanları çıkar", cmd: 'tshark -r cap.pcap -Y "http.response.code >= 500" -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.response.code' },
  { title: "JSON çıktısı", cmd: 'tshark -r cap.pcap -Y "sip" -T json' },
  { title: "Protocol hierarchy", cmd: "tshark -r cap.pcap -q -z io,phs" },
  { title: "IO stat (1sn)", cmd: "tshark -r cap.pcap -q -z io,stat,1" },
  { title: "IO stat filtreli", cmd: 'tshark -r cap.pcap -q -z io,stat,1,"tcp.analysis.retransmission"' },
  { title: "TCP conversations", cmd: "tshark -r cap.pcap -q -z conv,tcp" },
  { title: "HTTP tree", cmd: "tshark -r cap.pcap -q -z http,tree" },
  { title: "SIP stat", cmd: "tshark -r cap.pcap -q -z sip,stat" },
  { title: "TLS deşifre", cmd: 'tshark -r cap.pcap -o "tls.keylog_file:keys.log" -Y "http2"' },
  { title: "F5 key çıkar", cmd: 'tshark -r decrypt.pcap -Y "f5ethtrailer.tls.keylog" -T fields -e f5ethtrailer.tls.keylog | sed "s/,/\\n/g" > pre_master.pms' },
  { title: "PCAP birleştir", cmd: "mergecap -w merged.pcap cap1.pcap cap2.pcap" },
  { title: "Zaman dilimine kes", cmd: 'editcap -A "2024-01-15 10:00:00" -B "2024-01-15 10:05:00" input.pcap output.pcap' },
  { title: "İlk N paketi al", cmd: "editcap -r input.pcap output.pcap 1-1000" },
  { title: "PCAP bilgisi", cmd: "capinfos cap.pcap" },
  { title: "Dup paket kaldır", cmd: "editcap --discard-all-dupes input.pcap output.pcap" }
];

/* ───────── DATA: GITHUB REPOS ───────── */
const REPOS = [
  { name: "amwalding/wireshark_profiles", type: "Profil", desc: "500K+ indirme, en büyük koleksiyon", url: "https://github.com/amwalding/wireshark_profiles" },
  { name: "akamura/wireshark-profile", type: "Profil", desc: "GeoIP + ASN enrichment", url: "https://github.com/akamura/wireshark-profile" },
  { name: "networkforensic.dk", type: "Profil", desc: "Security odaklı — JA3, SMB, DDoS", url: "https://networkforensic.dk/Tools/default.html" },
  { name: "fullylegit/ja3", type: "Lua Plugin", desc: "JA3/JA3S TLS parmak izi", url: "https://github.com/fullylegit/ja3" },
  { name: "mar0ls/wireshark_plugin", type: "Lua Plugin", desc: "Multi-plugin koleksiyon", url: "https://github.com/mar0ls/wireshark_plugin" },
  { name: "Open-Markets/wireshark-lua", type: "Dissector", desc: "Fintech borsa protokolleri", url: "https://github.com/Open-Markets-Initiative/wireshark-lua" },
  { name: "gcla/termshark", type: "Terminal", desc: "Terminal Wireshark", url: "https://github.com/gcla/termshark" },
  { name: "brimdata/zui", type: "Desktop", desc: "ZUI — Zeek + Suricata + Zed", url: "https://github.com/brimdata/zui" },
  { name: "brimdata/brimcap", type: "CLI", desc: "PCAP → Zeek + Suricata", url: "https://github.com/brimdata/brimcap" },
  { name: "JuergenMang/f5-tls-decrypt", type: "Script", desc: "F5 TLS 1.3 deşifre otomatik", url: "https://github.com/JuergenMang/f5-tls-decrypt" },
  { name: "LpCodes/TCP-Issues", type: "Rehber", desc: "TCP sorun giderme adımları", url: "https://github.com/LpCodes/Identifying-and-Troubleshooting-Common-TCP-Issues-with-Wireshark" },
  { name: "caesar0301/awesome-pcaptools", type: "Liste", desc: "50+ PCAP aracı kategorili", url: "https://github.com/caesar0301/awesome-pcaptools" },
  { name: "arkime/arkime", type: "Enterprise", desc: "PCAP indexleme + arama", url: "https://github.com/arkime/arkime" },
  { name: "irontec/sngrep", type: "Terminal", desc: "SIP terminal analiz", url: "https://github.com/irontec/sngrep" },
  { name: "zeek/zeek", type: "NSM", desc: "Network Security Monitor", url: "https://github.com/zeek/zeek" },
  { name: "cisagov/Malcolm", type: "Platform", desc: "Zeek+Arkime+Suricata Docker", url: "https://github.com/cisagov/Malcolm" },
  { name: "hgn/captcp", type: "TCP Analiz", desc: "TCP root cause istatistikleri", url: "https://github.com/hgn/captcp" },
  { name: "FoxIO-LLC/ja4", type: "Fingerprint", desc: "Modern JA3 halefi — JA4", url: "https://github.com/FoxIO-LLC/ja4" },
  { name: "vidjinnangni/Cheat-Sheet", type: "Referans", desc: "Kapsamlı cheat sheet", url: "https://github.com/vidjinnangni/Wireshark-Cheat-Sheet" },
  { name: "DhaeyerWolf/ICS-OT", type: "Profil", desc: "SCADA/ICS protokolleri", url: "https://github.com/DhaeyerWolf/ICS-OT_wireshark_profiles" }
];

/* ───────── DATA: WCA-101 ───────── */
const WCA_INFO = {
  name: "Wireshark Certified Analyst (WCA-101)",
  announced: "2 Haziran 2025",
  org: "Wireshark Foundation (nonprofit)",
  founder: "Gerald Combs (Wireshark yaratıcısı)",
  price: "$349 / deneme",
  practice: "$29 practice exam",
  validity: "3 yıl",
  level: "CCNA üstü, enterprise-grade"
};

const WCA_DOMAINS = [
  { num: 1, name: "Paket Yakalama ve Temel Analiz", topics: ["Kurulum", "Interface seçimi", "BPF syntax", "PCAP kaydetme"] },
  { num: 2, name: "Display Filter ve Analiz", topics: ["Filter syntax", "AND/OR/NOT", "Protocol fields", "Expert Info"] },
  { num: 3, name: "Temel Protokol Analizi", topics: ["Ethernet", "IPv4/IPv6", "TCP/UDP", "DNS, DHCP"] },
  { num: 4, name: "TCP Sorun Giderme", topics: ["3-way handshake", "Retransmission", "Zero window", "RST", "Stream Graphs"] },
  { num: 5, name: "Uygulama Protokol Analizi", topics: ["HTTP/HTTPS", "TLS handshake", "DNS", "DHCP"] },
  { num: 6, name: "Statistics ve Görselleştirme", topics: ["Protocol Hierarchy", "Conversations", "IO Graphs", "Flow Graph"] },
  { num: 7, name: "İleri Troubleshooting", topics: ["Root cause analysis", "Enterprise sorunları", "Performans", "Gerçek senaryolar"] }
];

const WCA_PLAN = [
  { weeks: "1-4", level: "TEMEL", topics: "Kurulum, interface, capture filter, display filter syntax, SampleCaptures pratiği, Expert Info" },
  { weeks: "5-8", level: "ORTA", topics: "TCP sorun analizi, TLS handshake, Statistics menüsü, profil sistemi, JA3 plugin" },
  { weeks: "9-12", level: "İLERİ", topics: "ZUI/Brim, F5 TLS deşifre, tshark CLI, practice exam, malware-traffic-analysis, SharkFest" }
];

/* ═══════════════════════════════════════════════════════════════
   INTERACTIVE TOOL STATE
   ═══════════════════════════════════════════════════════════════ */

const builderState = {
  tool: "port",
  saved: JSON.parse(localStorage.getItem("wh-saved-filters") || "[]")
};

const wizardState = {
  step: 1,
  symptom: null,
  protocol: null,
  direction: null
};

const profileState = {
  name: "Fintech-Custom",
  columns: ["no","time","src","dst","proto","len","info"],
  colorRules: [],
  savedFilters: []
};

/* ═══════════════════════════════════════════════════════════════
   FILTER BUILDER — TOOL DEFINITIONS
   ═══════════════════════════════════════════════════════════════ */

const BUILDER_TOOLS = [
  { id: "port",   icon: "🔌", name: "Port Filtresi" },
  { id: "ip",     icon: "🌐", name: "IP Filtresi" },
  { id: "conv",   icon: "💬", name: "Konuşma (IP+Port)" },
  { id: "stream", icon: "🔗", name: "TCP Stream" },
  { id: "time",   icon: "⏱",  name: "Zaman / Süre" },
  { id: "size",   icon: "📏", name: "Paket Boyutu" },
  { id: "http",   icon: "📨", name: "HTTP Detay" },
  { id: "tls",    icon: "🔒", name: "TLS Detay" },
  { id: "combine",icon: "➕", name: "Birleştirici" }
];

/* ═══════════════════════════════════════════════════════════════
   WIZARD — DECISION TREE
   ═══════════════════════════════════════════════════════════════ */

const WIZARD_SYMPTOMS = [
  { id: "no-conn", title: "Bağlantı hiç kurulmuyor", desc: "SYN gönderiliyor ama cevap yok / RST geliyor" },
  { id: "slow",    title: "Bağlantı yavaş",           desc: "Veri akıyor ama beklenenden yavaş" },
  { id: "drop",    title: "Bağlantı kesiliyor",       desc: "Kuruldu ama ortada kesiliyor (timeout)" },
  { id: "error",   title: "Hata kodu dönüyor",        desc: "Yanıt var ama 4xx/5xx veya TLS alert" },
  { id: "voice",   title: "Ses/video sorunu",         desc: "Çağrı kuruldu ama ses yok/kesik" },
  { id: "unknown", title: "Bilmiyorum, genel bakış",  desc: "PCAP'i açtım, ne yapacağımı bilmiyorum" }
];

const WIZARD_PROTOCOLS = [
  { id: "https", name: "HTTPS / TLS" },
  { id: "http",  name: "HTTP (düz)" },
  { id: "sip",   name: "SIP / VoIP" },
  { id: "tcp",   name: "TCP (genel)" },
  { id: "other", name: "Fark etmez / bilmiyorum" }
];

const WIZARD_RESULTS = {
  // Symptom + Protocol kombinasyonları
  "no-conn/https": {
    title: "HTTPS Bağlantı Kurulamıyor",
    hint: "TLS handshake'in hangi adımda durduğunu bul. Client Hello → Server Hello → Certificate → Finished sırasını kontrol et.",
    filters: [
      { code: "tls.handshake.type == 1", desc: "Client Hello gönderildi mi?" },
      { code: "tls.handshake.type == 2", desc: "Server Hello geldi mi?" },
      { code: "tls.alert_message", desc: "TLS Alert (hata) var mı?" },
      { code: "tcp.flags.reset == 1", desc: "Yolda RST geliyor mu?" },
      { code: "tcp.flags.syn == 1 && tcp.flags.ack == 0", desc: "SYN ulaştı mı?" }
    ],
    steps: [
      "Önce TCP handshake tamamlanmış mı kontrol et (SYN → SYN-ACK → ACK)",
      "TCP handshake OK ise, tls.handshake.type == 1 (Client Hello) filtrele",
      "Server Hello geldiyse hangi cipher seçildiğine bak",
      "Server Hello gelmediyse cipher uyumsuzluğu var — F5/sunucu cipher profilini kontrol et",
      "tls.alert_message varsa alert kodunu not et (40=handshake_failure, 46=cert_unknown, 48=unknown_ca)"
    ]
  },
  "no-conn/http": {
    title: "HTTP Bağlantı Kurulamıyor",
    hint: "TCP katmanında takılı kalmış olabilir — SYN/SYN-ACK/ACK akışını izle.",
    filters: [
      { code: "tcp.flags.syn == 1 && tcp.flags.ack == 0", desc: "SYN gönderildi mi?" },
      { code: "tcp.flags.syn == 1 && tcp.flags.ack == 1", desc: "SYN-ACK geldi mi?" },
      { code: "tcp.flags.reset == 1", desc: "RST var mı?" },
      { code: "icmp", desc: "ICMP unreachable mesajı var mı?" }
    ],
    steps: [
      "SYN paketi görünüyorsa client isteği yolluyor demektir",
      "SYN-ACK gelmiyorsa → firewall drop / sunucu down / port kapalı",
      "SYN-ACK geliyor ama ACK sonrası RST varsa → uygulama reject",
      "ICMP unreachable varsa → routing sorunu"
    ]
  },
  "no-conn/sip": {
    title: "SIP Bağlantısı Kurulmuyor",
    hint: "SIP REGISTER veya INVITE yanıtlarını incele.",
    filters: [
      { code: 'sip.Method == "REGISTER"', desc: "SIP kayıt denemesi" },
      { code: 'sip.Method == "INVITE"', desc: "Arama başlatma" },
      { code: "sip.Status-Code >= 400", desc: "SIP hata yanıtları" },
      { code: "sip.Status-Code == 401", desc: "Credential sorunu" },
      { code: "sip.Status-Code == 403", desc: "IP yasaklı" }
    ],
    steps: [
      "SIP REGISTER istekleri gidiyor mu?",
      "Yanıt geliyor mu? 401 → normal (auth challenge), 403 → IP block",
      "INVITE gönderiliyor mu?",
      "100 Trying → 180 Ringing → 200 OK sırası tamamlanıyor mu?"
    ]
  },
  "no-conn/tcp": {
    title: "TCP Bağlantı Kurulamıyor",
    hint: "Handshake'in hangi adımda takıldığını bul.",
    filters: [
      { code: "tcp.flags.syn == 1 && tcp.flags.ack == 0", desc: "SYN" },
      { code: "tcp.flags.syn == 1 && tcp.flags.ack == 1", desc: "SYN-ACK" },
      { code: "tcp.flags.reset == 1", desc: "RST" },
      { code: "tcp.analysis.retransmission", desc: "Retransmitted SYN" }
    ],
    steps: [
      "SYN gönderiliyor mu? SYN yok → capture yanlış noktada",
      "SYN-ACK gelmiyor → firewall/routing/sunucu down",
      "SYN retransmit ediliyor → cevap yok, paket kaybı",
      "RST geliyor → port kapalı veya uygulama reject"
    ]
  },
  "slow/https": {
    title: "HTTPS Yavaş",
    hint: "TLS deşifre gerekli. Sonrasında HTTP response time'a bak.",
    filters: [
      { code: "http.time > 5", desc: "5sn+ yanıt süresi" },
      { code: 'http2.headers.status >= "500"', desc: "HTTP/2 5xx hatalar" },
      { code: "tcp.analysis.retransmission", desc: "Paket kaybı" },
      { code: "tcp.analysis.zero_window", desc: "Backend tamponu dolu" },
      { code: "tcp.analysis.rto", desc: "RTO olayları" }
    ],
    steps: [
      "TLS deşifre edildi mi? Edilmediyse http.time göremezsin",
      "Statistics → Service Response Time → HTTP ile min/max/avg bak",
      "Statistics → TCP Stream Graphs → Round Trip Time",
      "Retransmission varsa path paket kaybı var",
      "Zero window varsa backend yavaş tüketiyor"
    ]
  },
  "slow/tcp": {
    title: "TCP Yavaş",
    hint: "Window, RTT ve retransmission'a odaklan.",
    filters: [
      { code: "tcp.analysis.retransmission", desc: "Yeniden iletim" },
      { code: "tcp.analysis.zero_window", desc: "Zero Window" },
      { code: "tcp.analysis.duplicate_ack", desc: "Duplicate ACK" },
      { code: "tcp.window_size_value < 1000", desc: "Küçük window" },
      { code: "tcp.analysis.rto", desc: "RTO" }
    ],
    steps: [
      "Statistics → TCP Stream Graphs → Time-Sequence (tcptrace) aç",
      "Düz yatay çizgi → zero window veya app yavaş okuyor",
      "Geriye giden adım → retransmission",
      "Round Trip Time grafiği ile gecikme kaynağını belirle",
      "Window Scaling grafiği ile window büyüklüğü kontrol et"
    ]
  },
  "drop/https": {
    title: "HTTPS Bağlantısı Kesiliyor (Timeout)",
    hint: "RST kaynağı ve idle time kontrolü yap.",
    filters: [
      { code: "tcp.time_delta > 60", desc: "60sn+ sessizlik" },
      { code: "tcp.flags.reset == 1", desc: "RST paketleri" },
      { code: "tcp.analysis.keep_alive", desc: "Keepalive probe" },
      { code: "tls.alert_message", desc: "TLS close alert" }
    ],
    steps: [
      "tcp.time_delta > 60 ile sessizliği bul",
      "Sessizlik sonrası RST geldiyse ip.src'ye bak → kim kesti?",
      "F5 IP'sinden RST → idle timeout",
      "Backend IP'sinden RST → uygulama socket kapatıyor",
      "tmsh modify ltm virtual <vs> idle-timeout 300 (F5)"
    ]
  },
  "drop/tcp": {
    title: "TCP Bağlantısı Kesiliyor",
    hint: "Idle timeout en yaygın neden. RST kaynağını belirle.",
    filters: [
      { code: "tcp.time_delta > 60", desc: "60sn+ sessizlik" },
      { code: "tcp.flags.reset == 1", desc: "RST" },
      { code: "tcp.analysis.keep_alive", desc: "Keepalive" },
      { code: "tcp.flags.fin == 1", desc: "FIN (düzgün kapanış)" }
    ],
    steps: [
      "Önce idle time bul (tcp.time_delta > 60)",
      "Sonra RST/FIN hangisi geldi?",
      "FIN → uygulama düzgün kapatıyor",
      "RST + F5'ten → idle timeout",
      "RST + backend'den → app timeout"
    ]
  },
  "error/https": {
    title: "HTTPS Hata Kodu Dönüyor",
    hint: "TLS deşifre yap, sonra HTTP status'larına bak.",
    filters: [
      { code: "http.response.code >= 500", desc: "5xx sunucu hataları" },
      { code: "http.response.code == 503", desc: "Pool member down" },
      { code: "http.response.code == 504", desc: "F5 timeout" },
      { code: "tls.alert_message", desc: "TLS alert" },
      { code: 'http2.headers.status >= "500"', desc: "HTTP/2 5xx" }
    ],
    steps: [
      "TLS deşifre yapıldı mı?",
      "http.response.code ile hata kodunu filtrele",
      "503 → F5 pool member down (health monitor kontrol)",
      "504 → F5 server-timeout (backend yanıt vermiyor)",
      "500 → backend uygulamasında hata, App ekibine"
    ]
  },
  "error/http": {
    title: "HTTP Hata Kodu",
    hint: "Status code → kök neden eşleşmesi.",
    filters: [
      { code: "http.response.code >= 400", desc: "Tüm hatalar" },
      { code: "http.response.code == 404", desc: "Not Found" },
      { code: "http.response.code == 403", desc: "WAF block?" },
      { code: "http.response.code == 429", desc: "Rate limit" },
      { code: "http.response.code >= 500", desc: "Sunucu hataları" }
    ],
    steps: [
      "Yanıt kodunu belirle",
      "404 → URI yanlış, rewrite rule kontrol",
      "403 → F5 ASM/WAF block olabilir",
      "429 → rate limit, client çok hızlı",
      "5xx → backend sorunu"
    ]
  },
  "error/sip": {
    title: "SIP Hata Yanıtları",
    hint: "SIP status kodlarını incele, ladder diagram aç.",
    filters: [
      { code: "sip.Status-Code >= 400", desc: "Tüm hatalar" },
      { code: "sip.Status-Code == 401", desc: "Auth" },
      { code: "sip.Status-Code == 403", desc: "Forbidden" },
      { code: "sip.Status-Code == 404", desc: "Not Found" },
      { code: "sip.Status-Code == 503", desc: "Service unavailable" }
    ],
    steps: [
      "Telephony → VoIP Calls aç",
      "Çağrıyı seç → Flow butonu → Ladder diagram",
      "Hangi mesajdan sonra hata döndü?",
      "Status koduna göre aksiyon al (dokümandaki SIP tablosu)"
    ]
  },
  "voice/sip": {
    title: "Ses Sorunu (SIP + RTP)",
    hint: "SDP'deki IP adresi ve RTP akışı kalitesi kritik.",
    filters: [
      { code: "sdp", desc: "SDP IP adresi analizi" },
      { code: "rtp", desc: "RTP ses paketleri" },
      { code: "rtcp", desc: "RTCP kontrol" },
      { code: "sip.Method == \"INVITE\"", desc: "INVITE (SDP içerir)" }
    ],
    steps: [
      "Statistics → RTP → RTP Streams → Analyze aç",
      "Max delta < 50ms, jitter < 20ms, loss < 1% normaldir",
      "Tek yönlü ses → NAT / routing sorunu",
      "SDP'de private IP görünüyorsa → SIP ALG / SNAT kontrol",
      "RTP paketi hiç yok → UDP 10000-20000 firewall block"
    ]
  },
  "slow/http": {
    title: "HTTP Yavaş",
    hint: "TLS yok, direkt http.time kullanılabilir. Statistics → Service Response Time'a bak.",
    filters: [
      { code: "http.time > 5", desc: "5sn+ yanıt" },
      { code: "http.response.code >= 500", desc: "Sunucu hataları" },
      { code: "tcp.analysis.retransmission", desc: "Paket kaybı" },
      { code: "tcp.analysis.zero_window", desc: "Backend tamponu dolu" }
    ],
    steps: [
      "Statistics → Service Response Time → HTTP — min/max/avg gör",
      "http.time > 5 ile yavaş istekleri bul",
      "Yavaş isteklerin pattern'i ne? (saat, endpoint, client)",
      "TCP düzeyinde retrans/zero window var mı kontrol et"
    ]
  },
  "slow/sip": {
    title: "SIP Kurulumu Yavaş",
    hint: "INVITE → 180/200 arası süreyi ölç. Registrar/proxy yavaşlığı olabilir.",
    filters: [
      { code: 'sip.Method == "INVITE"', desc: "INVITE paketleri" },
      { code: "sip.Status-Code == 100", desc: "Trying yanıtı (server aldı mı?)" },
      { code: "sip.Status-Code == 180", desc: "Ringing — telefon çalıyor" },
      { code: "sip.Status-Code == 200", desc: "Cevaplandı" }
    ],
    steps: [
      "Telephony → VoIP Calls → çağrıyı seç → Flow (ladder)",
      "INVITE → 100 Trying arası süre (< 200ms normal)",
      "180 → 200 arası kullanıcı cevap süresi (kontrol dışı)",
      "100 yok ama 180 var → proxy provisional response atlıyor",
      "Hiç yanıt yok → SIP proxy timeout, network path sorunu"
    ]
  },
  "drop/http": {
    title: "HTTP Bağlantı Mid-stream Kesiliyor",
    hint: "F5 idle timeout veya backend connection close.",
    filters: [
      { code: "http.response.code", desc: "Son gelen response" },
      { code: "tcp.flags.reset == 1", desc: "RST paketleri" },
      { code: "tcp.flags.fin == 1", desc: "FIN (düzgün kapanış)" },
      { code: "tcp.time_delta > 30", desc: "30sn+ sessizlik" }
    ],
    steps: [
      "Son HTTP response başarılı mı?",
      "Ardından RST mi FIN mi geliyor?",
      "RST kaynağı kim? ip.src'ye bak",
      "Connection: close header var mı HTTP response'da?",
      "F5 idle-timeout default 300sn — daha kısa olabilir mi?"
    ]
  },
  "drop/sip": {
    title: "SIP Çağrı Ortada Kesiliyor",
    hint: "BYE paketi mi gelir, RTP akışı mı durur kontrol et.",
    filters: [
      { code: 'sip.Method == "BYE"', desc: "Normal kapanış" },
      { code: "sip.Status-Code == 481", desc: "Call Leg Does Not Exist" },
      { code: "rtp", desc: "RTP akışı" },
      { code: "rtcp", desc: "RTCP kalite raporları" }
    ],
    steps: [
      "BYE geldi mi? Kim gönderdi? — normal kapanış",
      "BYE yok ama çağrı kesildi → network disconnect",
      "RTP akışı aniden durdu mu? Statistics → RTP → RTP Streams",
      "UDP paket kaybı var mı? Firewall UDP timeout?"
    ]
  },
  "drop/http": {
    title: "HTTP Bağlantısı Kesiliyor",
    hint: "TCP düzeyinde idle timeout veya app-level disconnect.",
    filters: [
      { code: "tcp.time_delta > 30", desc: "30sn+ sessizlik" },
      { code: "tcp.flags.reset == 1", desc: "RST paketleri" },
      { code: 'http.connection == "close"', desc: "Server connection close" }
    ],
    steps: [
      "Son veri alışverişinden sonra ne kadar geçti?",
      "RST kimden geldi? (F5/backend/client)",
      "HTTP Connection: close header'ı var mı? (Server tarafı kapatmak istiyor)"
    ]
  },
  "error/tcp": {
    title: "TCP Düzeyi Anomali",
    hint: "TCP layer'da Expert Info'ya odaklan.",
    filters: [
      { code: 'expert.severity == "Error"', desc: "Tüm TCP error'ları" },
      { code: "tcp.analysis.flags", desc: "TCP analysis anomalileri" },
      { code: "tcp.checksum.status == 2", desc: "Bad checksum (capture offload sorunu)" }
    ],
    steps: [
      "Analyze → Expert Information",
      "Error ve Warning kategorilerine bak",
      "Her uyarı için ilgili pakete git, context incele",
      "Bad checksum → NIC offload açık demektir, yanıltıcı"
    ]
  },
  "voice/tcp": {
    title: "Ses/Video TCP Üzerinden Sorunlu",
    hint: "Genelde ses UDP/RTP olur. TCP üzerinden ise MSRP/RTSP olabilir.",
    filters: [
      { code: "tcp.port == 554", desc: "RTSP" },
      { code: "tcp.port == 2855", desc: "MSRP" },
      { code: "tcp.analysis.retransmission", desc: "Retrans (ses bozulur)" }
    ],
    steps: [
      "Hangi port/protokol kullanılıyor?",
      "TCP üzerinden medya → retrans = buffer underrun = ses bozulur",
      "UDP'ye geçme imkanı var mı?"
    ]
  },
  "voice/other": {
    title: "Ses/Video Sorunu (Genel)",
    hint: "RTP paket kaybı, jitter, gecikme kontrol et.",
    filters: [
      { code: "rtp", desc: "RTP paketleri" },
      { code: "rtp.p_type", desc: "Codec tipi" },
      { code: "rtcp", desc: "Kalite raporları" },
      { code: "sdp", desc: "Codec negotiation" }
    ],
    steps: [
      "Statistics → RTP → RTP Streams → Analyze",
      "Max delta (gecikme spike) kontrol et",
      "Jitter, packet loss değerlerine bak",
      "Hem gelen hem giden stream var mı?"
    ]
  },
  "unknown/https": {
    title: "HTTPS PCAP'inde Ne Var — Genel Bakış",
    hint: "TLS deşifre mümkün mü önce ona bak.",
    filters: [
      { code: "tls.handshake", desc: "TLS handshake paketleri" },
      { code: "tls.alert_message", desc: "TLS hataları" },
      { code: "tcp.flags.reset == 1", desc: "RST'ler" }
    ],
    steps: [
      "Statistics → Protocol Hierarchy — TLS oranı",
      "TLS handshake'ler başarılı mı? (type == 20 var mı)",
      "TLS deşifre yaparsan daha fazla şey görürsün",
      "Deşifre edilemiyorsa en azından cert/SNI'ye bak"
    ]
  },
  "unknown/http": {
    title: "HTTP PCAP'inde Ne Var",
    hint: "Status code dağılımı ve response time'a bak.",
    filters: [
      { code: "http", desc: "Tüm HTTP" },
      { code: "http.request", desc: "İstekler" },
      { code: "http.response", desc: "Yanıtlar" }
    ],
    steps: [
      "Statistics → HTTP → Requests tree",
      "Status code dağılımı nasıl?",
      "Hangi URI'lere en çok istek geliyor?",
      "Response time dağılımı?"
    ]
  },
  "unknown/sip": {
    title: "SIP PCAP'inde Ne Var",
    hint: "VoIP Calls panelinden başla.",
    filters: [
      { code: "sip", desc: "Tüm SIP" },
      { code: "rtp", desc: "Ses akışları" }
    ],
    steps: [
      "Telephony → VoIP Calls → çağrı listesi",
      "Her çağrıyı seç → Flow (ladder diagram)",
      "Başarılı/başarısız oranı nedir?",
      "RTP Streams'e bak — ses kalitesi nasıl?"
    ]
  },
  "unknown/tcp": {
    title: "TCP Trafiği Genel Bakış",
    hint: "Conversations + TCP Stream Graphs'tan başla.",
    filters: [
      { code: "tcp", desc: "Tüm TCP" },
      { code: "tcp.analysis.flags", desc: "Anomaliler" }
    ],
    steps: [
      "Statistics → Conversations → TCP tab",
      "Bytes'a göre sırala — en büyük konuşmalar",
      "Her konuşmaya bak: süre, byte, paket",
      "Anomali var mı? Expert Info"
    ]
  },
  "unknown/other": {
    title: "Genel PCAP Triage (Jasper Bongertz 5-step)",
    hint: "Nereden başlayacağını bilmiyorsan bu 5 adımı sırayla uygula.",
    filters: [
      { code: "tcp.analysis.flags && !tcp.analysis.window_update", desc: "Tüm TCP sorunları" },
      { code: "expert.severity == \"Error\"", desc: "Tüm hatalar" },
      { code: "http.response.code >= 400", desc: "HTTP hataları" },
      { code: "tls.alert_message", desc: "TLS hataları" }
    ],
    steps: [
      "Statistics → Capture File Properties — süre, boyut, paket sayısı",
      "Statistics → Protocol Hierarchy — trafik neden oluşuyor?",
      "Statistics → Conversations — Bytes'a sırala, en büyük konuşma kim?",
      "Analyze → Expert Information — Error/Warning'e bak",
      "Statistics → I/O Graphs — sorun zamansal olarak nerede?"
    ]
  }
};

/* ═══════════════════════════════════════════════════════════════
   PROFILE BUILDER DATA
   ═══════════════════════════════════════════════════════════════ */

const PROFILE_COLUMNS = [
  { id: "no",       label: "Paket No",      field: "%m" },
  { id: "time",     label: "Zaman",         field: "%Yt" },
  { id: "delta",    label: "Delta Time",    field: "%Cus:tcp.time_delta" },
  { id: "src",      label: "Kaynak IP",     field: "%s" },
  { id: "srcp",     label: "Kaynak Port",   field: "%uS" },
  { id: "dst",      label: "Hedef IP",      field: "%d" },
  { id: "dstp",     label: "Hedef Port",    field: "%uD" },
  { id: "proto",    label: "Protokol",      field: "%p" },
  { id: "len",      label: "Uzunluk",       field: "%L" },
  { id: "httpstat", label: "HTTP Status",   field: "%Cus:http.response.code" },
  { id: "httpuri",  label: "HTTP URI",      field: "%Cus:http.request.uri" },
  { id: "tlsver",   label: "TLS Versiyon",  field: "%Cus:tls.handshake.version" },
  { id: "info",     label: "Info",          field: "%i" }
];

const PROFILE_COLORS = [
  { id: "tcp-rst",     label: "TCP Reset",         filter: "tcp.flags.reset == 1",           bg: "ff6b6b", fg: "000000" },
  { id: "tcp-retrans", label: "TCP Retransmission",filter: "tcp.analysis.retransmission",    bg: "f39c12", fg: "000000" },
  { id: "tcp-zwin",    label: "Zero Window",       filter: "tcp.analysis.zero_window",       bg: "e74c3c", fg: "ffffff" },
  { id: "http-5xx",    label: "HTTP 5xx",          filter: "http.response.code >= 500",      bg: "ff6b6b", fg: "000000" },
  { id: "http-4xx",    label: "HTTP 4xx",          filter: "http.response.code >= 400 && http.response.code < 500", bg: "ffa500", fg: "000000" },
  { id: "tls-alert",   label: "TLS Alert",         filter: "tls.alert_message",              bg: "9b59b6", fg: "ffffff" },
  { id: "sip-err",     label: "SIP Errors",        filter: "sip.Status-Code >= 400",         bg: "ff8c00", fg: "000000" },
  { id: "http-slow",   label: "HTTP Yavaş (>10s)", filter: "http.time > 10",                 bg: "ffcc00", fg: "000000" },
  { id: "tcp-dup",     label: "Duplicate ACK",     filter: "tcp.analysis.duplicate_ack",     bg: "ffd700", fg: "000000" }
];

const PROFILE_SAVED_FILTERS = [
  { id: "f5-all-err",   label: "F5 All Errors",  filter: "http.response.code >= 500 || sip.Status-Code >= 400" },
  { id: "tcp-problems", label: "TCP Problems",   filter: "tcp.analysis.flags && !tcp.analysis.window_update" },
  { id: "timeout-60s",  label: "Timeout 60s",    filter: "tcp.time_delta > 60" },
  { id: "tls-issues",   label: "TLS Issues",     filter: "tls.alert_message" },
  { id: "sip-errors",   label: "SIP Errors",     filter: "sip.Status-Code >= 400" },
  { id: "rst-packets",  label: "RST Packets",    filter: "tcp.flags.reset == 1" },
  { id: "http-5xx",     label: "HTTP 5xx",       filter: "http.response.code >= 500" },
  { id: "retrans",      label: "Retransmissions",filter: "tcp.analysis.retransmission" }
];

/* ═══════════════════════════════════════════════════════════════
   TSHARK BUILDER DATA
   ═══════════════════════════════════════════════════════════════ */

const tsharkState = {
  input: "cap.pcap",
  filter: "",
  mode: "fields",
  fields: ["frame.time","ip.src","ip.dst","tcp.srcport","tcp.dstport"],
  stat: "",
  keylog: "",
  output: "",
  extra: ""
};

const TSHARK_FIELDS = [
  { id: "frame.time", label: "Zaman" },
  { id: "frame.number", label: "Paket No" },
  { id: "ip.src", label: "Kaynak IP" },
  { id: "ip.dst", label: "Hedef IP" },
  { id: "tcp.srcport", label: "TCP Src Port" },
  { id: "tcp.dstport", label: "TCP Dst Port" },
  { id: "udp.srcport", label: "UDP Src Port" },
  { id: "udp.dstport", label: "UDP Dst Port" },
  { id: "tcp.stream", label: "TCP Stream" },
  { id: "tcp.flags", label: "TCP Flags" },
  { id: "tcp.window_size_value", label: "TCP Window" },
  { id: "tcp.time_delta", label: "TCP Delta" },
  { id: "http.host", label: "HTTP Host" },
  { id: "http.request.uri", label: "HTTP URI" },
  { id: "http.request.method", label: "HTTP Method" },
  { id: "http.response.code", label: "HTTP Status" },
  { id: "http.user_agent", label: "User-Agent" },
  { id: "http.time", label: "HTTP Response Time" },
  { id: "tls.handshake.type", label: "TLS Handshake Type" },
  { id: "tls.handshake.version", label: "TLS Version" },
  { id: "tls.alert_message.desc", label: "TLS Alert" },
  { id: "tls.handshake.extensions_server_name", label: "TLS SNI" },
  { id: "sip.Method", label: "SIP Method" },
  { id: "sip.Status-Code", label: "SIP Status" },
  { id: "sip.From.user", label: "SIP From User" },
  { id: "sip.To.user", label: "SIP To User" },
  { id: "dns.qry.name", label: "DNS Query" },
  { id: "dns.flags.rcode", label: "DNS Rcode" },
  { id: "frame.len", label: "Paket Uzunluğu" },
  { id: "_ws.col.info", label: "Info Kolonu" }
];

const TSHARK_STATS = [
  { id: "", label: "Yok" },
  { id: "io,phs", label: "Protocol Hierarchy" },
  { id: "io,stat,1", label: "IO Stat (1sn)" },
  { id: "io,stat,0.1", label: "IO Stat (100ms)" },
  { id: "conv,tcp", label: "TCP Conversations" },
  { id: "conv,ip", label: "IP Conversations" },
  { id: "endpoints,tcp", label: "TCP Endpoints" },
  { id: "http,tree", label: "HTTP Tree" },
  { id: "http,stat,", label: "HTTP Stat" },
  { id: "dns,tree", label: "DNS Tree" },
  { id: "sip,stat", label: "SIP Stat" },
  { id: "rtp,streams", label: "RTP Streams" },
  { id: "expert", label: "Expert Info" }
];

const TSHARK_PRESETS = [
  { name: "HTTP 5xx Hataları", preset: { filter: "http.response.code >= 500", mode: "fields", fields: ["frame.time","ip.src","ip.dst","http.host","http.request.uri","http.response.code"] } },
  { name: "TLS Alert'leri", preset: { filter: "tls.alert_message", mode: "fields", fields: ["frame.time","ip.src","ip.dst","tls.alert_message.desc","tls.handshake.extensions_server_name"] } },
  { name: "TCP Retransmission Zaman Grafiği", preset: { filter: "", mode: "stat", stat: "io,stat,1", fields: [] } },
  { name: "SIP Hataları", preset: { filter: "sip.Status-Code >= 400", mode: "fields", fields: ["frame.time","ip.src","sip.Method","sip.Status-Code","sip.From.user","sip.To.user"] } },
  { name: "DNS Hata Yanıtları", preset: { filter: "dns.flags.rcode != 0", mode: "fields", fields: ["frame.time","ip.src","dns.qry.name","dns.flags.rcode"] } },
  { name: "TCP Zero Window", preset: { filter: "tcp.analysis.zero_window", mode: "fields", fields: ["frame.time","ip.src","ip.dst","tcp.srcport","tcp.dstport","tcp.window_size_value"] } },
  { name: "F5 TLS Key Export", preset: { filter: "f5ethtrailer.tls.keylog", mode: "fields-nh", fields: ["f5ethtrailer.tls.keylog"] } },
  { name: "Protocol Hierarchy", preset: { filter: "", mode: "stat", stat: "io,phs" } },
  { name: "Expert Info Özeti", preset: { filter: "", mode: "stat", stat: "expert" } }
];

/* ═══════════════════════════════════════════════════════════════
   PCAP BUILDER DATA (tcpdump)
   ═══════════════════════════════════════════════════════════════ */

const pcapState = {
  platform: "f5",
  iface: "0.0:nnnp",
  host1: "10.0.0.1",
  host1Type: "host",
  host2: "",
  host2Type: "and",
  port: "",
  portType: "",
  snaplen: "0",
  ringSize: "",
  ringCount: "",
  timeLimit: "",
  output: "/var/tmp/cap.pcap",
  sslprovider: false,
  verbose: false
};

const PCAP_PLATFORMS = [
  { id: "f5",       name: "F5 BIG-IP",   iface: "0.0:nnnp", outPath: "/var/tmp/cap.pcap" },
  { id: "fortinet", name: "FortiGate",   iface: "wan1",     outPath: "" },
  { id: "checkpoint", name: "Check Point", iface: "eth1",   outPath: "/var/log/dump/cap.pcap" },
  { id: "linux",    name: "Linux (Genel)",iface: "eth0",    outPath: "/tmp/cap.pcap" }
];

/* ═══════════════════════════════════════════════════════════════
   CHECKLIST DATA
   ═══════════════════════════════════════════════════════════════ */

const CHECKLIST_CATEGORIES = [
  { id: "general",   icon: "🎯", name: "Genel PCAP Triage", desc: "İlk 5 dakikada bakılacaklar" },
  { id: "tcp",       icon: "🔗", name: "TCP Sorun Kontrolü", desc: "Handshake, retrans, window" },
  { id: "tls",       icon: "🔒", name: "TLS/HTTPS Kontrolü", desc: "Handshake, alert, sertifika" },
  { id: "http",      icon: "📨", name: "HTTP Analizi",      desc: "Status, response time, headers" },
  { id: "sip",       icon: "📞", name: "SIP/VoIP Kontrolü", desc: "Signalling + RTP kalite" },
  { id: "performance", icon: "⚡", name: "Performans",        desc: "Gecikme, throughput, paket kaybı" }
];

const CHECKLIST = {
  general: [
    { id: "cap-props", q: "Capture File Properties'e baktın mı?", how: "Statistics → Capture File Properties", why: "Süre, paket sayısı, interface adı, drop sayısı — baseline bilgisi" },
    { id: "proto-hier", q: "Protocol Hierarchy kontrol ettin mi?", how: "Statistics → Protocol Hierarchy", why: "Trafiğin %kaçı TLS/HTTP/SIP? Beklenmedik protokol var mı?" },
    { id: "convs", q: "Conversations panelini açtın mı?", how: "Statistics → Conversations → Bytes'a göre sırala", why: "En büyük konuşmacıyı bul, outlier'a odaklan" },
    { id: "expert", q: "Expert Info'ya baktın mı?", how: "Analyze → Expert Information", why: "Wireshark'ın otomatik tespit ettiği sorunlar burada" },
    { id: "io-graph", q: "IO Graph çizdin mi?", how: "Statistics → I/O Graphs", why: "Sorun zaman içinde nerede? Pattern/spike var mı?" },
    { id: "baseline", q: "İyi bir PCAP ile karşılaştırdın mı?", how: "Aynı akış için 'iyi' zamanda alınmış PCAP", why: "Baseline olmadan 'normal mi değil mi' anlayamazsın" },
    { id: "capture-point", q: "Capture doğru noktada mı alınmış?", how: "Client-side mı, F5-side mı, backend-side mı?", why: "Yanlış noktada capture → eksik bilgi → yanlış tanı" },
    { id: "timestamp", q: "Timestamp'ler senkron mu?", how: "Birden fazla PCAP varsa NTP sync kontrol et", why: "Zaman farkı varsa korelasyon yanlış olur" }
  ],
  tcp: [
    { id: "handshake", q: "3-way handshake tamamlandı mı?", how: "Filter: tcp.flags.syn == 1 then inspect: SYN → SYN-ACK → ACK", why: "Eksikse bağlantı hiç kurulmamış demektir" },
    { id: "syn-only", q: "SYN var ama SYN-ACK yok mu?", how: "Filter: tcp.flags.syn == 1 && tcp.flags.ack == 0", why: "Firewall drop / sunucu down / port kapalı göstergesi" },
    { id: "rst", q: "RST paketi var mı, kimden?", how: "Filter: tcp.flags.reset == 1 ve ip.src'ye bak", why: "RST kaynağı sorunu kimin yarattığını söyler (F5 mı, backend mi, client mı?)" },
    { id: "retrans", q: "Retransmission var mı, ne kadar?", how: "Filter: tcp.analysis.retransmission + Statistics → IO Graph overlay", why: "%1+ paket kaybı sorun demektir — path veya cihaz" },
    { id: "dup-ack", q: "Duplicate ACK spike'ları var mı?", how: "Filter: tcp.analysis.duplicate_ack", why: "Kayıp paket sinyali — 3 DupACK sonrası fast retransmission" },
    { id: "zero-win", q: "Zero Window olayı var mı?", how: "Filter: tcp.analysis.zero_window", why: "Alıcı tamponu dolu — backend yavaş işliyor/hung" },
    { id: "idle", q: "60sn+ sessizlik var mı?", how: "Filter: tcp.time_delta > 60", why: "Idle timeout şüphesi — F5/FortiGate default 300sn" },
    { id: "keepalive", q: "Keepalive probe görüyor musun?", how: "Filter: tcp.analysis.keep_alive", why: "Bağlantı kurulu ama veri akmıyor göstergesi" },
    { id: "tcp-graph", q: "TCP Stream Graph inceledin mi?", how: "Paket seç → Statistics → TCP Stream Graphs → Time-Sequence (tcptrace)", why: "Düz çizgi = stuck, geri adım = retrans, eğim = throughput" },
    { id: "rtt", q: "RTT makul mü?", how: "Statistics → TCP Stream Graphs → Round Trip Time", why: "100ms+ RTT genelde path latency veya congestion" }
  ],
  tls: [
    { id: "tcp-first", q: "Önce TCP handshake tamamlandı mı?", how: "Filter: tcp.flags.syn == 1", why: "TCP OK değilse TLS başlayamaz" },
    { id: "client-hello", q: "Client Hello gönderildi mi?", how: "Filter: tls.handshake.type == 1", why: "TLS handshake'in ilk adımı — yoksa client TLS başlatmıyor" },
    { id: "server-hello", q: "Server Hello geldi mi?", how: "Filter: tls.handshake.type == 2", why: "Cipher/versiyon uyumsuzsa sunucu Hello göndermez" },
    { id: "cert", q: "Sertifika gönderildi mi?", how: "Filter: tls.handshake.type == 11", why: "Server Hello sonrası gelir, zincir kontrolü için şart" },
    { id: "alert", q: "TLS Alert var mı?", how: "Filter: tls.alert_message", why: "Handshake hatasının kesin göstergesi — alert koduna bak" },
    { id: "version", q: "TLS versiyonu doğru mu?", how: "Filter: tls.record.version", why: "Eski (1.0/1.1) güvenlik riski, 1.3 yeni özellikler" },
    { id: "cipher-match", q: "Cipher uyumu var mı?", how: "Client Hello cipher list vs Server Hello selected cipher", why: "Uyumsuzluk handshake_failure (Alert 40) sebebidir" },
    { id: "sni", q: "SNI doğru mu?", how: "Filter: tls.handshake.extensions_server_name", why: "SNI yanlış → yanlış sertifika → unknown_ca (Alert 48)" },
    { id: "cert-expiry", q: "Sertifika geçerli mi?", how: "Certificate paketini incele, valid-to tarihi", why: "Expired cert → Alert 45 (certificate_expired)" },
    { id: "finished", q: "Handshake tamamlandı mı?", how: "Filter: tls.handshake.type == 20", why: "Finished mesajı gelirse oturum kurulmuş demektir" }
  ],
  http: [
    { id: "tls-decrypt", q: "TLS deşifre yapıldı mı?", how: "Preferences → TLS → keylog file ayarla", why: "HTTPS trafiğine 'http' filtresi çalışmaz, deşifre şart" },
    { id: "status-codes", q: "Hangi HTTP status kodları dönüyor?", how: "Filter: http.response.code", why: "2xx normal, 4xx client hatası, 5xx sunucu hatası" },
    { id: "5xx", q: "5xx hataları var mı?", how: "Filter: http.response.code >= 500", why: "503 = pool down, 504 = backend timeout, 500 = app error" },
    { id: "response-time", q: "Yanıt süresi ne kadar?", how: "Filter: http.time > 5 veya Statistics → Service Response Time → HTTP", why: "5sn+ normal değil, root cause bulunmalı" },
    { id: "method", q: "Hangi method'lar kullanılıyor?", how: "Filter: http.request.method", why: "POST/PUT payload kontrolü, OPTIONS preflight" },
    { id: "host-header", q: "Host header doğru mu?", how: "Filter: http.host", why: "F5 host header bazlı routing yapıyorsa kritik" },
    { id: "uri-pattern", q: "URI pattern anlamlı mı?", how: "Filter: http.request.uri", why: "Rewrite rule veya routing sorunu için" },
    { id: "large-response", q: "Response boyutları normal mi?", how: "Statistics → HTTP → Packet Counter", why: "Anormal büyük response backend leak olabilir" }
  ],
  sip: [
    { id: "sip-traffic", q: "SIP trafiği var mı?", how: "Filter: sip", why: "Capture doğru portta mı? (genelde UDP/TCP 5060)" },
    { id: "invite", q: "INVITE gönderiliyor mu?", how: "Filter: sip.Method == 'INVITE'", why: "Arama başlatma mesajı — yoksa client istek yollamıyor" },
    { id: "register", q: "SIP REGISTER sorunlu mu?", how: "Filter: sip.Method == 'REGISTER'", why: "Kayıt başarısızsa hiçbir çağrı yapılamaz" },
    { id: "status-codes", q: "SIP status kodları ne?", how: "Filter: sip.Status-Code >= 400", why: "401 auth, 403 IP block, 404 no route, 486 busy" },
    { id: "flow", q: "VoIP Calls paneli incelendin mi?", how: "Telephony → VoIP Calls → çağrıyı seç → Flow", why: "Ladder diyagramı hata noktasını görsel gösterir" },
    { id: "sdp-ip", q: "SDP'de IP adresi doğru mu?", how: "Filter: sdp → c= satırına bak", why: "Private IP görünürse NAT sorunu" },
    { id: "rtp-flow", q: "RTP paketi geliyor mu?", how: "Filter: rtp", why: "Signalling OK ama RTP yoksa firewall UDP drop yapıyor" },
    { id: "rtp-quality", q: "RTP kalite metrikleri?", how: "Statistics → RTP → RTP Streams → Analyze", why: "Jitter/loss/delta ses kalitesini belirler" },
    { id: "one-way", q: "Tek yönlü ses mi?", how: "Her iki yöndeki RTP stream'leri karşılaştır", why: "NAT / routing / firewall asimetrisi göstergesi" }
  ],
  performance: [
    { id: "throughput", q: "Throughput beklenen seviyede mi?", how: "Statistics → TCP Stream Graphs → Throughput", why: "Beklenenden düşükse congestion/window/path sorunu" },
    { id: "rtt-check", q: "RTT dağılımı nasıl?", how: "Statistics → TCP Stream Graphs → Round Trip Time", why: "Artan RTT = queue birikimi, ani spike = loss" },
    { id: "window-scaling", q: "Window scaling açık mı?", how: "Statistics → TCP Stream Graphs → Window Scaling", why: "Window küçükse throughput darboğazı olur" },
    { id: "mtu", q: "MTU sorunu var mı?", how: "Filter: frame.len > 1500 veya ICMP fragmentation needed", why: "Path MTU keşfi başarısızsa yavaşlık" },
    { id: "bytes-flight", q: "Bytes in flight makul mu?", how: "Filter: tcp.analysis.bytes_in_flight", why: "Düşükse window/buffer darboğazı" },
    { id: "fast-retrans", q: "Fast retransmission oranı ne?", how: "Filter: tcp.analysis.fast_retransmission", why: "3 DupACK sonrası — kayıp var ama recovery çalışıyor" },
    { id: "rto", q: "RTO olayları var mı?", how: "Filter: tcp.analysis.rto", why: "RTO = fast recovery başarısız → daha ağır paket kaybı" },
    { id: "out-of-order", q: "Out-of-order var mı?", how: "Filter: tcp.analysis.out_of_order", why: "Path'te multi-route varsa normal, çok ise sorun" }
  ]
};

let checklistState = JSON.parse(localStorage.getItem("wh-checklist") || "{}");
let activeChecklistCat = "general";

/* ═══════════════════════════════════════════════════════════════
   RENDER FUNCTIONS
   ═══════════════════════════════════════════════════════════════ */

function escHTML(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

function escAttr(s) {
  return escHTML(s).replace(/'/g, "&#39;");
}

/* ═══════════════════════════════════════════════════════════════
   FILTER BUILDER
   ═══════════════════════════════════════════════════════════════ */

function renderBuilder() {
  const el = document.getElementById("builder");
  el.innerHTML = `
    <div class="section-header">
      <h2>Filter Builder</h2>
      <div class="description">Filtre oluşturucu — form doldur, canlı önizle, kopyala. Karmaşık filtreler de buradan.</div>
    </div>

    <div class="builder-layout">
      <div class="builder-sidebar" id="builder-tools"></div>
      <div class="builder-panel" id="builder-form"></div>
    </div>
  `;

  // Render tool list
  document.getElementById("builder-tools").innerHTML = BUILDER_TOOLS.map(t => `
    <div class="builder-tool ${builderState.tool === t.id ? "active" : ""}" data-tool="${t.id}">
      <span class="icon">${t.icon}</span>
      <span>${t.name}</span>
    </div>
  `).join("");

  document.querySelectorAll(".builder-tool").forEach(el2 => {
    el2.onclick = () => {
      builderState.tool = el2.dataset.tool;
      renderBuilder();
    };
  });

  renderBuilderForm();
}

function renderBuilderForm() {
  const form = document.getElementById("builder-form");
  if (!form) return;
  const tool = builderState.tool;
  const forms = {
    port:    buildPortForm,
    ip:      buildIpForm,
    conv:    buildConvForm,
    stream:  buildStreamForm,
    time:    buildTimeForm,
    size:    buildSizeForm,
    http:    buildHttpForm,
    tls:     buildTlsForm,
    combine: buildCombineForm
  };
  form.innerHTML = forms[tool]();
  attachBuilderEvents();
  updatePreview();
}

/* ─── Per-tool Forms ─── */
function buildPortForm() {
  return `
    <h3>🔌 Port Filtresi</h3>
    <p class="hint">Tek port, çoklu port, veya port aralığı — source/destination seçebilirsin.</p>

    <div class="form-row">
      <label>Yön</label>
      <div class="radio-group" data-group="direction" data-value="both">
        <div class="radio-pill selected" data-val="both">Her iki yön (source veya dest)</div>
        <div class="radio-pill" data-val="src">Sadece Source</div>
        <div class="radio-pill" data-val="dst">Sadece Destination</div>
      </div>
    </div>

    <div class="form-row">
      <label>Protokol</label>
      <div class="radio-group" data-group="proto" data-value="tcp">
        <div class="radio-pill selected" data-val="tcp">TCP</div>
        <div class="radio-pill" data-val="udp">UDP</div>
        <div class="radio-pill" data-val="both">İkisi</div>
      </div>
    </div>

    <div class="form-row">
      <label>Port(lar)</label>
      <input type="text" id="inp-ports" placeholder="443   veya   443,8080,8443   veya   8000-8999" value="443">
      <div class="helper">Tek: <code>443</code> · Çoklu: <code>443,8080,9090</code> · Aralık: <code>8000-8999</code></div>
    </div>

    <div class="preview-box">
      <div class="preview-label">Oluşan Filtre</div>
      <div class="preview-code" id="preview-out"><span class="empty">Port gir...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPreview()">📋 Kopyala</button>
      <button class="btn" onclick="savePreview()">💾 Kaydet</button>
      <button class="btn" onclick="clearSaved()">🗑 Tümünü Sil</button>
    </div>

    ${renderSavedFilters()}
  `;
}

function buildIpForm() {
  return `
    <h3>🌐 IP Filtresi</h3>
    <p class="hint">Tek IP, subnet (CIDR), veya birden fazla IP.</p>

    <div class="form-row">
      <label>Yön</label>
      <div class="radio-group" data-group="direction" data-value="both">
        <div class="radio-pill selected" data-val="both">Her iki yön</div>
        <div class="radio-pill" data-val="src">Sadece Source</div>
        <div class="radio-pill" data-val="dst">Sadece Destination</div>
      </div>
    </div>

    <div class="form-row">
      <label>IP / Subnet</label>
      <input type="text" id="inp-ips" placeholder="10.0.0.1  veya  10.0.0.0/24  veya  10.0.0.1,10.0.0.2" value="10.0.0.1">
      <div class="helper">Tek: <code>10.0.0.1</code> · Subnet: <code>10.0.0.0/24</code> · Çoklu: virgülle ayır</div>
    </div>

    <div class="preview-box">
      <div class="preview-label">Oluşan Filtre</div>
      <div class="preview-code" id="preview-out"><span class="empty">IP gir...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPreview()">📋 Kopyala</button>
      <button class="btn" onclick="savePreview()">💾 Kaydet</button>
      <button class="btn" onclick="clearSaved()">🗑 Tümünü Sil</button>
    </div>

    ${renderSavedFilters()}
  `;
}

function buildConvForm() {
  return `
    <h3>💬 Konuşma (IP + Port Çifti)</h3>
    <p class="hint">İki endpoint arasındaki trafiği izole et. Bidirectional filtre üretir.</p>

    <div class="form-row">
      <label>Client IP (istek atan)</label>
      <input type="text" id="inp-client" placeholder="10.0.0.1" value="10.0.0.1">
    </div>

    <div class="form-row">
      <label>Server IP (cevap veren)</label>
      <input type="text" id="inp-server" placeholder="192.168.10.100" value="192.168.10.100">
    </div>

    <div class="form-row">
      <label>Server Port</label>
      <input type="text" id="inp-serverport" placeholder="443" value="443">
      <div class="helper">Boş bırakırsan sadece IP+IP eşleşir (her port)</div>
    </div>

    <div class="form-row">
      <label>Protokol</label>
      <div class="radio-group" data-group="proto" data-value="tcp">
        <div class="radio-pill selected" data-val="tcp">TCP</div>
        <div class="radio-pill" data-val="udp">UDP</div>
      </div>
    </div>

    <div class="preview-box">
      <div class="preview-label">Oluşan Filtre (Bidirectional)</div>
      <div class="preview-code" id="preview-out"><span class="empty">...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPreview()">📋 Kopyala</button>
      <button class="btn" onclick="savePreview()">💾 Kaydet</button>
    </div>

    <div class="wizard-hint">
      💡 <strong>İpucu:</strong> Wireshark'ta paket seç → sağ tık → Follow → TCP Stream daha hızlı olabilir.
      Ama PCAP üzerinde tshark ile script yazıyorsan bu filtre lazım.
    </div>

    ${renderSavedFilters()}
  `;
}

function buildStreamForm() {
  return `
    <h3>🔗 TCP Stream</h3>
    <p class="hint">Stream index'ine göre tek konuşmayı izole et.</p>

    <div class="form-row">
      <label>Stream Index</label>
      <input type="text" id="inp-stream" placeholder="5" value="0">
      <div class="helper">Wireshark'ta paket seç → alt panel → Stream index değeri (veya Follow TCP Stream)</div>
    </div>

    <div class="form-row">
      <label>Ek Filtre</label>
      <div class="radio-group" data-group="streamop" data-value="eq">
        <div class="radio-pill selected" data-val="eq">Sadece bu stream</div>
        <div class="radio-pill" data-val="ne">Bu stream HARİÇ</div>
        <div class="radio-pill" data-val="lt">Bu stream'den önce</div>
        <div class="radio-pill" data-val="gt">Bu stream'den sonra</div>
      </div>
    </div>

    <div class="preview-box">
      <div class="preview-label">Oluşan Filtre</div>
      <div class="preview-code" id="preview-out"><span class="empty">...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPreview()">📋 Kopyala</button>
      <button class="btn" onclick="savePreview()">💾 Kaydet</button>
    </div>

    <div class="wizard-hint">
      💡 <strong>Nasıl bulunur:</strong> Bir pakete tıkla → alt tree'de "Transmission Control Protocol" aç → "[Stream index: N]" yazar.
      Veya paket seç → Analyze → Follow → TCP Stream (otomatik filtreler).
    </div>

    ${renderSavedFilters()}
  `;
}

function buildTimeForm() {
  return `
    <h3>⏱ Zaman ve Süre Filtresi</h3>
    <p class="hint">Paketler arası boşluk, yanıt süresi, belirli zaman aralığı.</p>

    <div class="form-row">
      <label>Tip</label>
      <div class="radio-group" data-group="timetype" data-value="tcpdelta">
        <div class="radio-pill selected" data-val="tcpdelta">TCP Paketler Arası (tcp.time_delta)</div>
        <div class="radio-pill" data-val="framedelta">Frame Arası (frame.time_delta)</div>
        <div class="radio-pill" data-val="httptime">HTTP Yanıt Süresi (http.time)</div>
        <div class="radio-pill" data-val="range">Zaman Aralığı</div>
      </div>
    </div>

    <div class="form-row" id="time-value-row">
      <label>Eşik (saniye)</label>
      <input type="number" id="inp-seconds" placeholder="60" value="60" step="0.1" min="0">
      <div class="helper">Bu süreden büyük değerleri göster</div>
    </div>

    <div class="form-row" id="time-range-row" style="display:none;">
      <label>Başlangıç</label>
      <input type="text" id="inp-timestart" placeholder="2024-01-15 10:00:00" value="2024-01-15 10:00:00">
      <label style="margin-top:10px;">Bitiş</label>
      <input type="text" id="inp-timeend" placeholder="2024-01-15 10:05:00" value="2024-01-15 10:05:00">
    </div>

    <div class="preview-box">
      <div class="preview-label">Oluşan Filtre</div>
      <div class="preview-code" id="preview-out"><span class="empty">...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPreview()">📋 Kopyala</button>
      <button class="btn" onclick="savePreview()">💾 Kaydet</button>
    </div>

    ${renderSavedFilters()}
  `;
}

function buildSizeForm() {
  return `
    <h3>📏 Paket Boyutu</h3>
    <p class="hint">MTU sorunları, jumbo frame, küçük ACK'leri filtrele.</p>

    <div class="form-row">
      <label>Operatör</label>
      <div class="radio-group" data-group="sizeop" data-value="gt">
        <div class="radio-pill selected" data-val="gt">Büyüktür (&gt;)</div>
        <div class="radio-pill" data-val="lt">Küçüktür (&lt;)</div>
        <div class="radio-pill" data-val="eq">Eşit (==)</div>
        <div class="radio-pill" data-val="ge">≥</div>
        <div class="radio-pill" data-val="le">≤</div>
      </div>
    </div>

    <div class="form-row">
      <label>Boyut (byte)</label>
      <input type="number" id="inp-size" placeholder="1400" value="1400">
      <div class="helper">MTU: 1500, TCP MSS: ~1460, Jumbo: 9000+</div>
    </div>

    <div class="preview-box">
      <div class="preview-label">Oluşan Filtre</div>
      <div class="preview-code" id="preview-out"><span class="empty">...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPreview()">📋 Kopyala</button>
      <button class="btn" onclick="savePreview()">💾 Kaydet</button>
    </div>

    ${renderSavedFilters()}
  `;
}

function buildHttpForm() {
  return `
    <h3>📨 HTTP Detay Filtresi</h3>
    <p class="hint">Status code, method, URI, host — HTTP özelinde filtrele.</p>

    <div class="form-row">
      <label>Ne Filtrele?</label>
      <div class="radio-group" data-group="httptype" data-value="status">
        <div class="radio-pill selected" data-val="status">Status Code</div>
        <div class="radio-pill" data-val="method">Method</div>
        <div class="radio-pill" data-val="uri">URI contains</div>
        <div class="radio-pill" data-val="host">Host contains</div>
        <div class="radio-pill" data-val="ua">User-Agent contains</div>
      </div>
    </div>

    <div class="form-row">
      <label>Değer</label>
      <input type="text" id="inp-httpval" placeholder="500" value="500">
      <div class="helper" id="http-helper">Tek: <code>500</code> · Aralık: <code>>=500</code> veya <code>>=400 && &lt;500</code></div>
    </div>

    <div class="preview-box">
      <div class="preview-label">Oluşan Filtre</div>
      <div class="preview-code" id="preview-out"><span class="empty">...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPreview()">📋 Kopyala</button>
      <button class="btn" onclick="savePreview()">💾 Kaydet</button>
    </div>

    ${renderSavedFilters()}
  `;
}

function buildTlsForm() {
  return `
    <h3>🔒 TLS Detay Filtresi</h3>
    <p class="hint">Handshake aşamaları, alert kodları, TLS versiyonları.</p>

    <div class="form-row">
      <label>Ne Filtrele?</label>
      <div class="radio-group" data-group="tlstype" data-value="handshake">
        <div class="radio-pill selected" data-val="handshake">Handshake Tipi</div>
        <div class="radio-pill" data-val="alert">Alert Mesajları</div>
        <div class="radio-pill" data-val="version">TLS Versiyonu</div>
        <div class="radio-pill" data-val="sni">SNI (Server Name)</div>
      </div>
    </div>

    <div class="form-row" id="tls-handshake-row">
      <label>Handshake Tipi</label>
      <select id="inp-hsktype">
        <option value="1">1 - Client Hello</option>
        <option value="2">2 - Server Hello</option>
        <option value="11">11 - Certificate</option>
        <option value="12">12 - Server Key Exchange</option>
        <option value="14">14 - Server Hello Done</option>
        <option value="16">16 - Client Key Exchange</option>
        <option value="20">20 - Finished</option>
        <option value="21">21 - Alert (Fatal)</option>
      </select>
    </div>

    <div class="form-row" id="tls-version-row" style="display:none;">
      <label>TLS Versiyonu</label>
      <select id="inp-tlsver">
        <option value="0x0301">TLS 1.0 (0x0301)</option>
        <option value="0x0302">TLS 1.1 (0x0302)</option>
        <option value="0x0303" selected>TLS 1.2 (0x0303)</option>
        <option value="0x0304">TLS 1.3 (0x0304)</option>
      </select>
    </div>

    <div class="form-row" id="tls-sni-row" style="display:none;">
      <label>Server Name (SNI)</label>
      <input type="text" id="inp-sni" placeholder="api.bank.com" value="api.bank.com">
    </div>

    <div class="preview-box">
      <div class="preview-label">Oluşan Filtre</div>
      <div class="preview-code" id="preview-out"><span class="empty">...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPreview()">📋 Kopyala</button>
      <button class="btn" onclick="savePreview()">💾 Kaydet</button>
    </div>

    ${renderSavedFilters()}
  `;
}

function buildCombineForm() {
  if (!builderState.saved.length) {
    return `
      <h3>➕ Filtreleri Birleştir</h3>
      <p class="hint">Kaydedilmiş filtreleri AND/OR ile birleştir.</p>
      <div class="wizard-hint">
        ⚠ Henüz kaydedilmiş filtre yok. Önce diğer araçlarla filtreler oluşturup <strong>💾 Kaydet</strong> butonuyla ekle.
      </div>
    `;
  }
  return `
    <h3>➕ Filtreleri Birleştir</h3>
    <p class="hint">Seçili filtreleri AND/OR operatörüyle birleştir.</p>

    <div class="form-row">
      <label>Operatör</label>
      <div class="radio-group" data-group="op" data-value="and">
        <div class="radio-pill selected" data-val="and">AND (hepsi aynı anda)</div>
        <div class="radio-pill" data-val="or">OR (herhangi biri)</div>
      </div>
    </div>

    <div class="form-row">
      <label>Kaydedilmiş Filtreler</label>
      <div id="combine-list">
        ${builderState.saved.map((f, i) => `
          <label style="display:flex;align-items:center;gap:10px;padding:8px;background:var(--bg-2);border-radius:6px;margin-bottom:6px;cursor:pointer;">
            <input type="checkbox" class="combine-check" data-idx="${i}" checked>
            <code style="flex:1;color:var(--accent);">${escHTML(f.filter)}</code>
          </label>
        `).join("")}
      </div>
    </div>

    <div class="preview-box">
      <div class="preview-label">Birleştirilmiş Filtre</div>
      <div class="preview-code" id="preview-out"><span class="empty">...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPreview()">📋 Kopyala</button>
      <button class="btn" onclick="savePreview()">💾 Kaydet</button>
    </div>

    ${renderSavedFilters()}
  `;
}

/* ─── Radio / Event handlers ─── */
function attachBuilderEvents() {
  // Radio pills
  document.querySelectorAll(".radio-group").forEach(g => {
    g.querySelectorAll(".radio-pill").forEach(p => {
      p.onclick = () => {
        g.querySelectorAll(".radio-pill").forEach(x => x.classList.remove("selected"));
        p.classList.add("selected");
        g.dataset.value = p.dataset.val;
        // Show/hide conditional fields
        if (g.dataset.group === "timetype") {
          const v = p.dataset.val;
          document.getElementById("time-value-row").style.display = (v === "range") ? "none" : "";
          document.getElementById("time-range-row").style.display = (v === "range") ? "" : "none";
        }
        if (g.dataset.group === "tlstype") {
          const v = p.dataset.val;
          document.getElementById("tls-handshake-row").style.display = (v === "handshake" || v === "alert") ? "" : "none";
          document.getElementById("tls-version-row").style.display = (v === "version") ? "" : "none";
          document.getElementById("tls-sni-row").style.display = (v === "sni") ? "" : "none";
        }
        updatePreview();
      };
    });
  });
  // Inputs
  document.querySelectorAll(".builder-panel input, .builder-panel select").forEach(i => {
    i.oninput = updatePreview;
    i.onchange = updatePreview;
  });
  // Combine checks
  document.querySelectorAll(".combine-check").forEach(c => {
    c.onchange = updatePreview;
  });
}

/* ─── Filter generation logic ─── */
function getRadioValue(group) {
  const g = document.querySelector(`.radio-group[data-group="${group}"]`);
  return g ? g.dataset.value : null;
}

function parsePorts(str) {
  return str.split(",").map(s => s.trim()).filter(Boolean);
}

function generateFilter() {
  const tool = builderState.tool;
  try {
    switch (tool) {
      case "port": return genPort();
      case "ip": return genIp();
      case "conv": return genConv();
      case "stream": return genStream();
      case "time": return genTime();
      case "size": return genSize();
      case "http": return genHttp();
      case "tls": return genTls();
      case "combine": return genCombine();
    }
  } catch(e) { return ""; }
}

function genPort() {
  const dir = getRadioValue("direction");
  const proto = getRadioValue("proto");
  const portsRaw = document.getElementById("inp-ports").value.trim();
  if (!portsRaw) return "";

  const fieldBase = { tcp: "tcp", udp: "udp" };
  const suffix = { src: "srcport", dst: "dstport", both: "port" };
  const fld = suffix[dir];

  // Parse ports — handle ranges and lists
  const parts = parsePorts(portsRaw);
  const single = parts.length === 1 && !parts[0].includes("-");
  const range = parts.length === 1 && parts[0].includes("-");

  function buildFor(p) {
    if (single) return `${p}.${fld} == ${parts[0]}`;
    if (range) {
      const [lo, hi] = parts[0].split("-");
      return `(${p}.${fld} >= ${lo} && ${p}.${fld} <= ${hi})`;
    }
    // Multiple ports - use "in {...}"
    return `${p}.${fld} in {${parts.join(" ")}}`;
  }

  if (proto === "both") {
    return `${buildFor("tcp")} or ${buildFor("udp")}`;
  }
  return buildFor(proto);
}

function genIp() {
  const dir = getRadioValue("direction");
  const ipsRaw = document.getElementById("inp-ips").value.trim();
  if (!ipsRaw) return "";
  const suffix = { src: "src", dst: "dst", both: "addr" };
  const fld = `ip.${suffix[dir]}`;
  const parts = parsePorts(ipsRaw);

  if (parts.length === 1) return `${fld} == ${parts[0]}`;
  return parts.map(p => `${fld} == ${p}`).join(" || ");
}

function genConv() {
  const client = document.getElementById("inp-client").value.trim();
  const server = document.getElementById("inp-server").value.trim();
  const port = document.getElementById("inp-serverport").value.trim();
  const proto = getRadioValue("proto");
  if (!client || !server) return "";
  let forward = `(ip.src == ${client} && ip.dst == ${server}`;
  let reverse = `(ip.src == ${server} && ip.dst == ${client}`;
  if (port) {
    forward += ` && ${proto}.dstport == ${port})`;
    reverse += ` && ${proto}.srcport == ${port})`;
  } else {
    forward += ")";
    reverse += ")";
  }
  return `${forward} or ${reverse}`;
}

function genStream() {
  const num = document.getElementById("inp-stream").value.trim();
  if (num === "") return "";
  const op = getRadioValue("streamop");
  const ops = { eq: "==", ne: "!=", lt: "<", gt: ">" };
  return `tcp.stream ${ops[op]} ${num}`;
}

function genTime() {
  const type = getRadioValue("timetype");
  if (type === "range") {
    const start = document.getElementById("inp-timestart").value.trim();
    const end = document.getElementById("inp-timeend").value.trim();
    if (!start || !end) return "";
    return `frame.time >= "${start}" && frame.time <= "${end}"`;
  }
  const sec = document.getElementById("inp-seconds").value.trim();
  if (!sec) return "";
  const fld = { tcpdelta: "tcp.time_delta", framedelta: "frame.time_delta", httptime: "http.time" }[type];
  return `${fld} > ${sec}`;
}

function genSize() {
  const op = getRadioValue("sizeop");
  const size = document.getElementById("inp-size").value.trim();
  if (!size) return "";
  const ops = { gt: ">", lt: "<", eq: "==", ge: ">=", le: "<=" };
  return `frame.len ${ops[op]} ${size}`;
}

function genHttp() {
  const type = getRadioValue("httptype");
  const val = document.getElementById("inp-httpval").value.trim();
  if (!val) return "";
  const map = {
    status: `http.response.code`,
    method: `http.request.method`,
    uri: `http.request.uri`,
    host: `http.host`,
    ua: `http.user_agent`
  };
  const fld = map[type];
  if (type === "status") {
    // If val starts with operator, use directly
    if (/^[<>=!]/.test(val)) return `${fld} ${val}`;
    return `${fld} == ${val}`;
  }
  if (type === "method") return `${fld} == "${val.toUpperCase()}"`;
  return `${fld} contains "${val}"`;
}

function genTls() {
  const type = getRadioValue("tlstype");
  if (type === "handshake" || type === "alert") {
    const hs = document.getElementById("inp-hsktype").value;
    if (type === "alert" || hs === "21") return `tls.alert_message`;
    return `tls.handshake.type == ${hs}`;
  }
  if (type === "version") {
    const v = document.getElementById("inp-tlsver").value;
    return `tls.record.version == ${v}`;
  }
  if (type === "sni") {
    const sni = document.getElementById("inp-sni").value.trim();
    if (!sni) return "";
    return `tls.handshake.extensions_server_name contains "${sni}"`;
  }
  return "";
}

function genCombine() {
  const op = getRadioValue("op");
  const sep = op === "and" ? " && " : " || ";
  const checked = [...document.querySelectorAll(".combine-check:checked")];
  if (!checked.length) return "";
  const parts = checked.map(c => `(${builderState.saved[c.dataset.idx].filter})`);
  return parts.join(sep);
}

/* ─── Preview + save ─── */
function updatePreview() {
  const out = document.getElementById("preview-out");
  if (!out) return;
  const f = generateFilter();
  if (f) {
    out.innerHTML = escHTML(f);
    out.classList.remove("empty");
  } else {
    out.innerHTML = '<span class="empty">Form doldur...</span>';
  }
}

function copyPreview() {
  const f = generateFilter();
  if (!f) { showToast("Önce filtre oluştur"); return; }
  copyText(f);
}

function savePreview() {
  const f = generateFilter();
  if (!f) { showToast("Önce filtre oluştur"); return; }
  if (builderState.saved.some(x => x.filter === f)) {
    showToast("Bu filtre zaten kayıtlı");
    return;
  }
  builderState.saved.push({ filter: f, tool: builderState.tool, ts: Date.now() });
  localStorage.setItem("wh-saved-filters", JSON.stringify(builderState.saved));
  showToast("Kaydedildi: " + f.substring(0, 40));
  renderBuilderForm();
}

function removeSaved(idx) {
  builderState.saved.splice(idx, 1);
  localStorage.setItem("wh-saved-filters", JSON.stringify(builderState.saved));
  renderBuilderForm();
}

function clearSaved() {
  if (!confirm("Tüm kaydedilmiş filtreleri silmek istiyor musun?")) return;
  builderState.saved = [];
  localStorage.setItem("wh-saved-filters", "[]");
  renderBuilderForm();
}

function renderSavedFilters() {
  if (!builderState.saved.length) return "";
  return `
    <div class="saved-filters">
      <h4>💾 Kaydedilmiş Filtreler (${builderState.saved.length})</h4>
      ${builderState.saved.map((f, i) => `
        <div class="saved-filter-item">
          <code onclick="copyText('${escAttr(f.filter)}')">${escHTML(f.filter)}</code>
          <span class="remove" onclick="removeSaved(${i})" title="Sil">×</span>
        </div>
      `).join("")}
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════════
   TROUBLESHOOTING WIZARD
   ═══════════════════════════════════════════════════════════════ */

function renderWizard() {
  const el = document.getElementById("wizard");
  el.innerHTML = `
    <div class="section-header">
      <h2>Sorun Sihirbazı</h2>
      <div class="description">Semptomu seç → protokolü seç → sana özel filtreler + adımlar.</div>
    </div>

    <div class="wizard-step">
      <span class="step-num">1</span>
      <h3>Sorunun semptomu nedir?</h3>
      <div class="wizard-options">
        ${WIZARD_SYMPTOMS.map(s => `
          <div class="wizard-option ${wizardState.symptom === s.id ? "selected" : ""}" data-symptom="${s.id}">
            <div class="opt-title">${escHTML(s.title)}</div>
            <div class="opt-desc">${escHTML(s.desc)}</div>
          </div>
        `).join("")}
      </div>
    </div>

    ${wizardState.symptom ? `
    <div class="wizard-step">
      <span class="step-num">2</span>
      <h3>Hangi protokol?</h3>
      <div class="wizard-options">
        ${WIZARD_PROTOCOLS.map(p => `
          <div class="wizard-option ${wizardState.protocol === p.id ? "selected" : ""}" data-protocol="${p.id}">
            <div class="opt-title">${escHTML(p.name)}</div>
          </div>
        `).join("")}
      </div>
    </div>
    ` : ""}

    ${wizardState.symptom && wizardState.protocol ? renderWizardResult() : ""}

    ${wizardState.symptom ? `<button class="btn-reset" onclick="resetWizard()">🔄 Baştan Başla</button>` : ""}
  `;

  document.querySelectorAll("[data-symptom]").forEach(el2 => {
    el2.onclick = () => { wizardState.symptom = el2.dataset.symptom; wizardState.protocol = null; renderWizard(); };
  });
  document.querySelectorAll("[data-protocol]").forEach(el2 => {
    el2.onclick = () => { wizardState.protocol = el2.dataset.protocol; renderWizard(); };
  });
}

function renderWizardResult() {
  // Try exact match, fall back to generic
  const key = `${wizardState.symptom}/${wizardState.protocol}`;
  let result = WIZARD_RESULTS[key];
  if (!result) {
    // fallback: try with "other" protocol
    result = WIZARD_RESULTS[`${wizardState.symptom}/other`] || WIZARD_RESULTS[`${wizardState.symptom}/tcp`];
  }
  if (!result) {
    return `
      <div class="wizard-result">
        <h3>Bu kombinasyon için özel rehber hazırlanmamış</h3>
        <p>Genel triage adımlarını dene → Sol menüden "Root Cause" bölümüne bak.</p>
      </div>
    `;
  }

  return `
    <div class="wizard-result">
      <h3>✓ ${escHTML(result.title)}</h3>

      <div class="wizard-hint">💡 ${escHTML(result.hint)}</div>

      <h4 style="color:var(--text-0);margin-top:16px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;">Önerilen Filtreler</h4>
      <div class="wizard-filters">
        ${result.filters.map(f => `
          <div class="filter-item">
            <span class="filter-code" onclick="copyText('${escAttr(f.code)}')">${escHTML(f.code)}</span>
            <span class="filter-desc">${escHTML(f.desc)}</span>
          </div>
        `).join("")}
      </div>

      <h4 style="color:var(--text-0);margin-top:16px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;">Adım Adım Yapılacaklar</h4>
      <ol class="wizard-steps-list">
        ${result.steps.map(s => `<li>${escHTML(s)}</li>`).join("")}
      </ol>
    </div>
  `;
}

function resetWizard() {
  wizardState.symptom = null;
  wizardState.protocol = null;
  renderWizard();
}

/* ═══════════════════════════════════════════════════════════════
   FOLLOW TRAFFIC HELPER
   ═══════════════════════════════════════════════════════════════ */

function renderFollow() {
  const el = document.getElementById("follow");
  el.innerHTML = `
    <div class="section-header">
      <h2>Trafik Takibi — Tek Konuşmayı İzole Et</h2>
      <div class="description">"Bir trafiği takip edip analiz etmek" — bu bölüm tam olarak onu öğretir.</div>
    </div>

    <div class="content-block">
      <h3>Konuşma Nedir?</h3>
      <p>Bir "konuşma" (conversation) = iki endpoint arasındaki paket akışı. Her endpoint: <code>IP:Port</code> çifti.</p>
      <p><strong>Örnek:</strong> Client <code>10.0.0.1:54321</code> ↔ Server <code>192.168.10.100:443</code> arasındaki tüm paketler = bir TCP konuşması.</p>

      <h4>Wireshark'ta bir konuşmayı 4 yolla izole edebilirsin:</h4>
      <ul>
        <li><strong>Follow TCP Stream</strong> (en kolay): Paket seç → sağ tık → Follow → TCP Stream. Wireshark otomatik filtreler + içeriği açık gösterir.</li>
        <li><strong>Stream Index ile</strong>: <code>tcp.stream eq 5</code> — stream numarasıyla filtrele.</li>
        <li><strong>IP+Port kombinasyonu</strong>: iki yönlü filtre yaz (aşağıdaki builder).</li>
        <li><strong>Conversations paneli</strong>: Statistics → Conversations → üzerine sağ tık → Apply as Filter.</li>
      </ul>
    </div>

    <div class="content-block">
      <h3>Adım Adım: Follow TCP Stream</h3>
      <ol class="wizard-steps-list">
        <li>Paket listesinde ilgilendiğin TCP paketine tıkla (örn. bir SYN veya HTTP paketi).</li>
        <li>Sağ tık → <strong>Follow → TCP Stream</strong> (veya Ctrl+Alt+Shift+T).</li>
        <li>Yeni pencere açılır: client→server (mavi) ve server→client (kırmızı) metinleri ayırır.</li>
        <li>Pencere kapandığında ana ekranda filtre otomatik uygulanır: <code>tcp.stream eq N</code>.</li>
        <li>Artık sadece o konuşmanın paketlerini görürsün. Diğer trafik gizli.</li>
        <li>Başka akış için: Clear butonuna bas → başka pakete uygula.</li>
      </ol>
    </div>

    <div class="content-block">
      <h3>Konuşma Filtresi Oluşturucu</h3>
      <p class="hint">Client IP + Server IP + Port gir → bidirectional filtre üretir.</p>

      <div class="form-row">
        <label>Client IP</label>
        <input type="text" id="follow-client" placeholder="10.0.0.1" value="10.0.0.1">
      </div>
      <div class="form-row">
        <label>Server IP</label>
        <input type="text" id="follow-server" placeholder="192.168.10.100" value="192.168.10.100">
      </div>
      <div class="form-row">
        <label>Server Port</label>
        <input type="text" id="follow-port" placeholder="443" value="443">
      </div>
      <div class="form-row">
        <label>Protokol</label>
        <div class="radio-group" data-group="follow-proto" data-value="tcp">
          <div class="radio-pill selected" data-val="tcp">TCP</div>
          <div class="radio-pill" data-val="udp">UDP</div>
        </div>
      </div>

      <div class="preview-box">
        <div class="preview-label">Bidirectional Konuşma Filtresi</div>
        <div class="preview-code" id="follow-preview"><span class="empty">...</span></div>
      </div>

      <div class="btn-row">
        <button class="btn btn-primary" onclick="copyFollowPreview()">📋 Kopyala</button>
      </div>
    </div>

    <div class="content-block">
      <h3>Yaygın Senaryolar — Hazır Filtreler</h3>

      <div class="filter-list">
        <div class="filter-item">
          <span class="filter-code" onclick="copyText('tcp.stream eq 0')">tcp.stream eq 0</span>
          <span class="filter-desc">İlk TCP stream (PCAP'ta ilk konuşma)</span>
        </div>
        <div class="filter-item">
          <span class="filter-code" onclick="copyText('ip.addr == 10.0.0.1 && tcp.port == 443')">ip.addr == 10.0.0.1 &amp;&amp; tcp.port == 443</span>
          <span class="filter-desc">Bir IP'nin tüm HTTPS trafiği</span>
        </div>
        <div class="filter-item">
          <span class="filter-code" onclick="copyText('ip.src == 10.0.0.1 && tcp.srcport == 54321')">ip.src == 10.0.0.1 &amp;&amp; tcp.srcport == 54321</span>
          <span class="filter-desc">Belirli client:port'tan çıkan tek akış</span>
        </div>
        <div class="filter-item">
          <span class="filter-code" onclick="copyText('tcp.flags.syn == 1 && tcp.flags.ack == 0')">tcp.flags.syn == 1 &amp;&amp; tcp.flags.ack == 0</span>
          <span class="filter-desc">Tüm yeni bağlantı denemeleri</span>
        </div>
        <div class="filter-item">
          <span class="filter-code" onclick="copyText('eth.addr == 00:11:22:33:44:55')">eth.addr == 00:11:22:33:44:55</span>
          <span class="filter-desc">Belirli MAC adresi trafiği</span>
        </div>
      </div>
    </div>

    <div class="content-block">
      <h3>İpuçları</h3>
      <ul>
        <li><strong>Stream index bul:</strong> Bir pakete tıkla → alt panel → "Transmission Control Protocol" aç → "[Stream index: N]" yazar.</li>
        <li><strong>Yeni pencerede aç:</strong> Statistics → Conversations → sağ tık → Apply as Filter → "Not Selected" (karşılaştırma için).</li>
        <li><strong>Stream'i ayrı dosyaya kaydet:</strong> Filtre uyguladıktan sonra File → Export Specified Packets → Displayed.</li>
        <li><strong>tshark ile:</strong> <code>tshark -r cap.pcap -Y "tcp.stream eq 5" -w stream5.pcap</code></li>
      </ul>
    </div>
  `;

  // Hook follow form
  const update = () => {
    const client = document.getElementById("follow-client").value.trim();
    const server = document.getElementById("follow-server").value.trim();
    const port = document.getElementById("follow-port").value.trim();
    const proto = document.querySelector('[data-group="follow-proto"]').dataset.value;
    const out = document.getElementById("follow-preview");
    if (!client || !server) { out.innerHTML = '<span class="empty">IP adreslerini gir...</span>'; return; }
    let f = `(ip.src == ${client} && ip.dst == ${server}`;
    let r = `(ip.src == ${server} && ip.dst == ${client}`;
    if (port) { f += ` && ${proto}.dstport == ${port})`; r += ` && ${proto}.srcport == ${port})`; }
    else { f += ")"; r += ")"; }
    out.innerHTML = escHTML(f + " or " + r);
    out.classList.remove("empty");
  };

  ["follow-client","follow-server","follow-port"].forEach(id => {
    document.getElementById(id).oninput = update;
  });
  document.querySelectorAll('[data-group="follow-proto"] .radio-pill').forEach(p => {
    p.onclick = () => {
      document.querySelectorAll('[data-group="follow-proto"] .radio-pill').forEach(x => x.classList.remove("selected"));
      p.classList.add("selected");
      document.querySelector('[data-group="follow-proto"]').dataset.value = p.dataset.val;
      update();
    };
  });
  update();
}

function copyFollowPreview() {
  const out = document.getElementById("follow-preview");
  const text = out.textContent.trim();
  if (!text || text.includes("gir...")) { showToast("Önce form doldur"); return; }
  copyText(text);
}

/* ═══════════════════════════════════════════════════════════════
   PROFILE BUILDER
   ═══════════════════════════════════════════════════════════════ */

function renderProfileBuilder() {
  const el = document.getElementById("profilebuilder");
  el.innerHTML = `
    <div class="section-header">
      <h2>Profil Oluşturucu</h2>
      <div class="description">Kolonları, renk kurallarını ve kayıtlı filtreleri seç → Wireshark'a import edilebilir dosyalar indir.</div>
    </div>

    <div class="content-block">
      <h3>1. Profil Adı</h3>
      <div class="form-row">
        <input type="text" id="prof-name" value="${escAttr(profileState.name)}" placeholder="Fintech-Custom">
      </div>
    </div>

    <div class="content-block">
      <h3>2. Kolonlar (${profileState.columns.length} seçili)</h3>
      <p class="hint">Wireshark paket listesinde görünecek kolonlar.</p>
      <div class="check-group">
        ${PROFILE_COLUMNS.map(c => `
          <div class="check-pill ${profileState.columns.includes(c.id) ? "selected" : ""}" data-col="${c.id}">${escHTML(c.label)}</div>
        `).join("")}
      </div>
    </div>

    <div class="content-block">
      <h3>3. Renk Kuralları (${profileState.colorRules.length} seçili)</h3>
      <p class="hint">Eşleşen paketler otomatik renklenir.</p>
      <div class="check-group">
        ${PROFILE_COLORS.map(c => `
          <div class="check-pill ${profileState.colorRules.includes(c.id) ? "selected" : ""}" data-color="${c.id}" style="${profileState.colorRules.includes(c.id) ? `background:#${c.bg};color:#${c.fg};border-color:#${c.bg};` : ""}">${escHTML(c.label)}</div>
        `).join("")}
      </div>
    </div>

    <div class="content-block">
      <h3>4. Kayıtlı Filtreler (${profileState.savedFilters.length} seçili)</h3>
      <p class="hint">Wireshark'ta hızlı erişim için kaydedilir (★ butonunda görünür).</p>
      <div class="check-group">
        ${PROFILE_SAVED_FILTERS.map(f => `
          <div class="check-pill ${profileState.savedFilters.includes(f.id) ? "selected" : ""}" data-filter="${f.id}">${escHTML(f.label)}</div>
        `).join("")}
      </div>
    </div>

    <div class="content-block">
      <h3>5. İndir ve Import Et</h3>
      <p class="hint">Dosyalar oluşturulacak → Wireshark profil klasörüne yerleştir.</p>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="downloadProfile()">⬇ Profil Dosyalarını İndir</button>
        <button class="btn" onclick="previewProfile()">👁 Önizle</button>
        <button class="btn" onclick="resetProfile()">🔄 Sıfırla</button>
      </div>

      <div id="profile-preview" style="display:none;margin-top:16px;"></div>

      <div class="wizard-hint" style="margin-top:16px;">
        <strong>Nasıl Import Edilir:</strong><br>
        <strong>1)</strong> Yukarıdaki butonla 3 dosya indirilir: <code>colorfilters</code>, <code>dfilters</code>, <code>preferences</code><br>
        <strong>2)</strong> Wireshark → Edit → Configuration Profiles → New → "${profileState.name || "Fintech-Custom"}"<br>
        <strong>3)</strong> Profil klasörünü aç (Edit → Configuration Profiles → seçili profile → üzerine tıkla → path görünür)<br>
        <strong>4)</strong> İndirdiğin 3 dosyayı o klasöre kopyala (üzerine yaz)<br>
        <strong>5)</strong> Wireshark'ı kapat-aç veya profil değiştir → ayarlar aktif olur
      </div>
    </div>
  `;

  // Events
  document.getElementById("prof-name").oninput = (e) => { profileState.name = e.target.value; };
  document.querySelectorAll("[data-col]").forEach(p => p.onclick = () => toggleProfile("columns", p.dataset.col));
  document.querySelectorAll("[data-color]").forEach(p => p.onclick = () => toggleProfile("colorRules", p.dataset.color));
  document.querySelectorAll("[data-filter]").forEach(p => p.onclick = () => toggleProfile("savedFilters", p.dataset.filter));
}

function toggleProfile(arr, id) {
  const idx = profileState[arr].indexOf(id);
  if (idx >= 0) profileState[arr].splice(idx, 1);
  else profileState[arr].push(id);
  renderProfileBuilder();
}

function resetProfile() {
  profileState.columns = ["no","time","src","dst","proto","len","info"];
  profileState.colorRules = [];
  profileState.savedFilters = [];
  renderProfileBuilder();
}

function generateProfileFiles() {
  // colorfilters file
  const colorfilters = profileState.colorRules.map(id => {
    const c = PROFILE_COLORS.find(x => x.id === id);
    // Format: @name@filter@[fg][bg]
    const fg = `[${parseInt(c.fg.substr(0,2),16) << 8},${parseInt(c.fg.substr(2,2),16) << 8},${parseInt(c.fg.substr(4,2),16) << 8}]`;
    const bg = `[${parseInt(c.bg.substr(0,2),16) << 8},${parseInt(c.bg.substr(2,2),16) << 8},${parseInt(c.bg.substr(4,2),16) << 8}]`;
    return `@${c.label}@${c.filter}@${fg}${bg}`;
  }).join("\n");

  // dfilters (display filter buttons / saved filters)
  const dfilters = profileState.savedFilters.map(id => {
    const f = PROFILE_SAVED_FILTERS.find(x => x.id === id);
    return `"${f.label}" ${f.filter}`;
  }).join("\n");

  // preferences (columns)
  const cols = profileState.columns.map(id => PROFILE_COLUMNS.find(x => x.id === id));
  const colFormat = cols.map(c => `"${c.label}", "${c.field}"`).join(", ");
  const preferences = `# Wireshark preferences file — generated by Wireshark Hub\n# Profile: ${profileState.name}\n\n####### Columns #######\ncolumn.format: ${colFormat}\n`;

  return { colorfilters, dfilters, preferences };
}

function previewProfile() {
  const files = generateProfileFiles();
  const el = document.getElementById("profile-preview");
  el.style.display = "block";
  el.innerHTML = `
    <h4 style="color:var(--text-0);margin-bottom:8px;">colorfilters</h4>
    <pre><code>${escHTML(files.colorfilters || "(renk kuralı seçilmedi)")}</code></pre>
    <h4 style="color:var(--text-0);margin:12px 0 8px;">dfilters (Saved Filters)</h4>
    <pre><code>${escHTML(files.dfilters || "(filtre seçilmedi)")}</code></pre>
    <h4 style="color:var(--text-0);margin:12px 0 8px;">preferences</h4>
    <pre><code>${escHTML(files.preferences)}</code></pre>
  `;
}

function downloadFile(name, content) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function downloadProfile() {
  const files = generateProfileFiles();
  if (files.colorfilters) downloadFile("colorfilters", files.colorfilters);
  if (files.dfilters) downloadFile("dfilters", files.dfilters);
  downloadFile("preferences", files.preferences);
  showToast("3 dosya indirildi — Wireshark profil klasörüne koy");
}

/* ═══════════════════════════════════════════════════════════════
   TSHARK COMMAND BUILDER
   ═══════════════════════════════════════════════════════════════ */

function renderTsharkBuilder() {
  const el = document.getElementById("tsharkbuilder");
  el.innerHTML = `
    <div class="section-header">
      <h2>tshark Command Builder</h2>
      <div class="description">Form doldur → tshark CLI komutu üret. Otomasyonda, SSH üzerinden, script'te kullan.</div>
    </div>

    <div class="content-block">
      <h3>Hızlı Preset'ler</h3>
      <div class="check-group">
        ${TSHARK_PRESETS.map((p, i) => `
          <div class="check-pill" onclick="applyTsharkPreset(${i})">${escHTML(p.name)}</div>
        `).join("")}
      </div>
    </div>

    <div class="content-block">
      <h3>Parametreler</h3>

      <div class="form-row">
        <label>Girdi PCAP Dosyası (-r)</label>
        <input type="text" id="ts-input" value="${escAttr(tsharkState.input)}" placeholder="cap.pcap">
      </div>

      <div class="form-row">
        <label>Display Filter (-Y)</label>
        <input type="text" id="ts-filter" value="${escAttr(tsharkState.filter)}" placeholder='tcp.analysis.flags veya http.response.code >= 500'>
        <div class="helper">Filter Builder'dan kopyaladığın filtreyi buraya yapıştır</div>
      </div>

      <div class="form-row">
        <label>Çıktı Modu</label>
        <div class="radio-group" data-group="ts-mode" data-value="${tsharkState.mode}">
          <div class="radio-pill ${tsharkState.mode==='fields'?'selected':''}" data-val="fields">Alanları Çıkar (-T fields)</div>
          <div class="radio-pill ${tsharkState.mode==='fields-nh'?'selected':''}" data-val="fields-nh">Alanlar (header yok)</div>
          <div class="radio-pill ${tsharkState.mode==='json'?'selected':''}" data-val="json">JSON</div>
          <div class="radio-pill ${tsharkState.mode==='pdml'?'selected':''}" data-val="pdml">PDML (XML)</div>
          <div class="radio-pill ${tsharkState.mode==='stat'?'selected':''}" data-val="stat">Sadece İstatistik</div>
          <div class="radio-pill ${tsharkState.mode==='view'?'selected':''}" data-val="view">Normal Görüntüle</div>
        </div>
      </div>

      <div class="form-row" id="ts-fields-row">
        <label>Çıkarılacak Alanlar (-e)</label>
        <div class="check-group" style="max-height:200px;overflow-y:auto;padding:6px;background:var(--bg-2);border-radius:6px;">
          ${TSHARK_FIELDS.map(f => `
            <div class="check-pill ${tsharkState.fields.includes(f.id)?'selected':''}" data-field="${f.id}">${escHTML(f.label)}</div>
          `).join("")}
        </div>
        <div class="helper">${tsharkState.fields.length} alan seçili</div>
      </div>

      <div class="form-row" id="ts-stat-row">
        <label>İstatistik (-z)</label>
        <select id="ts-stat">
          ${TSHARK_STATS.map(s => `<option value="${s.id}" ${tsharkState.stat===s.id?'selected':''}>${escHTML(s.label)}</option>`).join("")}
        </select>
      </div>

      <div class="form-row">
        <label>TLS Keylog Dosyası (-o) — opsiyonel</label>
        <input type="text" id="ts-keylog" value="${escAttr(tsharkState.keylog)}" placeholder="/tmp/tls.keys (boş bırakabilirsin)">
        <div class="helper">TLS deşifre için — F5'ten çıkardığın pre_master_log.pms vb.</div>
      </div>

      <div class="form-row">
        <label>Çıktı PCAP Dosyası (-w) — opsiyonel</label>
        <input type="text" id="ts-output" value="${escAttr(tsharkState.output)}" placeholder="filtered.pcap (boş bırakabilirsin)">
        <div class="helper">Filtreli paketleri yeni PCAP'e kaydet</div>
      </div>

      <div class="form-row">
        <label>Ekstra Parametreler</label>
        <input type="text" id="ts-extra" value="${escAttr(tsharkState.extra)}" placeholder="-c 1000 veya -n">
        <div class="helper">İsteğe bağlı ek flag'ler</div>
      </div>
    </div>

    <div class="preview-box">
      <div class="preview-label">tshark Komutu</div>
      <div class="preview-code" id="ts-preview"><span class="empty">...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyTsharkCommand()">📋 Kopyala</button>
      <button class="btn" onclick="clearTsharkFields()">🗑 Alanları Temizle</button>
    </div>

    <div class="wizard-hint" style="margin-top:16px;">
      💡 <strong>SSH ile F5'te çalıştırmak:</strong><br>
      <code>ssh root@f5-ip "tshark -r /var/tmp/cap.pcap -Y 'filter'"</code><br>
      Veya canlı capture için:<br>
      <code>ssh root@f5 "tcpdump -i 0.0:nnnp -s 0 -w - host X" | tshark -r - -Y 'filter'</code>
    </div>
  `;

  // Events
  ["ts-input","ts-filter","ts-stat","ts-keylog","ts-output","ts-extra"].forEach(id => {
    const el2 = document.getElementById(id);
    if (el2) el2.oninput = () => updateTshark();
    if (el2) el2.onchange = () => updateTshark();
  });
  document.querySelectorAll('[data-group="ts-mode"] .radio-pill').forEach(p => {
    p.onclick = () => {
      document.querySelectorAll('[data-group="ts-mode"] .radio-pill').forEach(x => x.classList.remove("selected"));
      p.classList.add("selected");
      document.querySelector('[data-group="ts-mode"]').dataset.value = p.dataset.val;
      tsharkState.mode = p.dataset.val;
      renderTsharkBuilder();
    };
  });
  document.querySelectorAll("[data-field]").forEach(p => {
    p.onclick = () => {
      const f = p.dataset.field;
      const idx = tsharkState.fields.indexOf(f);
      if (idx >= 0) tsharkState.fields.splice(idx, 1);
      else tsharkState.fields.push(f);
      renderTsharkBuilder();
    };
  });

  // Show/hide rows based on mode
  const fieldsRow = document.getElementById("ts-fields-row");
  const statRow = document.getElementById("ts-stat-row");
  if (fieldsRow) fieldsRow.style.display = (tsharkState.mode === "fields" || tsharkState.mode === "fields-nh") ? "" : "none";
  if (statRow) statRow.style.display = (tsharkState.mode === "stat") ? "" : "none";

  updateTshark();
}

function updateTshark() {
  tsharkState.input = document.getElementById("ts-input")?.value.trim() || "";
  tsharkState.filter = document.getElementById("ts-filter")?.value.trim() || "";
  tsharkState.stat = document.getElementById("ts-stat")?.value || "";
  tsharkState.keylog = document.getElementById("ts-keylog")?.value.trim() || "";
  tsharkState.output = document.getElementById("ts-output")?.value.trim() || "";
  tsharkState.extra = document.getElementById("ts-extra")?.value.trim() || "";

  let parts = ["tshark"];
  if (tsharkState.input) parts.push("-r", tsharkState.input);
  if (tsharkState.keylog) parts.push("-o", `"tls.keylog_file:${tsharkState.keylog}"`);
  if (tsharkState.filter) parts.push("-Y", `"${tsharkState.filter}"`);

  if (tsharkState.mode === "fields" || tsharkState.mode === "fields-nh") {
    parts.push("-T", "fields");
    if (tsharkState.mode === "fields") parts.push("-E", "header=y");
    tsharkState.fields.forEach(f => parts.push("-e", f));
  } else if (tsharkState.mode === "json") {
    parts.push("-T", "json");
  } else if (tsharkState.mode === "pdml") {
    parts.push("-T", "pdml");
  } else if (tsharkState.mode === "stat" && tsharkState.stat) {
    parts.push("-q", "-z", tsharkState.stat);
  }

  if (tsharkState.output) parts.push("-w", tsharkState.output);
  if (tsharkState.extra) parts.push(tsharkState.extra);

  const cmd = parts.join(" ");
  const out = document.getElementById("ts-preview");
  if (out) {
    out.innerHTML = escHTML(cmd);
    out.classList.remove("empty");
  }
}

function copyTsharkCommand() {
  const out = document.getElementById("ts-preview");
  const cmd = out.textContent.trim();
  if (!cmd || cmd === "tshark") { showToast("Önce form doldur"); return; }
  copyText(cmd);
}

function clearTsharkFields() {
  tsharkState.fields = [];
  renderTsharkBuilder();
}

function applyTsharkPreset(idx) {
  const p = TSHARK_PRESETS[idx].preset;
  tsharkState.filter = p.filter || "";
  tsharkState.mode = p.mode || "fields";
  tsharkState.fields = p.fields || [];
  tsharkState.stat = p.stat || "";
  renderTsharkBuilder();
  showToast("Preset uygulandı: " + TSHARK_PRESETS[idx].name);
}

/* ═══════════════════════════════════════════════════════════════
   PCAP CAPTURE COMMAND BUILDER
   ═══════════════════════════════════════════════════════════════ */

function renderPcapBuilder() {
  const el = document.getElementById("pcapbuilder");
  el.innerHTML = `
    <div class="section-header">
      <h2>PCAP Capture Komut Üretici</h2>
      <div class="description">tcpdump komutunu form ile üret — F5/FortiGate/Check Point/Linux.</div>
    </div>

    <div class="content-block">
      <h3>Platform</h3>
      <div class="check-group">
        ${PCAP_PLATFORMS.map(p => `
          <div class="check-pill ${pcapState.platform===p.id?'selected':''}" data-platform="${p.id}">${escHTML(p.name)}</div>
        `).join("")}
      </div>
    </div>

    <div class="content-block">
      <h3>Capture Parametreleri</h3>

      <div class="form-row">
        <label>Interface (-i)</label>
        <input type="text" id="pc-iface" value="${escAttr(pcapState.iface)}" placeholder="eth0">
        <div class="helper">${pcapState.platform === 'f5' ? 'F5: <code>0.0:nnnp</code> (tüm interface + metadata) veya spesifik interface' : pcapState.platform === 'checkpoint' ? 'Check Point: <code>eth0, eth1, bond0</code> vb.' : 'İsim: <code>eth0, ens192, wan1</code>'}</div>
      </div>

      <div class="form-row">
        <label>Ana Host/IP Filtresi</label>
        <div class="radio-group" data-group="pc-h1t" data-value="${pcapState.host1Type}">
          <div class="radio-pill ${pcapState.host1Type==='host'?'selected':''}" data-val="host">host (iki yön)</div>
          <div class="radio-pill ${pcapState.host1Type==='src'?'selected':''}" data-val="src">src host</div>
          <div class="radio-pill ${pcapState.host1Type==='dst'?'selected':''}" data-val="dst">dst host</div>
          <div class="radio-pill ${pcapState.host1Type==='net'?'selected':''}" data-val="net">net (subnet)</div>
          <div class="radio-pill ${pcapState.host1Type==='none'?'selected':''}" data-val="none">Yok</div>
        </div>
        <input type="text" id="pc-host1" value="${escAttr(pcapState.host1)}" placeholder="10.0.0.1" style="margin-top:8px;">
      </div>

      <div class="form-row">
        <label>İkinci Host (opsiyonel — kombinasyon)</label>
        <div class="radio-group" data-group="pc-h2t" data-value="${pcapState.host2Type}">
          <div class="radio-pill ${pcapState.host2Type==='and'?'selected':''}" data-val="and">AND</div>
          <div class="radio-pill ${pcapState.host2Type==='or'?'selected':''}" data-val="or">OR</div>
          <div class="radio-pill ${pcapState.host2Type==='none'?'selected':''}" data-val="none">Yok</div>
        </div>
        <input type="text" id="pc-host2" value="${escAttr(pcapState.host2)}" placeholder="192.168.10.100" style="margin-top:8px;">
        <div class="helper">İki host kombinasyonu: <code>host A and host B</code> = sadece A↔B trafiği</div>
      </div>

      <div class="form-row">
        <label>Port Filtresi</label>
        <div class="radio-group" data-group="pc-pt" data-value="${pcapState.portType}">
          <div class="radio-pill ${pcapState.portType==='port'?'selected':''}" data-val="port">port (iki yön)</div>
          <div class="radio-pill ${pcapState.portType==='srcport'?'selected':''}" data-val="srcport">src port</div>
          <div class="radio-pill ${pcapState.portType==='dstport'?'selected':''}" data-val="dstport">dst port</div>
          <div class="radio-pill ${pcapState.portType==='portrange'?'selected':''}" data-val="portrange">portrange</div>
          <div class="radio-pill ${pcapState.portType===''?'selected':''}" data-val="">Yok</div>
        </div>
        <input type="text" id="pc-port" value="${escAttr(pcapState.port)}" placeholder="443 veya 10000-20000" style="margin-top:8px;">
      </div>

      <div class="form-row">
        <label>Snaplen (-s)</label>
        <div class="radio-group" data-group="pc-snap" data-value="${pcapState.snaplen}">
          <div class="radio-pill ${pcapState.snaplen==='0'?'selected':''}" data-val="0">0 (tüm paket)</div>
          <div class="radio-pill ${pcapState.snaplen==='96'?'selected':''}" data-val="96">96 (header only)</div>
          <div class="radio-pill ${pcapState.snaplen==='1500'?'selected':''}" data-val="1500">1500 (MTU)</div>
        </div>
      </div>

      <div class="form-row">
        <label>Ring Buffer — Dosya Boyutu MB (-C)</label>
        <input type="text" id="pc-rsize" value="${escAttr(pcapState.ringSize)}" placeholder="50 (boş = yok)">
        <div class="helper">Her dosya bu MB'a ulaşınca yenisi açılır</div>
      </div>

      <div class="form-row">
        <label>Ring Buffer — Dosya Adedi (-W)</label>
        <input type="text" id="pc-rcount" value="${escAttr(pcapState.ringCount)}" placeholder="3 (boş = sınırsız)">
        <div class="helper">Bu kadar dosya olunca eskisi silinir (rotation)</div>
      </div>

      <div class="form-row">
        <label>Süre Sınırı (-G saniye)</label>
        <input type="text" id="pc-time" value="${escAttr(pcapState.timeLimit)}" placeholder="300 (boş = sınırsız)">
      </div>

      <div class="form-row">
        <label>Çıktı Dosyası (-w)</label>
        <input type="text" id="pc-out" value="${escAttr(pcapState.output)}" placeholder="/var/tmp/cap.pcap">
      </div>

      ${pcapState.platform === 'f5' ? `
      <div class="form-row">
        <label>F5 Özel Bayraklar</label>
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--text-1);font-size:13px;margin:6px 0;">
          <input type="checkbox" id="pc-ssl" ${pcapState.sslprovider?'checked':''}> <code>--f5 ssl</code> (sslprovider TLS deşifre için)
        </label>
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--text-1);font-size:13px;margin:6px 0;">
          <input type="checkbox" id="pc-verbose" ${pcapState.verbose?'checked':''}> <code>-vvv</code> (verbose)
        </label>
      </div>
      ` : ''}
    </div>

    <div class="preview-box">
      <div class="preview-label">tcpdump Komutu</div>
      <div class="preview-code" id="pc-preview"><span class="empty">...</span></div>
    </div>

    <div class="btn-row">
      <button class="btn btn-primary" onclick="copyPcapCommand()">📋 Kopyala</button>
      <button class="btn" onclick="copySshPipeCommand()">📡 SSH+Wireshark Pipe</button>
    </div>

    ${pcapState.platform === 'f5' && pcapState.sslprovider ? `
    <div class="wizard-hint" style="margin-top:16px;">
      💡 <strong>sslprovider Tam İş Akışı:</strong><br>
      1. <code>tmsh modify sys db tcpdump.sslprovider value enable</code><br>
      2. Yukarıdaki komutu çalıştır (capture al)<br>
      3. <code>tmsh modify sys db tcpdump.sslprovider value disable</code><br>
      4. PCAP'i indir: <code>scp root@f5:${pcapState.output} ./</code><br>
      5. Key çıkar: <code>tshark -r ${pcapState.output.split('/').pop()} -Y "f5ethtrailer.tls.keylog" -T fields -e f5ethtrailer.tls.keylog | sed 's/,/\\n/g' > keys.pms</code><br>
      6. Wireshark → Preferences → TLS → keys.pms yükle
    </div>
    ` : ''}
  `;

  // Events
  document.querySelectorAll("[data-platform]").forEach(p => {
    p.onclick = () => {
      const plat = PCAP_PLATFORMS.find(x => x.id === p.dataset.platform);
      pcapState.platform = plat.id;
      pcapState.iface = plat.iface;
      pcapState.output = plat.outPath;
      renderPcapBuilder();
    };
  });

  document.querySelectorAll('.radio-group .radio-pill').forEach(p => {
    p.onclick = () => {
      const g = p.closest('.radio-group');
      g.querySelectorAll('.radio-pill').forEach(x => x.classList.remove("selected"));
      p.classList.add("selected");
      g.dataset.value = p.dataset.val;
      const gid = g.dataset.group;
      if (gid === "pc-h1t") pcapState.host1Type = p.dataset.val;
      if (gid === "pc-h2t") pcapState.host2Type = p.dataset.val;
      if (gid === "pc-pt") pcapState.portType = p.dataset.val;
      if (gid === "pc-snap") pcapState.snaplen = p.dataset.val;
      updatePcap();
    };
  });

  ["pc-iface","pc-host1","pc-host2","pc-port","pc-rsize","pc-rcount","pc-time","pc-out"].forEach(id => {
    const el2 = document.getElementById(id);
    if (el2) el2.oninput = updatePcap;
  });
  ["pc-ssl","pc-verbose"].forEach(id => {
    const el2 = document.getElementById(id);
    if (el2) el2.onchange = updatePcap;
  });

  updatePcap();
}

function updatePcap() {
  pcapState.iface = document.getElementById("pc-iface")?.value.trim() || "";
  pcapState.host1 = document.getElementById("pc-host1")?.value.trim() || "";
  pcapState.host2 = document.getElementById("pc-host2")?.value.trim() || "";
  pcapState.port = document.getElementById("pc-port")?.value.trim() || "";
  pcapState.ringSize = document.getElementById("pc-rsize")?.value.trim() || "";
  pcapState.ringCount = document.getElementById("pc-rcount")?.value.trim() || "";
  pcapState.timeLimit = document.getElementById("pc-time")?.value.trim() || "";
  pcapState.output = document.getElementById("pc-out")?.value.trim() || "";
  pcapState.sslprovider = document.getElementById("pc-ssl")?.checked || false;
  pcapState.verbose = document.getElementById("pc-verbose")?.checked || false;

  let parts = ["tcpdump"];
  if (pcapState.iface) parts.push("-i", pcapState.iface);
  parts.push("-nn");
  parts.push("-s", pcapState.snaplen);

  if (pcapState.verbose) parts.push("-vvv");
  if (pcapState.platform === "f5" && pcapState.sslprovider) parts.push("--f5", "ssl");

  // BPF expression
  let bpf = [];
  if (pcapState.host1Type !== "none" && pcapState.host1) {
    bpf.push(`${pcapState.host1Type} ${pcapState.host1}`);
  }
  if (pcapState.host2Type !== "none" && pcapState.host2) {
    const op = pcapState.host2Type;
    const prefix = pcapState.host1Type === "net" ? "net" : "host";
    bpf.push(`${op} ${prefix} ${pcapState.host2}`);
  }
  if (pcapState.portType && pcapState.port) {
    const connector = bpf.length ? "and" : "";
    bpf.push(`${connector} ${pcapState.portType} ${pcapState.port}`.trim());
  }

  if (bpf.length) {
    const expr = bpf.join(" ").trim();
    parts.push(`'${expr}'`);
  }

  if (pcapState.ringSize) parts.push("-C", pcapState.ringSize);
  if (pcapState.ringCount) parts.push("-W", pcapState.ringCount);
  if (pcapState.timeLimit) parts.push("-G", pcapState.timeLimit);
  if (pcapState.output) parts.push("-w", pcapState.output);

  const cmd = parts.join(" ");
  const out = document.getElementById("pc-preview");
  if (out) {
    out.innerHTML = escHTML(cmd);
    out.classList.remove("empty");
  }
}

function copyPcapCommand() {
  const out = document.getElementById("pc-preview");
  const cmd = out.textContent.trim();
  if (!cmd) return;
  copyText(cmd);
}

function copySshPipeCommand() {
  const out = document.getElementById("pc-preview");
  let cmd = out.textContent.trim();
  // Replace -w path with -w - and wrap in ssh
  cmd = cmd.replace(/-w\s+\S+/, "-w -");
  const ssh = `ssh root@HOST "${cmd}" | wireshark -k -i -`;
  copyText(ssh);
  showToast("SSH pipe komutu kopyalandı — HOST'u değiştir");
}

/* ═══════════════════════════════════════════════════════════════
   INTERACTIVE CHECKLIST
   ═══════════════════════════════════════════════════════════════ */

function renderChecklist() {
  const el = document.getElementById("checklist");

  // Calculate progress
  const items = CHECKLIST[activeChecklistCat] || [];
  const checked = items.filter(i => checklistState[`${activeChecklistCat}/${i.id}`]).length;
  const pct = items.length ? Math.round(checked / items.length * 100) : 0;

  el.innerHTML = `
    <div class="section-header">
      <h2>Kontrol Listesi — Ne Kontrol Edilecek?</h2>
      <div class="description">Kategori seç → soruları sırayla cevapla. "Nasıl kontrol edilir?" ve "Neden önemli?" her adımda açık.</div>
    </div>

    <div class="content-block">
      <h3>Kategori</h3>
      <div class="check-group">
        ${CHECKLIST_CATEGORIES.map(c => `
          <div class="check-pill ${activeChecklistCat===c.id?'selected':''}" data-cl-cat="${c.id}">
            ${c.icon} ${escHTML(c.name)}
          </div>
        `).join("")}
      </div>
    </div>

    <div class="content-block">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
        <h3 style="margin:0;">${CHECKLIST_CATEGORIES.find(c=>c.id===activeChecklistCat).name}</h3>
        <div style="font-size:12px;color:var(--text-2);">
          ${checked}/${items.length} tamamlandı · %${pct}
        </div>
      </div>

      <div style="background:var(--bg-2);border-radius:6px;height:6px;overflow:hidden;margin-bottom:16px;">
        <div style="background:var(--accent);height:100%;width:${pct}%;transition:width 0.3s;"></div>
      </div>

      <div id="checklist-items">
        ${items.map((item, i) => {
          const key = `${activeChecklistCat}/${item.id}`;
          const isChecked = !!checklistState[key];
          return `
            <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:10px;${isChecked?'opacity:0.6;':''}">
              <div style="display:flex;gap:12px;align-items:flex-start;">
                <label style="display:flex;align-items:center;cursor:pointer;padding-top:2px;">
                  <input type="checkbox" data-check="${key}" ${isChecked?'checked':''} style="width:18px;height:18px;cursor:pointer;accent-color:var(--accent);">
                </label>
                <div style="flex:1;">
                  <div style="font-size:13px;color:var(--text-0);font-weight:600;margin-bottom:6px;${isChecked?'text-decoration:line-through;':''}">
                    ${i+1}. ${escHTML(item.q)}
                  </div>
                  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;">
                    <div style="background:var(--bg-1);padding:8px 10px;border-radius:4px;border-left:3px solid var(--info);">
                      <div style="font-size:10px;text-transform:uppercase;color:var(--info);letter-spacing:0.5px;margin-bottom:3px;">Nasıl?</div>
                      <div style="font-size:11px;color:var(--text-1);">${escHTML(item.how)}</div>
                    </div>
                    <div style="background:var(--bg-1);padding:8px 10px;border-radius:4px;border-left:3px solid var(--warn);">
                      <div style="font-size:10px;text-transform:uppercase;color:var(--warn);letter-spacing:0.5px;margin-bottom:3px;">Neden?</div>
                      <div style="font-size:11px;color:var(--text-1);">${escHTML(item.why)}</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          `;
        }).join("")}
      </div>

      <div class="btn-row" style="margin-top:16px;">
        <button class="btn" onclick="resetChecklistCategory()">🔄 Bu Kategoriyi Sıfırla</button>
        <button class="btn btn-danger" onclick="resetAllChecklist()">🗑 Tüm Kategorileri Sıfırla</button>
      </div>
    </div>
  `;

  document.querySelectorAll("[data-cl-cat]").forEach(p => {
    p.onclick = () => {
      activeChecklistCat = p.dataset.clCat;
      renderChecklist();
    };
  });

  document.querySelectorAll("[data-check]").forEach(c => {
    c.onchange = () => {
      const key = c.dataset.check;
      if (c.checked) checklistState[key] = true;
      else delete checklistState[key];
      localStorage.setItem("wh-checklist", JSON.stringify(checklistState));
      renderChecklist();
    };
  });
}

function resetChecklistCategory() {
  Object.keys(checklistState).forEach(k => {
    if (k.startsWith(activeChecklistCat + "/")) delete checklistState[k];
  });
  localStorage.setItem("wh-checklist", JSON.stringify(checklistState));
  renderChecklist();
  showToast("Kategori sıfırlandı");
}

function resetAllChecklist() {
  if (!confirm("Tüm kategorilerde ilerlemeyi silmek istiyor musun?")) return;
  checklistState = {};
  localStorage.setItem("wh-checklist", "{}");
  renderChecklist();
  showToast("Tümü sıfırlandı");
}

/* ═══════════════════════════════════════════════════════════════
   PACKET ENCYCLOPEDIA DATA
   ═══════════════════════════════════════════════════════════════ */

const ENCYCLOPEDIA = {
  "tcp-analysis": {
    name: "TCP Analiz Olayları",
    icon: "🔍",
    desc: "Wireshark'ın otomatik tespit ettiği TCP anomalileri — 'retransmission nedir?' gibi sorular buradan",
    entries: [
      { code: "Retransmission", name: "Yeniden İletim", what: "Aynı TCP segment'in tekrar gönderilmesi. Önceki gönderim onaylanmadı (ACK gelmedi) veya RTO doldu.", why: "Paket yolda kayboldu (path loss), sunucu cevap vermedi, veya ACK geri dönüş yolunda kayboldu. Genelde fiziksel ağda paket kaybı, congestion, veya cihaz arıza göstergesi.", action: "IO Graph'ta overlay yap (tcp.analysis.retransmission) — zamansal pattern ara. %1+ oranı sorun. Path'teki her hop'u kontrol et. TCP Stream Graph → Time-Sequence ile görsel incele.", filter: "tcp.analysis.retransmission", related: ["Fast Retransmission", "Duplicate ACK", "RTO"] },
      { code: "Fast Retransmission", name: "Hızlı Yeniden İletim", what: "3 duplicate ACK aldıktan sonra gönderilen retransmission. RTO beklemeden hemen tekrar gönderir.", why: "Alıcı aynı sequence'i 3 kez istedi → 'paketi alamadım' sinyali. Gönderici beklemeden tekrar yollar (fast recovery).", action: "Path'te paket kaybı var — kabul edilebilir seviyede olabilir. Ancak sık görülüyorsa path iyileştirilmeli.", filter: "tcp.analysis.fast_retransmission", related: ["Retransmission", "Duplicate ACK"] },
      { code: "Spurious Retransmission", name: "Sahte Yeniden İletim", what: "Aslında gereksiz olan retransmission. Orijinal paket geç de olsa ulaşmış ama retrans yapıldı.", why: "Gönderici acele etti, ACK geç geldi. RTT değişkenliği veya yanlış RTO hesaplaması nedeniyle.", action: "Kendisi sorun değil ama sıklık analizi yap. Path'te jitter/gecikme değişkenliği var demek.", filter: "tcp.analysis.spurious_retransmission", related: ["Retransmission", "Out-of-Order"] },
      { code: "Duplicate ACK", name: "Tekrar Eden Onay", what: "Aynı ACK numarasının 2+ kez gelmesi. Alıcı 'beklediğim sıra henüz gelmedi' diyor.", why: "Bir paket kayboldu veya sıra dışı geldi → alıcı hâlâ eksik olanı bekliyor. 3 DupACK → fast retrans tetikler.", action: "Yakında retransmission gelecek demektir. Tek başına sorun değil, çokluk sorun. IO Graph'ta pattern ara.", filter: "tcp.analysis.duplicate_ack", related: ["Fast Retransmission", "Lost Segment"] },
      { code: "Out-of-Order", name: "Sıra Dışı Paket", what: "Beklenen sequence'ten farklı gelen paket. Paketler yoldaki farklı rotadan geldi.", why: "Path'te load balancing, ECMP, veya multi-path routing var. Packet reordering normal olabilir ama aşırı ise sorun.", action: "%1'den az normal. Sık ise routing/LB kontrol et. Receiver buffer'a hafif yük bindirir.", filter: "tcp.analysis.out_of_order", related: ["Retransmission", "Lost Segment"] },
      { code: "Zero Window", name: "Sıfır Pencere", what: "Alıcı 'şu an veri kabul edemiyorum' diyor (window=0). Gönderici DURMAK zorunda.", why: "Alıcı uygulama buffer'ı okuyamıyor/yavaş okuyor. Backend uygulamada yavaşlık, CPU yüksek, disk I/O darboğaz.", action: "Backend sağlığını kontrol et! App hung/yavaş/overloaded. Window update gelince devam eder. Bu kritik — timeout'a sebep olur.", filter: "tcp.analysis.zero_window", related: ["Window Full", "Window Update"] },
      { code: "Window Full", name: "Pencere Dolu", what: "Gönderici receiver window'u tamamen dolduruyor. Artık gönderemez, ACK beklemeli.", why: "Alıcı yavaş tüketiyor, gönderici hızlı üretiyor. Throughput darboğazı window büyüklüğüyle sınırlı.", action: "Window scaling kontrol et (ölçek faktörü yeterli mi). Backend kapasite yeterli mi? Alıcı daha büyük buffer kullansın.", filter: "tcp.analysis.window_full", related: ["Zero Window", "Window Update"] },
      { code: "Window Update", name: "Pencere Güncelleme", what: "Alıcı window boyutunu güncelliyor (genelde arttırıyor). 'Şimdi daha fazla veri alabilirim'.", why: "Alıcı uygulama buffer'dan veri okudu, yeni yer açıldı. Normal akışın parçası.", action: "Bilgi amaçlıdır, kendisi sorun değil. Ama zero window sonrası gelmiyorsa backend hâlâ yavaş.", filter: "tcp.analysis.window_update", related: ["Zero Window", "Window Full"] },
      { code: "Lost Segment", name: "Kayıp Segment", what: "Wireshark sequence numaralarından 'bir segment eksik' çıkarımı yapıyor.", why: "Gerçek paket kaybı (capture sırasında eksik değil, gerçek kayıp). Sequence atlaması görülüyor.", action: "Path'te ciddi paket kaybı. Ağ cihazları, fiziksel bağlantı, MTU sorunları kontrol edilmeli.", filter: "tcp.analysis.lost_segment", related: ["Retransmission", "Duplicate ACK"] },
      { code: "RTO", name: "Retransmission Timeout", what: "Gönderici RTO süresini bekledi ama ACK gelmedi → segment'i tekrar gönderdi.", why: "Fast retransmission da devreye giremedi (3 DupACK olmadı) veya RTT uzun. Ağırbaşlı paket kaybı.", action: "RTO = ortalama RTT * 2-4. Çok oluyorsa path latency çok yüksek veya ağır kayıp. Congestion window küçülür → throughput düşer.", filter: "tcp.analysis.rto", related: ["Retransmission", "Fast Retransmission"] },
      { code: "Keep-Alive", name: "Keepalive Probe", what: "Bağlantı boş durdukça gönderilen test paketi. 'Hâlâ var mısın?' sorusu.", why: "Taraflardan biri idle timeout'a karşı keepalive açık. Veya NAT/firewall session'u açık tutmak istiyor.", action: "Normal davranış. Ancak çok erken görülürse app-level keepalive ayarı yanlış. F5'te idle timeout kontrol et.", filter: "tcp.analysis.keep_alive", related: ["Keep-Alive ACK"] },
      { code: "ACKed Unseen", name: "Görülmeyen ACK", what: "ACK var ama orijinal paketi capture'da göremiyoruz.", why: "Capture noktası tek yönlü, asymmetric routing, veya paket kaçırıldı.", action: "Capture stratejisini gözden geçir. Her iki yönü de yakalayacak noktada capture al.", filter: "tcp.analysis.ack_lost_segment", related: ["Lost Segment"] }
    ]
  },
  "tcp-flags": {
    name: "TCP Bayrakları",
    icon: "🚩",
    desc: "TCP header'daki kontrol bayrakları — her biri farklı anlam",
    entries: [
      { code: "SYN", name: "Synchronize", what: "Yeni bağlantı başlatma isteği. Initial sequence number'ı paylaşır.", why: "Client yeni bir TCP bağlantısı açmak istiyor. 3-way handshake'in ilk paketi.", action: "SYN-ACK cevabı gelmeliyse; gelmiyorsa firewall/routing/sunucu sorunu.", filter: "tcp.flags.syn == 1 && tcp.flags.ack == 0", related: ["SYN-ACK", "ACK"] },
      { code: "SYN-ACK", name: "Synchronize + Acknowledge", what: "Server'ın client'ın SYN'ini onayladığı ve kendi sequence'ini paylaştığı paket.", why: "Server bağlantı talebini kabul etti. Handshake'in 2. adımı.", action: "Gelmiyorsa: port kapalı, firewall drop, server down. Geliyor ama ACK yok → client tarafı sorun.", filter: "tcp.flags.syn == 1 && tcp.flags.ack == 1", related: ["SYN", "ACK"] },
      { code: "ACK", name: "Acknowledge", what: "Alınan veriyi onaylayan paket. Sequence'i 'buraya kadar aldım' der.", why: "Her TCP paketinde (SYN hariç) ACK flag açıktır. Veri akışının onaylanması.", action: "ACK gelmiyorsa geri dönüş yolu sorunlu. Timestamp senkronizasyonuyla loss analizi yap.", filter: "tcp.flags.ack == 1", related: ["SYN-ACK"] },
      { code: "FIN", name: "Finish", what: "Bağlantıyı düzgün kapatma sinyali. 'Daha fazla veri göndermeyeceğim'.", why: "Tarafın göndereceği veri bitti, kapanış başlıyor. İki yönlü FIN-ACK akışı ile kapanır.", action: "Normal kapanış. RST yerine FIN görmek sağlıklı işaret.", filter: "tcp.flags.fin == 1", related: ["RST", "ACK"] },
      { code: "RST", name: "Reset", what: "Bağlantıyı zorla kesme. 'Bu bağlantı hata, şimdi kes' emri.", why: "Hata, policy drop, idle timeout, uygulama reject. Normal kapanışın aksine ani.", action: "RST kaynağına bak (ip.src). F5'ten → idle timeout, backend'den → app reject, firewall'dan → policy drop.", filter: "tcp.flags.reset == 1", related: ["FIN"] },
      { code: "PSH", name: "Push", what: "Buffer bekletmeden hemen uygulama katmanına verme sinyali.", why: "Gönderici 'bu veri kritik, hemen ilet' demek istiyor. Interactive uygulamalarda yaygın.", action: "Genelde önemsiz flag. Ama PSH+FIN aynı anda → hızlı kapanış kalıbı.", filter: "tcp.flags.push == 1", related: ["URG"] },
      { code: "URG", name: "Urgent", what: "Acil veri işareti. Urgent pointer ile birlikte kullanılır.", why: "Nadiren kullanılır. Telnet gibi legacy protokollerde iptal sinyali için.", action: "Modern protokollerde görülürse dikkat et — potansiyel eksploit veya anormallik.", filter: "tcp.flags.urg == 1", related: ["PSH"] },
      { code: "ECE/CWR", name: "ECN Echo / CWR", what: "Explicit Congestion Notification bayrakları. Ağda congestion sinyali.", why: "Router 'path dolu' dedi. Endpoint'ler hızı düşürmeli.", action: "ECN açıksa normal. Yoksa path'te congestion — queue yönetimi kontrol edilmeli.", filter: "tcp.flags.ece == 1 || tcp.flags.cwr == 1", related: [] }
    ]
  },
  "tls-handshake": {
    name: "TLS Handshake Tipleri",
    icon: "🔒",
    desc: "TLS handshake sürecinin her adımı — hangisinde takıldığını anla",
    entries: [
      { code: "1", name: "Client Hello", what: "TLS handshake'in ilk mesajı. Client destekled. cipher'ları, TLS versiyonunu, random değeri, SNI'yi gönderir.", why: "Client TLS başlatıyor. Sunucuya 'benim özelliklerim bunlar' diyor.", action: "Gelmiyorsa client TLS açmıyor — TCP handshake OK mı kontrol et. SNI doğru mu?", filter: "tls.handshake.type == 1", related: ["Server Hello", "SNI"] },
      { code: "2", name: "Server Hello", what: "Server'ın seçtiği cipher, TLS versiyonu, session ID, random değeri.", why: "Server 'client'ın önerilerinden bunu seçtim' diyor.", action: "Gelmiyorsa cipher/versiyon uyumsuzluğu veya server TLS config sorunu. Alert 40 olası.", filter: "tls.handshake.type == 2", related: ["Client Hello", "Cipher Suite"] },
      { code: "11", name: "Certificate", what: "Server sertifika zincirini gönderiyor (leaf + intermediate + root).", why: "Client sertifikayı doğrulamalı. Identity kanıtı.", action: "Gelmiyorsa server cert config hatalı. Zincir eksikse unknown_ca alert (48). Süresi dolmuşsa alert 45.", filter: "tls.handshake.type == 11", related: ["Certificate Verify", "Unknown CA"] },
      { code: "12", name: "Server Key Exchange", what: "DH/ECDHE parametreleri. Perfect Forward Secrecy için.", why: "Cipher ECDHE ise server temporary key paylaşır.", action: "Gelmiyorsa RSA cipher seçilmiş (PFS yok). Geliyorsa normal.", filter: "tls.handshake.type == 12", related: ["Client Key Exchange"] },
      { code: "14", name: "Server Hello Done", what: "Server 'handshake mesajlarım bitti, sıra sende' diyor.", why: "Server tarafı key/cert paylaşımını tamamladı, client'tan yanıt bekliyor.", action: "Gelmiyorsa server hâlâ yanıt hazırlıyor veya takıldı.", filter: "tls.handshake.type == 14", related: ["Client Key Exchange"] },
      { code: "16", name: "Client Key Exchange", what: "Client master secret oluşturmak için key material gönderir.", why: "Simetrik şifreleme için session key türetilecek.", action: "Gelmiyorsa client key material oluşturamadı — OS/library sorunu olabilir.", filter: "tls.handshake.type == 16", related: ["Server Key Exchange", "Finished"] },
      { code: "20", name: "Finished", what: "Handshake tamamlandı onayı. Şifreli kanal kuruldu.", why: "Hem client hem server Finished gönderdi = bağlantı hazır.", action: "Bu görülüyorsa TLS OK, veri akışı başlar. Görünmüyorsa handshake takıldı.", filter: "tls.handshake.type == 20", related: ["Application Data"] },
      { code: "21", name: "Alert (Fatal)", what: "TLS hata mesajı. Handshake sırasında veya sonrasında.", why: "Bir şey yanlış gitti — cert invalid, cipher mismatch, decrypt error...", action: "Alert kodunu not al (TLS Alert sözlüğüne bak). Handshake kesilir.", filter: "tls.alert_message", related: ["Alert Codes"] }
    ]
  },
  "tls-alerts": {
    name: "TLS Alert Kodları",
    icon: "⚠",
    desc: "TLS handshake hatalarında gelen alert kodları — ne anlama geldiklerini bil",
    entries: [
      { code: "0", name: "close_notify", what: "Normal TLS bağlantı kapatma bildirimi.", why: "Taraflardan biri düzgün şekilde TLS oturumunu kapatıyor.", action: "Normal — sorun değil. Ama handshake ortasında görülürse ani kapanış.", filter: 'tls.alert_message.desc == "Close Notify"', related: [] },
      { code: "10", name: "unexpected_message", what: "Protokol sırasında beklenmeyen mesaj geldi.", why: "Client/server protokol akışını yanlış takip etti. Implementation bug.", action: "TLS library versiyonlarını kontrol et. Protokol inconsistency var.", filter: 'tls.alert_message.desc == "Unexpected Message"', related: [] },
      { code: "20", name: "bad_record_mac", what: "Şifreli paketin MAC'i (integrity check) eşleşmedi.", why: "Paket bozuldu, ortada değişti, veya cryptographic state uyumsuz.", action: "MITM olabilir, network corruption olabilir. Cihaz aralarda paket modifiye ediyor mu?", filter: 'tls.alert_message.desc == "Bad Record MAC"', related: ["decrypt_error"] },
      { code: "30", name: "decompression_failure", what: "TLS compression başarısız oldu.", why: "Çok nadir — compression artık TLS 1.3'te yok.", action: "TLS 1.3'e geçmek en iyisi.", filter: 'tls.alert_message.desc == "Decompression Failure"', related: [] },
      { code: "40", name: "handshake_failure", what: "GENEL handshake başarısızlığı. En yaygın alert.", why: "Cipher suite uyumsuzluğu, TLS versiyon uyumsuzluğu, cert verification bypass ayarları.", action: "Client cipher list (Client Hello) ile server cipher list'i karşılaştır. F5 cipher profile kontrol et.", filter: 'tls.alert_message.desc contains "Handshake Failure"', related: ["Client Hello", "Server Hello"] },
      { code: "41", name: "no_certificate", what: "Client cert istenmiş ama gönderilmedi (mTLS'de).", why: "Mutual TLS gerektiren server, client'tan cert istedi ama client cert yok.", action: "Client cert kurulumu kontrol et. F5 LTM client-ssl profile 'client authentication' ayarları.", filter: 'tls.alert_message.desc contains "No Certificate"', related: ["certificate_required"] },
      { code: "42", name: "bad_certificate", what: "Sertifika geçersiz, bozuk, veya parse edilemedi.", why: "Cert dosyası bozuk, yanlış formatted, imza yanlış.", action: "Server sertifika dosyasını kontrol et. openssl ile validate et.", filter: 'tls.alert_message.desc contains "Bad Certificate"', related: ["unknown_ca", "certificate_expired"] },
      { code: "43", name: "unsupported_certificate", what: "Cert tipi desteklenmiyor.", why: "Server ECDSA cert kullanıyor ama client sadece RSA destekler (veya tersi).", action: "Cert tipini client desteğine göre değiştir.", filter: 'tls.alert_message.desc contains "Unsupported Certificate"', related: [] },
      { code: "44", name: "certificate_revoked", what: "Sertifika iptal edilmiş (CRL/OCSP).", why: "CA sertifikayı revoke etti — compromise edildiği için.", action: "Yeni cert alınmalı, CA'dan yeni imzalı cert iste.", filter: 'tls.alert_message.desc contains "Certificate Revoked"', related: [] },
      { code: "45", name: "certificate_expired", what: "Sertifika süresi dolmuş.", why: "Expiration date geçmiş. Monitoring eksik olmuş.", action: "HEMEN yeni cert al ve deploy et. Expiration monitoring kur (30 gün önceden uyarı).", filter: 'tls.alert_message.desc contains "Certificate Expired"', related: [] },
      { code: "46", name: "certificate_unknown", what: "Sertifika ile ilgili tanımlanamayan sorun.", why: "Genel cert hatası — intermediate missing, CN mismatch olabilir.", action: "openssl s_client ile sunucuyu test et. Sertifika zincirini kontrol et.", filter: 'tls.alert_message.desc contains "Certificate Unknown"', related: ["unknown_ca"] },
      { code: "47", name: "illegal_parameter", what: "Handshake mesajında yasa dışı parametre.", why: "TLS protokol kurallarına aykırı değer. Implementation hatası.", action: "Hem client hem server'ın TLS library versiyonlarını güncelle.", filter: 'tls.alert_message.desc contains "Illegal Parameter"', related: [] },
      { code: "48", name: "unknown_ca", what: "Client sunucunun CA'sını tanımıyor.", why: "Self-signed cert, intermediate CA eksik, veya private CA client'ta tanımlı değil.", action: "Server'a intermediate CA ekle. Private CA ise client'a CA cert'i yükle (trust store).", filter: 'tls.alert_message.desc contains "Unknown CA"', related: ["certificate_unknown"] },
      { code: "49", name: "access_denied", what: "Server client'a erişim reddetti (policy).", why: "Client cert valid ama server policy'si reject etti. mTLS'de yaygın.", action: "F5 ASM/iRule'lerde client cert validation policy'sini kontrol et.", filter: 'tls.alert_message.desc contains "Access Denied"', related: [] },
      { code: "50", name: "decode_error", what: "Handshake mesajı decode edilemedi.", why: "Bit bozulması, yanlış formatted mesaj.", action: "Network'te corruption var mı? MTU/fragmentation sorunu olabilir.", filter: 'tls.alert_message.desc contains "Decode Error"', related: [] },
      { code: "51", name: "decrypt_error", what: "Şifreli veri decrypt edilemedi.", why: "Key mismatch, signature verification failed.", action: "TLS state corruption — bağlantı sıfırdan yenilenmeli.", filter: 'tls.alert_message.desc contains "Decrypt Error"', related: ["bad_record_mac"] },
      { code: "70", name: "protocol_version", what: "Client istediği TLS versiyonunu server desteklemiyor.", why: "Client TLS 1.3 istiyor, server sadece 1.2 veya eski desteklıyor (veya tersi).", action: "F5 client-ssl profile → TLS versions ayarını gözden geçir.", filter: 'tls.alert_message.desc contains "Protocol Version"', related: [] },
      { code: "71", name: "insufficient_security", what: "Client sunulan cipher'ları güvenli bulmuyor.", why: "Modern client, eski weak cipher listesi alıyor.", action: "Server'da weak cipher'ları devre dışı bırak (RC4, DES, NULL ciphers).", filter: 'tls.alert_message.desc contains "Insufficient Security"', related: ["handshake_failure"] },
      { code: "80", name: "internal_error", what: "Server internal hata — detay verilmedi.", why: "Server crash, memory allocation fail, library error.", action: "Server loglarını kontrol et. TLS library memory/CPU durumunu izle.", filter: 'tls.alert_message.desc contains "Internal Error"', related: [] },
      { code: "112", name: "unrecognized_name", what: "SNI ile istenen host name sunucuda yok.", why: "Client SNI 'api.bank.com' gönderdi ama server bu name'i tanımıyor.", action: "F5 SNI routing kontrol et. Virtual server SNI mapping doğru mu?", filter: 'tls.alert_message.desc contains "Unrecognized Name"', related: ["SNI"] },
      { code: "116", name: "certificate_required", what: "Server mTLS istiyor ama client cert göndermedi (TLS 1.3).", why: "mTLS gerektiren endpoint, client cert zorunlu.", action: "Client cert deploy et. F5 client-ssl 'request-cert' veya 'require-cert' ayarı.", filter: 'tls.alert_message.desc contains "Certificate Required"', related: ["no_certificate"] }
    ]
  },
  "http-status": {
    name: "HTTP Status Kodları",
    icon: "🌐",
    desc: "HTTP yanıt kodları — özellikle 4xx/5xx'i doğru yorumla (fintech bağlamında)",
    entries: [
      { code: "200", name: "OK", what: "Normal başarılı yanıt.", why: "İstek başarılı işlendi, response body dönüldü.", action: "Sorun yok. Response time'ı izle — 200 geliyor ama yavaşsa backend inceleme.", filter: "http.response.code == 200", related: [] },
      { code: "301", name: "Moved Permanently", what: "Kalıcı yönlendirme.", why: "URL değişti, kalıcı olarak başka yere gidilmeli.", action: "F5 redirect iRule veya HTTP profile 'insert location' kontrol et.", filter: "http.response.code == 301", related: ["302"] },
      { code: "302", name: "Found", what: "Geçici yönlendirme.", why: "Şimdilik başka yere gidin, ileride geri gelin.", action: "SSL redirect (80→443) genelde 302'dir. Normal akış olabilir.", filter: "http.response.code == 302", related: ["301"] },
      { code: "400", name: "Bad Request", what: "İstek formatı hatalı.", why: "Malformed HTTP, header eksik/fazla, F5 tarafı parse edemedi.", action: "Client'ın gönderdiği request'i incele (Follow HTTP Stream). F5 WAF/ASM block yapmış olabilir.", filter: "http.response.code == 400", related: ["WAF"] },
      { code: "401", name: "Unauthorized", what: "Kimlik doğrulama başarısız/eksik.", why: "Token missing, invalid, expired. Authorization header sorunu.", action: "Client auth header'ını kontrol et. Token expiry süresi doğru mu?", filter: "http.response.code == 401", related: ["403"] },
      { code: "403", name: "Forbidden", what: "Yetkin yok, reddedildi.", why: "Auth OK ama bu kaynağa erişimin yok. F5 WAF/ASM block da olabilir.", action: "F5 WAF loglarını incele (ASM event logs). Policy kural kontrolü.", filter: "http.response.code == 403", related: ["401", "WAF Block"] },
      { code: "404", name: "Not Found", what: "Kaynak yok.", why: "URL yanlış, backend'de o endpoint yok, rewrite rule yanlış.", action: "F5 HTTP Class / iRule URI routing kontrol et. Backend endpoint doğru mu?", filter: "http.response.code == 404", related: [] },
      { code: "408", name: "Request Timeout", what: "Client istek göndermede çok yavaş kaldı.", why: "Client request tamamlanmadı, server bekledi ve kapattı.", action: "Client yavaş bağlantı üzerinden gönderiyor. Network latency kontrolü.", filter: "http.response.code == 408", related: ["504"] },
      { code: "413", name: "Payload Too Large", what: "Request body çok büyük.", why: "F5 max-requestbody limiti aşıldı veya backend limit.", action: "F5 HTTP profile → max-request-body-size ayarını kontrol et.", filter: "http.response.code == 413", related: [] },
      { code: "429", name: "Too Many Requests", what: "Rate limit aşıldı.", why: "Client çok fazla istek yolluyor. F5 rate-limit policy aktif.", action: "Rate limit threshold'unu gözden geçir. Client davranışı normal mi?", filter: "http.response.code == 429", related: [] },
      { code: "500", name: "Internal Server Error", what: "Backend uygulama hatası.", why: "App crash, null pointer, DB connection fail — backend kodu hata verdi.", action: "Backend application loglarını kontrol et. App ekibine eskalasyon.", filter: "http.response.code == 500", related: ["502", "503"] },
      { code: "502", name: "Bad Gateway", what: "Upstream'den geçersiz yanıt geldi.", why: "F5 backend'e istek yolladı, backend bozuk response döndü veya bağlantı kesildi.", action: "Backend pool member sağlığı. F5 health monitor durumu. Backend log.", filter: "http.response.code == 502", related: ["503", "504"] },
      { code: "503", name: "Service Unavailable", what: "Servis kullanılamıyor — genelde F5 pool tamamen down.", why: "Pool'daki tüm member'lar health check'i geçemiyor. Hepsi down/unhealthy.", action: "F5 pool status (tmsh show ltm pool). Health monitor konfigürasyonu. Backend kapasitesi.", filter: "http.response.code == 503", related: ["502"] },
      { code: "504", name: "Gateway Timeout", what: "F5 backend'den yanıt bekledi, zaman aşımı.", why: "Backend yanıt vermedi (connect veya response timeout). F5 giveup oldu.", action: "F5 HTTP profile timeout'larını kontrol et (idle-timeout, server-timeout). Backend performansı.", filter: "http.response.code == 504", related: ["502", "503"] },
      { code: "505", name: "HTTP Version Not Supported", what: "HTTP versiyonu desteklenmiyor.", why: "Client HTTP/2 istiyor, backend HTTP/1.1 only.", action: "F5 HTTP/2 profile kontrol et. Backend HTTP versiyonu.", filter: "http.response.code == 505", related: [] }
    ]
  },
  "sip-status": {
    name: "SIP Status Kodları",
    icon: "📞",
    desc: "SIP yanıt kodları — INVITE sonrası dönen cevaplar",
    entries: [
      { code: "100", name: "Trying", what: "'İsteğini alıyorum, işliyorum'.", why: "INVITE sonrası provisional yanıt. Normal akış.", action: "Normal — sonra 180/200 gelmeli.", filter: "sip.Status-Code == 100", related: ["180", "200"] },
      { code: "180", name: "Ringing", what: "'Telefon çalıyor'.", why: "Aranan telefon çalıyor, cevap bekliyor.", action: "Normal — sonra 200 (cevaplandı) veya 486 (meşgul) gelmeli.", filter: "sip.Status-Code == 180", related: ["200", "486"] },
      { code: "200", name: "OK", what: "Başarılı — çağrı kuruldu (INVITE) veya istek tamamlandı.", why: "Aranan telefon cevapladı. Normal akış.", action: "Sonra ACK gönderilmeli. SDP'deki RTP bilgisine bak.", filter: "sip.Status-Code == 200", related: ["ACK", "SDP"] },
      { code: "302", name: "Moved Temporarily", what: "Çağrı başka yere yönlendirilsin.", why: "Aranan kişi başka numarada — call forwarding.", action: "SIP yönlendirme akışı — normal.", filter: "sip.Status-Code == 302", related: [] },
      { code: "401", name: "Unauthorized", what: "Credential gerekli.", why: "SIP server kimlik doğrulama istiyor. Digest auth challenge.", action: "Normal — client credentials ile tekrar INVITE yollamalı.", filter: "sip.Status-Code == 401", related: ["403"] },
      { code: "403", name: "Forbidden", what: "Erişim yasak.", why: "IP yasaklı, credentials yanlış, SIP peer tanınmıyor.", action: "F5/firewall SIP peer IP listesi. Auth credentials.", filter: "sip.Status-Code == 403", related: [] },
      { code: "404", name: "Not Found", what: "Aranan numara/URI yok.", why: "Dial plan'da olmayan numara, yanlış SIP URI.", action: "SIP server routing/dial plan kontrol et.", filter: "sip.Status-Code == 404", related: [] },
      { code: "408", name: "Request Timeout", what: "SIP istek zaman aşımına uğradı.", why: "Karşı taraf yanıt vermedi.", action: "Network'te UDP paket kaybı olabilir. SIP server'a erişim?", filter: "sip.Status-Code == 408", related: [] },
      { code: "480", name: "Temporarily Unavailable", what: "Kullanıcı şu an cevap veremez.", why: "Telefon DND modda veya internet yok.", action: "Normal — beklenen senaryo.", filter: "sip.Status-Code == 480", related: [] },
      { code: "481", name: "Call Leg Does Not Exist", what: "Referans edilen call session yok.", why: "BYE/UPDATE geldi ama o çağrı zaten kapanmış.", action: "SIP state mismatch — session management bug olabilir.", filter: "sip.Status-Code == 481", related: [] },
      { code: "486", name: "Busy Here", what: "Aranan meşgul.", why: "Aranan telefon zaten başka aramada.", action: "Normal — beklenen senaryo.", filter: "sip.Status-Code == 486", related: [] },
      { code: "487", name: "Request Terminated", what: "Çağrı iptal edildi.", why: "Arayan CANCEL yolladı veya aranan cevap vermeden kapattı.", action: "Normal kapanış.", filter: "sip.Status-Code == 487", related: ["CANCEL"] },
      { code: "488", name: "Not Acceptable Here", what: "SDP teklifi kabul edilmez — codec uyumsuz.", why: "İki taraf ortak codec bulamadı.", action: "SDP içeriklerini incele. F5 SIP ALG codec manipulation yapıyor olabilir.", filter: "sip.Status-Code == 488", related: ["SDP"] },
      { code: "500", name: "Server Internal Error", what: "SIP server iç hatası.", why: "Server crash, config hatası, DB down.", action: "SIP server logları acil incelenmeli.", filter: "sip.Status-Code == 500", related: ["503"] },
      { code: "503", name: "Service Unavailable", what: "SIP servisi kullanılamıyor.", why: "Overload, capacity dolu, yakında restart.", action: "SIP server kapasite/yük kontrolü.", filter: "sip.Status-Code == 503", related: [] },
      { code: "603", name: "Decline", what: "Aranan çağrıyı reddetti.", why: "Kullanıcı manuel reject etti (red tuşu).", action: "Normal — kullanıcı tercihi.", filter: "sip.Status-Code == 603", related: [] }
    ]
  },
  "sip-methods": {
    name: "SIP Method'ları",
    icon: "📤",
    desc: "SIP request metodları — hangi amaçla kullanılır",
    entries: [
      { code: "INVITE", name: "Invite", what: "Yeni SIP oturumu (çağrı) başlatma.", why: "Arama başlatılıyor. SDP ile medya parametreleri paylaşılır.", action: "100→180→200 yanıt akışı normal. SDP içeriğini incele.", filter: 'sip.Method == "INVITE"', related: ["ACK", "BYE"] },
      { code: "ACK", name: "Acknowledge", what: "INVITE'a gelen 200 OK'i onaylıyor.", why: "3-way SIP handshake'in son adımı — 'kurulumu tamamladım'.", action: "Normal akış.", filter: 'sip.Method == "ACK"', related: ["INVITE"] },
      { code: "BYE", name: "Bye", what: "Aktif çağrıyı sonlandırma.", why: "Taraflardan biri kapatıyor.", action: "200 OK yanıtı gelmeli. Gelmiyorsa call state sorunu.", filter: 'sip.Method == "BYE"', related: ["CANCEL"] },
      { code: "CANCEL", name: "Cancel", what: "Tamamlanmamış isteği iptal et (genelde INVITE).", why: "Arayan cevap beklerken iptal etti.", action: "487 yanıtı gelmeli.", filter: 'sip.Method == "CANCEL"', related: ["487"] },
      { code: "REGISTER", name: "Register", what: "SIP kullanıcı konumunu bildirme.", why: "Telefon online oluyor, SIP server'a 'buradayım' diyor.", action: "401 challenge → credentials → 200 OK akışı normal.", filter: 'sip.Method == "REGISTER"', related: ["401"] },
      { code: "OPTIONS", name: "Options", what: "Destek sorgulama / keepalive.", why: "'Hangi metodları destekliyorsun?' veya canlılık kontrolü.", action: "SIP peer keepalive için yaygın. Normal.", filter: 'sip.Method == "OPTIONS"', related: [] },
      { code: "REFER", name: "Refer", what: "Çağrı transferi.", why: "Aranan 'bu çağrıyı şuraya aktar' diyor.", action: "Blind/attended transfer için kullanılır.", filter: 'sip.Method == "REFER"', related: [] },
      { code: "NOTIFY", name: "Notify", what: "Subscription güncellemesi.", why: "Mesaj bekleniyor, presence değişti vs.", action: "Asenkron bildirim — normal.", filter: 'sip.Method == "NOTIFY"', related: ["SUBSCRIBE"] },
      { code: "SUBSCRIBE", name: "Subscribe", what: "Bildirim aboneliği.", why: "Belirli bir olayı dinlemek için kayıt.", action: "NOTIFY ile cevaplanır.", filter: 'sip.Method == "SUBSCRIBE"', related: ["NOTIFY"] }
    ]
  },
  "icmp": {
    name: "ICMP Tipleri",
    icon: "📡",
    desc: "ICMP mesajları — ağ sorun sinyalleri",
    entries: [
      { code: "0", name: "Echo Reply", what: "Ping yanıtı.", why: "Ping isteğine cevap — host erişilebilir.", action: "Normal — RTT ölç.", filter: "icmp.type == 0", related: ["8"] },
      { code: "3", name: "Destination Unreachable", what: "Hedefe erişilemiyor.", why: "Code'a göre değişir: 0=net unreach, 1=host unreach, 3=port unreach, 4=fragmentation needed.", action: "ICMP code'u kritik — routing/firewall/port sorunu.", filter: "icmp.type == 3", related: [] },
      { code: "3/4", name: "Fragmentation Needed (MTU)", what: "Path MTU discovery için — 'DF bit set ama fragment gerekli'.", why: "Path'te küçük MTU var, paket bölünemez.", action: "MTU sorunu! Path MTU discovery blok ediliyor → black hole.", filter: "icmp.type == 3 && icmp.code == 4", related: [] },
      { code: "5", name: "Redirect", what: "'Bu trafiği başka gateway'e yolla' yönlendirmesi.", why: "Router daha iyi rota öneriyor.", action: "Genelde güvenlik riski — spoofing olabilir.", filter: "icmp.type == 5", related: [] },
      { code: "8", name: "Echo Request", what: "Ping isteği.", why: "Host canlılık testi.", action: "Normal.", filter: "icmp.type == 8", related: ["0"] },
      { code: "11", name: "Time Exceeded (TTL)", what: "TTL=0 oldu, paket düştü.", why: "Routing loop veya TTL çok kısa.", action: "Traceroute'un çalışma prensibi. Loop varsa acil fix.", filter: "icmp.type == 11", related: [] }
    ]
  },
  "dns-rcode": {
    name: "DNS Response Codes",
    icon: "🌍",
    desc: "DNS sorgularının yanıt kodları",
    entries: [
      { code: "0", name: "NOERROR", what: "Başarılı DNS yanıtı.", why: "Sorgu çözüldü, kayıt bulundu.", action: "Normal — ama yanıtta kayıt sıfırsa 'exists but no record'.", filter: "dns.flags.rcode == 0", related: [] },
      { code: "1", name: "FORMERR", what: "Sorgu format hatası.", why: "Client malformed query yolladı.", action: "DNS client bug veya middlebox manipulation.", filter: "dns.flags.rcode == 1", related: [] },
      { code: "2", name: "SERVFAIL", what: "DNS server iç hatası.", why: "Upstream sorgu başarısız, server config hatası, DNSSEC validation fail.", action: "DNS server loglarını kontrol et. Upstream server durumu.", filter: "dns.flags.rcode == 2", related: [] },
      { code: "3", name: "NXDOMAIN", what: "Domain yok.", why: "Sorulan domain adı DNS'te tanımlı değil.", action: "Yazım hatası mı? Domain gerçekten var mı?", filter: "dns.flags.rcode == 3", related: [] },
      { code: "5", name: "REFUSED", what: "Server sorguyu reddetti.", why: "ACL (access control) blok ediyor. Recursion denied.", action: "DNS server ACL kontrolü. Client doğru DNS server'ı mı kullanıyor?", filter: "dns.flags.rcode == 5", related: [] }
    ]
  }
};

let activeEncyclopediaCat = "tcp-analysis";
let encyclopediaSearch = "";

/* ═══════════════════════════════════════════════════════════════
   ENCYCLOPEDIA RENDER
   ═══════════════════════════════════════════════════════════════ */

function renderEncyclopedia() {
  const el = document.getElementById("encyclopedia");
  const cats = Object.entries(ENCYCLOPEDIA);

  // Search across all entries if search query exists
  let visibleEntries;
  if (encyclopediaSearch) {
    const q = encyclopediaSearch.toLowerCase();
    visibleEntries = [];
    cats.forEach(([catId, cat]) => {
      cat.entries.forEach(e => {
        if (
          e.code.toLowerCase().includes(q) ||
          e.name.toLowerCase().includes(q) ||
          e.what.toLowerCase().includes(q) ||
          e.why.toLowerCase().includes(q) ||
          (e.filter || "").toLowerCase().includes(q)
        ) {
          visibleEntries.push({ catId, catName: cat.name, ...e });
        }
      });
    });
  } else {
    const cat = ENCYCLOPEDIA[activeEncyclopediaCat];
    visibleEntries = cat.entries.map(e => ({ catId: activeEncyclopediaCat, catName: cat.name, ...e }));
  }

  el.innerHTML = `
    <div class="section-header">
      <h2>Paket Sözlüğü</h2>
      <div class="description">Paket tipini/kodunu ara — ne demek, neden oluşur, ne yapmalı öğren.</div>
    </div>

    <div class="content-block">
      <div class="form-row" style="margin-bottom:8px;">
        <input type="text" id="enc-search" value="${escAttr(encyclopediaSearch)}" placeholder="Ara: retransmission, SYN, 503, handshake_failure, zero window..." autofocus>
      </div>

      ${!encyclopediaSearch ? `
      <div class="check-group">
        ${cats.map(([id, c]) => `
          <div class="check-pill ${activeEncyclopediaCat===id?'selected':''}" data-enc-cat="${id}">
            ${c.icon} ${escHTML(c.name)} (${c.entries.length})
          </div>
        `).join("")}
      </div>
      ` : `<div style="font-size:12px;color:var(--text-2);margin-bottom:8px;">${visibleEntries.length} sonuç bulundu "${escHTML(encyclopediaSearch)}" için</div>`}

      ${!encyclopediaSearch ? `<p class="hint" style="margin-top:10px;">${escHTML(ENCYCLOPEDIA[activeEncyclopediaCat].desc)}</p>` : ""}
    </div>

    ${visibleEntries.length === 0 ? `
      <div class="content-block" style="text-align:center;color:var(--text-2);padding:40px;">
        Eşleşme yok. Başka terim dene.
      </div>
    ` : visibleEntries.map(e => `
      <div class="content-block" style="margin-bottom:10px;">
        <div style="display:flex;gap:12px;align-items:flex-start;">
          <div style="background:var(--accent);color:#fff;padding:8px 12px;border-radius:6px;font-family:var(--mono);font-size:14px;font-weight:600;min-width:60px;text-align:center;">${escHTML(e.code)}</div>
          <div style="flex:1;">
            <h3 style="margin-bottom:4px;">${escHTML(e.name)}</h3>
            ${encyclopediaSearch ? `<div style="font-size:10px;color:var(--text-2);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px;">${escHTML(e.catName)}</div>` : ""}

            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-top:10px;">
              <div style="background:var(--bg-2);padding:10px 12px;border-radius:6px;border-left:3px solid var(--info);">
                <div style="font-size:10px;text-transform:uppercase;color:var(--info);letter-spacing:0.5px;margin-bottom:4px;font-weight:600;">Ne demek?</div>
                <div style="font-size:12px;color:var(--text-1);line-height:1.5;">${escHTML(e.what)}</div>
              </div>
              <div style="background:var(--bg-2);padding:10px 12px;border-radius:6px;border-left:3px solid var(--warn);">
                <div style="font-size:10px;text-transform:uppercase;color:var(--warn);letter-spacing:0.5px;margin-bottom:4px;font-weight:600;">Neden oluşur?</div>
                <div style="font-size:12px;color:var(--text-1);line-height:1.5;">${escHTML(e.why)}</div>
              </div>
              <div style="background:var(--bg-2);padding:10px 12px;border-radius:6px;border-left:3px solid var(--ok);">
                <div style="font-size:10px;text-transform:uppercase;color:var(--ok);letter-spacing:0.5px;margin-bottom:4px;font-weight:600;">Ne yapmalı?</div>
                <div style="font-size:12px;color:var(--text-1);line-height:1.5;">${escHTML(e.action)}</div>
              </div>
            </div>

            ${e.filter ? `
            <div style="margin-top:10px;display:flex;align-items:center;gap:8px;">
              <span style="font-size:10px;text-transform:uppercase;color:var(--text-2);letter-spacing:0.5px;">Filtre:</span>
              <span class="filter-code" onclick="copyText('${escAttr(e.filter)}')">${escHTML(e.filter)}</span>
            </div>
            ` : ""}

            ${e.related && e.related.length ? `
            <div style="margin-top:8px;font-size:11px;color:var(--text-2);">
              <strong>İlgili:</strong> ${e.related.map(r => escHTML(r)).join(", ")}
            </div>
            ` : ""}
          </div>
        </div>
      </div>
    `).join("")}
  `;

  // Category tabs
  document.querySelectorAll("[data-enc-cat]").forEach(p => {
    p.onclick = () => { activeEncyclopediaCat = p.dataset.encCat; renderEncyclopedia(); };
  });
  // Search
  let searchTimer;
  document.getElementById("enc-search").oninput = (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      encyclopediaSearch = e.target.value.trim();
      renderEncyclopedia();
      // Restore focus
      const inp = document.getElementById("enc-search");
      if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
    }, 150);
  };
}

/* ═══════════════════════════════════════════════════════════════
   HANDSHAKE DIAGNOSTIC
   ═══════════════════════════════════════════════════════════════ */

let handshakeType = "tcp";
let stuckAt = null;

const HANDSHAKE_DIAGNOSIS = {
  tcp: {
    name: "TCP 3-Way Handshake",
    steps: [
      { id: "syn-sent", label: "Client SYN gönderdi", ok: "SYN paketi capture'da görünüyor" },
      { id: "synack-received", label: "Server SYN-ACK gönderdi", ok: "SYN-ACK yanıtı geldi" },
      { id: "ack-sent", label: "Client ACK gönderdi (handshake bitti)", ok: "3-way handshake tamamlandı" },
      { id: "data-flow", label: "Veri akışı başladı", ok: "Bağlantı normal çalışıyor" }
    ],
    diagnoses: {
      "nothing": {
        title: "Hiçbir şey yok — SYN bile görmüyorum",
        causes: [
          "Capture YANLIŞ noktada alınmış — client bu yolu kullanmıyor",
          "Client isteği hiç göndermedi (uygulama sorunu)",
          "Client → capture noktası arasında paket kaybı"
        ],
        filters: ["tcp.flags.syn == 1", "ip.src == <client>"],
        actions: [
          "Capture'ı client'a daha yakın al (veya client makinede Wireshark aç)",
          "Client uygulamasında hata logu var mı?",
          "DNS çözümleme başarılı mı? (DNS sorgusunu kontrol et)"
        ]
      },
      "syn-sent": {
        title: "SYN gitti ama SYN-ACK gelmiyor",
        causes: [
          "Firewall SYN'i drop ediyor (stateful drop)",
          "Server down / uygulama dinlemiyor (port kapalı)",
          "Routing sorunu — server'a ulaşmıyor",
          "SYN retransmission olmalı ama SYN-ACK hiç gelmez",
          "Server port binding yok"
        ],
        filters: ["tcp.flags.syn == 1 && tcp.flags.ack == 0", "icmp", "tcp.analysis.retransmission"],
        actions: [
          "Server'da port dinleniyor mu? (netstat -an | grep <port>)",
          "Firewall log → SYN drop var mı?",
          "Traceroute/ping server'a çalışıyor mu?",
          "ICMP unreachable dönüyor mu? (icmp.type == 3)"
        ]
      },
      "synack-received": {
        title: "SYN-ACK geldi ama ACK gönderilmiyor",
        causes: [
          "Client ACK göndermedi — bu çok nadir (client tarafı sorun)",
          "Client'ta RST dönüyor olabilir (policy reject)",
          "Client-side firewall/antivirus bağlantıyı kesiyor"
        ],
        filters: ["tcp.flags.syn == 1 && tcp.flags.ack == 1", "tcp.flags.reset == 1 && ip.src == <client>"],
        actions: [
          "Client tarafındaki güvenlik yazılımını kontrol et",
          "Client OS TCP stack sağlıklı mı?",
          "RST kaynağı client ise → client uygulaması kapatmak istiyor"
        ]
      },
      "ack-sent": {
        title: "Handshake tamam ama veri akmıyor",
        causes: [
          "Client istek göndermiyor (app katmanı)",
          "Server yanıt göndermiyor (app katmanı)",
          "Application layer protocol başlatılmıyor",
          "Idle connection — keepalive bile yok"
        ],
        filters: ["tcp.analysis.keep_alive", "tcp.time_delta > 10"],
        actions: [
          "Application log — istek gönderildi mi?",
          "Client uygulaması hung mu, thread blocked mı?",
          "tcp.time_delta > 60 ile idle time ölç"
        ]
      },
      "data-flow": {
        title: "Veri akıyor — sorun başka yerde",
        causes: [
          "TCP seviyesi OK, uygulama katmanında sorun var",
          "Response yavaş, hata kodu dönüyor, TLS handshake sorunlu..."
        ],
        filters: ["http.response.code >= 400", "tls.alert_message"],
        actions: [
          "TLS handshake tamam mı? (tls.handshake.type == 20)",
          "HTTP yanıt kodları ne? (http.response.code)",
          "Response time ne kadar? (http.time)"
        ]
      }
    }
  },
  tls: {
    name: "TLS Handshake",
    steps: [
      { id: "client-hello", label: "Client Hello gönderildi", ok: "Client TLS başlatıyor" },
      { id: "server-hello", label: "Server Hello geldi", ok: "Server cipher seçti" },
      { id: "certificate", label: "Server Certificate geldi", ok: "Sertifika yollandı" },
      { id: "key-exchange", label: "Key Exchange tamam", ok: "Key material paylaşıldı" },
      { id: "finished", label: "Finished mesajı geldi", ok: "TLS hazır, şifreli kanal açık" }
    ],
    diagnoses: {
      "nothing": {
        title: "Client Hello bile görmüyorum",
        causes: [
          "TCP handshake tamamlanmadı — TLS başlamadı",
          "Client HTTPS değil HTTP kullanıyor",
          "Port 443 değil, başka port kullanılıyor"
        ],
        filters: ["tcp.flags.syn == 1", "tls"],
        actions: [
          "Önce TCP handshake kontrol et",
          "Client gerçekten HTTPS mi istiyor?",
          "Doğru portu capture ediyor musun?"
        ]
      },
      "client-hello": {
        title: "Client Hello gitti ama Server Hello YOK",
        causes: [
          "Cipher suite uyumsuzluğu — server client'ın hiçbir cipher'ını desteklemiyor",
          "TLS versiyon uyumsuzluğu (client TLS 1.3 ister, server 1.2 only veya tersi)",
          "Server SNI'yi tanımıyor (unrecognized_name alert 112 gelir)",
          "F5 client-ssl profile bu bağlantı için tanımsız"
        ],
        filters: ["tls.handshake.type == 1", "tls.alert_message"],
        actions: [
          "Client Hello'da hangi cipher'lar listelenmiş — incele",
          "Hangi TLS versiyon istenmiş? (tls.handshake.version)",
          "SNI değeri doğru mu? (tls.handshake.extensions_server_name)",
          "F5 → tmsh list ltm profile client-ssl <name> ciphers"
        ]
      },
      "server-hello": {
        title: "Server Hello geldi ama Certificate YOK",
        causes: [
          "Server Hello sonrası hemen Alert (Alert 40 handshake_failure)",
          "Server cipher seçti ama cert yükleyemedi",
          "F5 cert profile hatası"
        ],
        filters: ["tls.handshake.type == 2", "tls.alert_message"],
        actions: [
          "Alert mesajı var mı? Hemen sonrasında?",
          "F5 SSL profile cert-file ayarı kontrol et",
          "Cert dosyası okunabilir mi, format doğru mu?"
        ]
      },
      "certificate": {
        title: "Certificate geldi ama sonrası gelmiyor",
        causes: [
          "Client sertifikayı doğrulayamadı (unknown_ca, bad_certificate)",
          "Cert expired (alert 45)",
          "Cert chain eksik (intermediate missing)",
          "CN/SAN ile SNI eşleşmiyor"
        ],
        filters: ["tls.handshake.type == 11", "tls.alert_message.desc"],
        actions: [
          "Alert 48 (unknown_ca) varsa intermediate CA ekle",
          "Alert 45 (expired) varsa yeni cert al",
          "Cert CN/SAN ile istenen SNI uyuşuyor mu?",
          "openssl s_client -connect server:443 -showcerts ile zincir incele"
        ]
      },
      "key-exchange": {
        title: "Key Exchange takıldı",
        causes: [
          "Client Key Exchange paketi gelmedi",
          "Cryptographic parameter mismatch",
          "Çok nadir — genelde library bug"
        ],
        filters: ["tls.handshake.type == 16", "tls.alert_message"],
        actions: [
          "TLS library versiyonları uyumlu mu?",
          "FIPS mode aktif mi, çakışma var mı?"
        ]
      },
      "finished": {
        title: "Finished geldi — TLS OK",
        causes: [
          "TLS handshake başarılı! Sorun üst katmanda (HTTP)"
        ],
        filters: ["tls.handshake.type == 20", "http.response.code"],
        actions: [
          "Şimdi HTTP seviyesine bak",
          "TLS deşifre yap ve HTTP response'ları incele"
        ]
      }
    }
  }
};

function renderHandshake() {
  const el = document.getElementById("handshake");
  const hs = HANDSHAKE_DIAGNOSIS[handshakeType];

  el.innerHTML = `
    <div class="section-header">
      <h2>Handshake Teşhis</h2>
      <div class="description">Handshake nerede takıldı? Görsel stepper'da seç, tam teşhis + aksiyon listesi al.</div>
    </div>

    <div class="content-block">
      <h3>Handshake Tipi</h3>
      <div class="check-group">
        <div class="check-pill ${handshakeType==='tcp'?'selected':''}" data-hs="tcp">🔗 TCP 3-Way Handshake</div>
        <div class="check-pill ${handshakeType==='tls'?'selected':''}" data-hs="tls">🔒 TLS Handshake</div>
      </div>
    </div>

    <div class="content-block">
      <h3>${escHTML(hs.name)} — Nerede takıldı?</h3>
      <p class="hint">Son başarılı adımı seç. Wireshark'ta hangi pakete kadar gördün?</p>

      <div style="margin-top:16px;">
        ${renderHandshakeStepper(hs)}
      </div>

      <div class="btn-row" style="margin-top:16px;">
        <button class="btn" onclick="resetHandshake()">🔄 Sıfırla</button>
      </div>
    </div>

    ${stuckAt !== null ? renderHandshakeDiagnosis(hs) : ""}
  `;

  document.querySelectorAll("[data-hs]").forEach(p => {
    p.onclick = () => { handshakeType = p.dataset.hs; stuckAt = null; renderHandshake(); };
  });
  document.querySelectorAll("[data-step]").forEach(s => {
    s.onclick = () => { stuckAt = s.dataset.step; renderHandshake(); };
  });
}

function renderHandshakeStepper(hs) {
  const steps = hs.steps;
  // Include "nothing seen" as step 0
  return `
    <div style="display:flex;flex-direction:column;gap:0;">
      <div class="stepper-item ${stuckAt==='nothing'?'active':''}" data-step="nothing" style="
        display:flex;align-items:center;gap:12px;padding:12px 14px;
        background:${stuckAt==='nothing'?'rgba(248,81,73,0.15)':'var(--bg-2)'};
        border:1px solid ${stuckAt==='nothing'?'var(--err)':'var(--border)'};
        border-radius:8px;cursor:pointer;margin-bottom:8px;transition:all 0.15s;">
        <div style="width:24px;height:24px;border-radius:50%;background:var(--bg-3);color:var(--err);display:flex;align-items:center;justify-content:center;font-size:14px;">✗</div>
        <div style="flex:1;font-size:13px;color:var(--text-0);">Hiçbir şey yok — capture'da bu handshake görünmüyor</div>
      </div>

      ${steps.map((s, i) => `
        <div class="stepper-item ${stuckAt===s.id?'active':''}" data-step="${s.id}" style="
          display:flex;align-items:center;gap:12px;padding:12px 14px;
          background:${stuckAt===s.id?'rgba(210,153,34,0.15)':'var(--bg-2)'};
          border:1px solid ${stuckAt===s.id?'var(--warn)':'var(--border)'};
          border-radius:8px;cursor:pointer;margin-bottom:8px;transition:all 0.15s;">
          <div style="width:24px;height:24px;border-radius:50%;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;">${i+1}</div>
          <div style="flex:1;">
            <div style="font-size:13px;color:var(--text-0);font-weight:600;">${escHTML(s.label)}</div>
            <div style="font-size:11px;color:var(--text-2);margin-top:2px;">${escHTML(s.ok)}</div>
          </div>
          ${i < steps.length - 1 ? `<div style="color:var(--text-2);">↓</div>` : ""}
        </div>
      `).join("")}
    </div>
  `;
}

function renderHandshakeDiagnosis(hs) {
  const d = hs.diagnoses[stuckAt];
  if (!d) return "";
  return `
    <div class="wizard-result">
      <h3>🎯 ${escHTML(d.title)}</h3>

      <h4 style="color:var(--text-0);margin-top:14px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;">Olası Nedenler</h4>
      <ul style="margin-left:20px;color:var(--text-1);font-size:13px;line-height:1.8;">
        ${d.causes.map(c => `<li>${escHTML(c)}</li>`).join("")}
      </ul>

      <h4 style="color:var(--text-0);margin-top:14px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;">Kullanılacak Filtreler</h4>
      <div class="wizard-filters">
        ${d.filters.map(f => `
          <div class="filter-item">
            <span class="filter-code" onclick="copyText('${escAttr(f)}')">${escHTML(f)}</span>
          </div>
        `).join("")}
      </div>

      <h4 style="color:var(--text-0);margin-top:14px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;">Aksiyon Listesi</h4>
      <ol class="wizard-steps-list">
        ${d.actions.map(a => `<li>${escHTML(a)}</li>`).join("")}
      </ol>
    </div>
  `;
}

function resetHandshake() {
  stuckAt = null;
  renderHandshake();
}

/* ─── Dashboard ─── */
function renderDashboard() {
  const el = document.getElementById("dashboard");
  el.innerHTML = `
    <div class="hero">
      <h2>Wireshark Hub</h2>
      <div class="lead">Fintech Network Security Engineer için referans merkezi — filtreler, senaryolar, araçlar, metodolojiler.</div>
      <div class="stats-grid">
        <div class="stat-card"><div class="num">${FILTERS.length}</div><div class="label">Filtre</div></div>
        <div class="stat-card"><div class="num">${SCENARIOS.length}</div><div class="label">Senaryo</div></div>
        <div class="stat-card"><div class="num">${PROFILES.length}</div><div class="label">Profil</div></div>
        <div class="stat-card"><div class="num">${ECOSYSTEM.length}</div><div class="label">Araç</div></div>
        <div class="stat-card"><div class="num">${REPOS.length}</div><div class="label">Repo</div></div>
        <div class="stat-card"><div class="num">${CHEATSHEETS.length}</div><div class="label">Cheat Sheet</div></div>
      </div>
    </div>

    <div class="content-block">
      <h3>60 Saniyede PCAP Analizi — 5 Adım</h3>
      <ol style="margin-left:20px;color:var(--text-1);font-size:13px;line-height:1.8;">
        <li><strong>Overview:</strong> Statistics → Protocol Hierarchy (30sn)</li>
        <li><strong>Conversations:</strong> Bytes'a sırala, outlier bul (1dk)</li>
        <li><strong>Expert Info:</strong> Error → Warning önceliklendir (2dk)</li>
        <li><strong>IO Graph:</strong> tcp.analysis.flags overlay (2dk)</li>
        <li><strong>Drill-Down:</strong> Follow TCP Stream → kaydet (5dk)</li>
      </ol>
    </div>

    <h3 style="color:var(--text-0);margin-bottom:12px;font-size:16px;">⭐ İnteraktif Araçlar</h3>
    <div class="card-grid">
      ${[
        ["builder","🔧","Filter Builder","Port/IP/Stream — form doldur, filtre üret"],
        ["wizard","🧭","Sorun Sihirbazı","Semptom seç → filtreler + adımlar"],
        ["follow","👁","Trafik Takibi","Konuşma nasıl izole edilir?"],
        ["encyclopedia","📖","Paket Sözlüğü","Retransmission nedir? TCP flag, TLS alert, HTTP/SIP status sözlüğü"],
        ["handshake","🤝","Handshake Teşhis","Handshake nerede takıldı? → teşhis"],
        ["checklist","✓","Kontrol Listesi","Ne kontrol edilecek? 53 soru"],
        ["tsharkbuilder","⌨","tshark Builder","CLI komutu form ile üret"],
        ["pcapbuilder","📡","PCAP Komutu","tcpdump komutu üretici"],
        ["profilebuilder","🎨","Profil Oluşturucu","Wireshark profil dosyası indir"]
      ].map(([id,ic,t,d]) => `
        <div class="card" onclick="showSection('${id}')" style="border-color:var(--accent);">
          <h3>${ic} ${t}</h3>
          <p>${d}</p>
        </div>
      `).join("")}
    </div>

    <h3 style="color:var(--text-0);margin:20px 0 12px;font-size:16px;">📚 Referans</h3>
    <div class="card-grid">
      ${[
        ["filters","⚙","Filtre Kütüphanesi",`${FILTERS.length} hazır filtre, kategorili`],
        ["scenarios","⚠","Sorun Senaryoları","5 fintech senaryosu"],
        ["f5tls","🔒","F5 &amp; TLS","PCAP + 3 deşifre yöntemi"],
        ["fortigate","🛡","FortiGate","Deep Inspection + capture"],
        ["checkpoint","⬡","Check Point","fw monitor + HTTPS Inspection"],
        ["rootcause","🎯","Root Cause","Metodolojiler + checklist"]
      ].map(([id,ic,t,d]) => `
        <div class="card" onclick="showSection('${id}')">
          <h3>${ic} ${t}</h3>
          <p>${d}</p>
        </div>
      `).join("")}
    </div>
  `;
}

/* ─── Filtreler ─── */
let activeFilterCat = "all";
let filterSectionSearch = "";

function renderFilters() {
  const el = document.getElementById("filters");
  const cats = [...new Set(FILTERS.map(f => f.cat))];

  el.innerHTML = `
    <div class="section-header">
      <h2>Filtre Kütüphanesi</h2>
      <div class="description">${FILTERS.length} filtre, ${cats.length} kategori. Arama kutusuna yaz veya kategori seç. Koda tıkla → kopyalanır.</div>
    </div>

    <div class="content-block" style="padding:14px 18px;margin-bottom:12px;">
      <div style="display:flex;gap:10px;align-items:center;">
        <input type="text" id="flt-search" value="${escAttr(filterSectionSearch)}" placeholder="Ara: port, syn, retransmission, 503, handshake..." style="flex:1;background:var(--bg-2);border:1px solid var(--border);color:var(--text-0);padding:10px 12px;border-radius:6px;font-family:var(--mono);font-size:13px;outline:none;">
        ${filterSectionSearch ? `<button class="btn" onclick="clearFilterSearch()">× Temizle</button>` : ""}
      </div>
      <div id="flt-count" style="font-size:11px;color:var(--text-2);margin-top:6px;"></div>
    </div>

    ${!filterSectionSearch ? `
    <div class="category-tabs" id="cat-tabs">
      <div class="category-tab ${activeFilterCat==="all"?"active":""}" data-cat="all">Tümü (${FILTERS.length})</div>
      ${cats.map(c => `
        <div class="category-tab ${activeFilterCat===c?"active":""}" data-cat="${c}">${escHTML(c)} (${FILTERS.filter(f=>f.cat===c).length})</div>
      `).join("")}
    </div>
    ` : ""}

    <table class="filter-table">
      <thead>
        <tr>
          <th style="width:30px"></th>
          <th>Filtre</th>
          <th>Açıklama</th>
          <th style="width:110px">Kategori</th>
        </tr>
      </thead>
      <tbody id="filter-tbody"></tbody>
    </table>
  `;

  el.querySelectorAll(".category-tab").forEach(tab => {
    tab.onclick = () => {
      activeFilterCat = tab.dataset.cat;
      renderFilters();
    };
  });

  const searchInp = document.getElementById("flt-search");
  let tmr;
  searchInp.addEventListener("input", (e) => {
    clearTimeout(tmr);
    tmr = setTimeout(() => {
      filterSectionSearch = e.target.value.trim();
      renderFilters();
      // Restore focus + cursor position after re-render
      const inp = document.getElementById("flt-search");
      if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
    }, 150);
  });

  renderFilterRows();
}

function renderFilterRows() {
  const tbody = document.getElementById("filter-tbody");
  const countEl = document.getElementById("flt-count");
  if (!tbody) return;

  let rows;
  if (filterSectionSearch) {
    const q = filterSectionSearch.toLowerCase();
    rows = FILTERS.filter(f =>
      matchesQuery(f, q)
    );
    if (countEl) countEl.textContent = `${rows.length} sonuç bulundu "${filterSectionSearch}" için`;
  } else {
    rows = FILTERS.filter(f => activeFilterCat === "all" || f.cat === activeFilterCat);
    if (countEl) countEl.textContent = activeFilterCat === "all" ? `Toplam ${rows.length} filtre` : `${rows.length} filtre — kategori: ${activeFilterCat}`;
  }

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:30px;color:var(--text-2);">Eşleşme yok — başka terim dene</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(f => `
    <tr>
      <td><span class="sev-badge sev-${f.sev}"></span></td>
      <td><span class="filter-code" onclick="copyText('${escAttr(f.code)}')">${escHTML(f.code)}</span></td>
      <td class="filter-desc">${escHTML(f.desc)}</td>
      <td><span class="platform-badge">${escHTML(f.cat)}</span></td>
    </tr>
  `).join("");
}

function clearFilterSearch() {
  filterSectionSearch = "";
  renderFilters();
}

/* ─── Senaryolar ─── */
function renderScenarios() {
  const el = document.getElementById("scenarios");
  el.innerHTML = `
    <div class="section-header">
      <h2>Sorun Senaryoları</h2>
      <div class="description">Her senaryo: semptom → filtre sırası → kök neden tablosu. Filtreye tıkla, kopyala.</div>
    </div>
    ${SCENARIOS.map(s => `
      <div class="scenario">
        <div class="scenario-header">
          <h3>${escHTML(s.title)}</h3>
          <span class="badge badge-${s.badgeType}">${s.badge}</span>
        </div>
        <div class="scenario-symptom"><strong>Semptom:</strong> ${escHTML(s.symptom)}</div>
        <div class="scenario-filters">
          <h4>Filtre Sırası</h4>
          <div class="filter-list">
            ${s.filters.map(f => `
              <div class="filter-item">
                <span class="sev-badge sev-${f.sev}"></span>
                <span class="filter-code" onclick="copyText('${escHTML(f.code).replace(/'/g,"\\'")}')">${escHTML(f.code)}</span>
                <span class="filter-desc">${escHTML(f.desc)}</span>
              </div>
            `).join("")}
          </div>
        </div>
        <h4 style="margin-top:16px;font-size:13px;color:var(--text-1);text-transform:uppercase;letter-spacing:0.5px;">Kök Neden Matrisi</h4>
        <table class="root-cause-table">
          <thead><tr><th>Bulgu</th><th>Kök Neden</th><th>Eylem</th></tr></thead>
          <tbody>
            ${s.rootCauses.map(rc => `
              <tr><td>${escHTML(rc.finding)}</td><td>${escHTML(rc.cause)}</td><td>${escHTML(rc.action)}</td></tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `).join("")}
  `;
}

/* ─── F5 & TLS ─── */
function renderF5TLS() {
  const el = document.getElementById("f5tls");
  el.innerHTML = `
    <div class="section-header">
      <h2>F5 BIG-IP — PCAP &amp; TLS Deşifre</h2>
      <div class="description">tcpdump komutları ve 3 deşifre yöntemi. Maintenance window öner.</div>
    </div>

    <div class="content-block">
      <h3>F5'ten PCAP Alma Komutları</h3>
      <table class="data-table">
        <thead><tr><th>Amaç</th><th>Komut</th></tr></thead>
        <tbody>
          ${F5_COMMANDS.map(c => `
            <tr>
              <td>${escHTML(c.title)}</td>
              <td><span class="filter-code" onclick="copyText('${escHTML(c.cmd).replace(/'/g,"\\'")}')">${escHTML(c.cmd)}</span></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>

    <div class="content-block">
      <h3>TLS Deşifre Yöntemleri</h3>
      ${TLS_METHODS.map(m => `
        <div style="border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px;background:var(--bg-2);">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
            <span class="platform-badge platform-f5">${escHTML(m.platform)}</span>
            <strong style="color:var(--text-0);">${escHTML(m.method)}</strong>
          </div>
          <div style="font-size:12px;color:var(--text-2);margin-bottom:8px;">
            <span style="color:var(--ok);">✓ ${escHTML(m.pros)}</span> ·
            <span style="color:var(--warn);">⚠ ${escHTML(m.cons)}</span>
          </div>
          ${m.code ? `<pre><code>${escHTML(m.code)}</code></pre>` : ""}
          <ol style="margin-left:20px;font-size:12px;color:var(--text-1);">
            ${m.steps.map(s => `<li style="margin-bottom:4px;"><code>${escHTML(s)}</code></li>`).join("")}
          </ol>
        </div>
      `).join("")}
    </div>
  `;
}

/* ─── FortiGate ─── */
function renderFortiGate() {
  const el = document.getElementById("fortigate");
  el.innerHTML = `
    <div class="section-header">
      <h2>FortiGate — PCAP &amp; TLS</h2>
      <div class="description">Deep Inspection AÇIK ise PCAP zaten deşifreli gelir.</div>
    </div>

    <div class="content-block">
      <h3>PCAP Alma Komutları</h3>
      <table class="data-table">
        <thead><tr><th>Amaç</th><th>Komut / Yöntem</th></tr></thead>
        <tbody>
          ${FORTIGATE_COMMANDS.map(c => `
            <tr>
              <td>${escHTML(c.title)}</td>
              <td><span class="filter-code" onclick="copyText('${escHTML(c.cmd).replace(/'/g,"\\'")}')">${escHTML(c.cmd)}</span></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>

    <div class="content-block">
      <h3>SSL Deep Inspection ile TLS Deşifre</h3>
      <p>FortiGate SSL Deep Inspection = MITM proxy. Aktifse trafik cihazda açılır, packet capture'da CLEAR görünür.</p>
      <ol style="margin-left:20px;color:var(--text-1);font-size:13px;line-height:1.8;">
        ${FG_TLS_STEPS.map(s => `<li>${escHTML(s)}</li>`).join("")}
      </ol>
      <div style="background:var(--bg-2);border-left:3px solid var(--warn);padding:10px 12px;border-radius:4px;margin-top:12px;font-size:12px;color:var(--text-1);">
        <strong>Uyarı:</strong> Certificate pinning yapan uygulamalar (bankacılık app'leri) başarısız olur.
        CLI <code>diagnose sniffer</code> PCAP dosyası üretmez — GUI Packet Capture kullan.
      </div>
    </div>
  `;
}

/* ─── Check Point ─── */
function renderCheckPoint() {
  const el = document.getElementById("checkpoint");
  el.innerHTML = `
    <div class="section-header">
      <h2>Check Point — PCAP &amp; TLS</h2>
      <div class="description">fw monitor 4 noktadan capture — i/I/o/O seçimi kritik.</div>
    </div>

    <div class="content-block">
      <h3>PCAP Alma Komutları</h3>
      <table class="data-table">
        <thead><tr><th>Amaç</th><th>Komut</th></tr></thead>
        <tbody>
          ${CP_COMMANDS.map(c => `
            <tr>
              <td>${escHTML(c.title)}</td>
              <td><span class="filter-code" onclick="copyText('${escHTML(c.cmd).replace(/'/g,"\\'")}')">${escHTML(c.cmd)}</span></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>

    <div class="content-block">
      <h3>fw monitor Noktaları</h3>
      <table class="data-table">
        <thead><tr><th>Nokta</th><th>İsim</th><th>Ne Zaman Kullan</th></tr></thead>
        <tbody>
          ${CP_MONITOR_POINTS.map(p => `
            <tr><td><code>${p.pt}</code></td><td>${escHTML(p.name)}</td><td>${escHTML(p.use)}</td></tr>
          `).join("")}
        </tbody>
      </table>
      <p style="margin-top:12px;">HTTPS Inspection AÇIKSA <code>fw monitor -m I</code> ile deşifre edilmiş trafik yakalanabilir.</p>
    </div>
  `;
}

/* ─── Profiller ─── */
function renderProfiles() {
  const el = document.getElementById("profiles");
  el.innerHTML = `
    <div class="section-header">
      <h2>Wireshark Profilleri</h2>
      <div class="description">Hazır renk/kolon/filtre setleri. ZIP import ile 30 saniyede kurulum.</div>
    </div>

    <div class="content-block">
      <h3>ZIP Profil Import — 4 Adım</h3>
      <ol style="margin-left:20px;color:var(--text-1);font-size:13px;line-height:1.8;">
        ${IMPORT_STEPS.map(s => `<li>${escHTML(s)}</li>`).join("")}
      </ol>
    </div>

    <div class="card-grid">
      ${PROFILES.map(p => `
        <div class="card">
          <h3>${escHTML(p.name)}</h3>
          <p>${escHTML(p.desc)}</p>
          <div class="tags">${p.tags.map(t => `<span class="tag">${escHTML(t)}</span>`).join("")}</div>
          <a href="${escHTML(p.url)}" target="_blank" rel="noopener">GitHub →</a>
        </div>
      `).join("")}
    </div>
  `;
}

/* ─── Cheat Sheets ─── */
let activeCheatsheet = "ports";
let cheatsheetSearch = "";

function renderCheatsheets() {
  const el = document.getElementById("cheatsheets");

  // Global search across all cheatsheets
  let searchResults = null;
  if (cheatsheetSearch) {
    const q = cheatsheetSearch.toLowerCase();
    searchResults = [];
    CHEATSHEETS.forEach(cs => {
      cs.rows.forEach(row => {
        const rowText = row.join(" ").toLowerCase();
        if (rowText.includes(q) || cs.name.toLowerCase().includes(q) || cs.desc.toLowerCase().includes(q)) {
          searchResults.push({ sheet: cs, row });
        }
      });
    });
  }

  const cur = CHEATSHEETS.find(c => c.id === activeCheatsheet);

  el.innerHTML = `
    <div class="section-header">
      <h2>Cheat Sheets — Hızlı Referans</h2>
      <div class="description">${CHEATSHEETS.length} tablo · ${CHEATSHEETS.reduce((a,c)=>a+c.rows.length,0)} entry. Ara veya kategori seç.</div>
    </div>

    <div class="content-block" style="padding:14px 18px;margin-bottom:12px;">
      <div style="display:flex;gap:10px;align-items:center;">
        <input type="text" id="cs-search" value="${escAttr(cheatsheetSearch)}" placeholder="Ara: 443, SYN, 500, CNAME, CIDR..." style="flex:1;background:var(--bg-2);border:1px solid var(--border);color:var(--text-0);padding:10px 12px;border-radius:6px;font-family:var(--mono);font-size:13px;outline:none;">
        ${cheatsheetSearch ? `<button class="btn" onclick="clearCheatsheetSearch()">× Temizle</button>` : ""}
      </div>
    </div>

    ${!cheatsheetSearch ? `
    <div class="category-tabs" style="margin-bottom:16px;">
      ${CHEATSHEETS.map(cs => `
        <div class="category-tab ${activeCheatsheet===cs.id?'active':''}" data-cs="${cs.id}">
          ${cs.icon} ${escHTML(cs.name)}
        </div>
      `).join("")}
    </div>
    ` : ""}

    ${cheatsheetSearch ? `
      <div class="content-block">
        <h3>Arama Sonuçları (${searchResults.length})</h3>
        ${searchResults.length === 0 ? `<p class="hint">Eşleşme yok — başka terim dene.</p>` : `
          <table class="data-table">
            <thead><tr><th>Tablo</th>${CHEATSHEETS[0].cols.map(() => '').join('')}<th>Değerler</th></tr></thead>
            <tbody>
              ${searchResults.map(r => `
                <tr>
                  <td><span class="platform-badge">${escHTML(r.sheet.name)}</span></td>
                  <td>${r.row.map((c, i) => `<strong style="color:${i===0?'var(--accent)':'var(--text-1)'};">${escHTML(c)}</strong>`).join(" · ")}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        `}
      </div>
    ` : `
      <div class="content-block">
        <div style="display:flex;align-items:baseline;gap:12px;margin-bottom:10px;">
          <h3 style="margin:0;">${cur.icon} ${escHTML(cur.name)}</h3>
          <span style="color:var(--text-2);font-size:12px;">${cur.rows.length} entry</span>
        </div>
        <p class="hint" style="margin-bottom:14px;">${escHTML(cur.desc)}</p>
        <table class="data-table">
          <thead>
            <tr>
              ${cur.cols.map(c => `<th>${escHTML(c)}</th>`).join("")}
            </tr>
          </thead>
          <tbody>
            ${cur.rows.map(row => `
              <tr>
                ${row.map((cell, i) => `
                  <td${i===0?' style="font-family:var(--mono);color:var(--accent);font-weight:600;"':''}>${escHTML(cell)}</td>
                `).join("")}
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `}

    <div class="content-block" style="margin-top:16px;">
      <h4 style="font-size:11px;text-transform:uppercase;color:var(--text-2);letter-spacing:0.5px;">Ek Online Referanslar</h4>
      <ul style="font-size:12px;color:var(--text-1);margin-top:8px;list-style:none;">
        <li style="padding:4px 0;">• <a href="https://www.wireshark.org/docs/dfref/" target="_blank" rel="noopener" style="color:var(--accent);">Wireshark Display Filter Reference</a> — 10.000+ alan</li>
        <li style="padding:4px 0;">• <a href="https://packetlife.net/library/cheat-sheets/" target="_blank" rel="noopener" style="color:var(--accent);">Packetlife Cheat Sheets</a> — PDF'ler (BGP/OSPF/EIGRP detay)</li>
        <li style="padding:4px 0;">• <a href="https://tshark.dev/" target="_blank" rel="noopener" style="color:var(--accent);">tshark.dev</a> — tshark tam rehberi</li>
      </ul>
    </div>
  `;

  // Events
  document.querySelectorAll("[data-cs]").forEach(p => {
    p.onclick = () => { activeCheatsheet = p.dataset.cs; renderCheatsheets(); };
  });

  const searchInp = document.getElementById("cs-search");
  if (searchInp) {
    let tmr;
    searchInp.addEventListener("input", (e) => {
      clearTimeout(tmr);
      tmr = setTimeout(() => {
        cheatsheetSearch = e.target.value.trim();
        renderCheatsheets();
        const inp = document.getElementById("cs-search");
        if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
      }, 150);
    });
  }
}

function clearCheatsheetSearch() {
  cheatsheetSearch = "";
  renderCheatsheets();
}

/* ─── Ekosistem ─── */
function renderEcosystem() {
  const el = document.getElementById("ecosystem");
  el.innerHTML = `
    <div class="section-header">
      <h2>Wireshark Ekosistemi</h2>
      <div class="description">Wireshark'ı tamamlayan araçlar — kurulum komutları + örnek kullanım gömülü.</div>
    </div>

    ${ECOSYSTEM.map(t => `
      <div class="content-block">
        <div style="display:flex;align-items:baseline;gap:12px;margin-bottom:6px;">
          <h3 style="margin:0;">${escHTML(t.name)}</h3>
          <span class="platform-badge">${escHTML(t.role)}</span>
        </div>
        <p>${escHTML(t.desc)}</p>
        <div style="background:var(--bg-2);padding:8px 12px;border-left:3px solid var(--info);border-radius:4px;font-size:12px;color:var(--text-1);margin:10px 0;">
          <strong style="color:var(--text-0);">Ne zaman kullan:</strong> ${escHTML(t.use)}
        </div>

        <h4 style="font-size:11px;text-transform:uppercase;color:var(--text-1);letter-spacing:0.5px;margin-top:14px;">Kurulum</h4>
        ${Object.entries(t.install).map(([os, cmd]) => `
          <div style="margin-bottom:6px;">
            <span class="platform-badge" style="margin-bottom:4px;display:inline-block;">${escHTML(os)}</span>
            <pre style="margin:4px 0;"><code onclick="copyText('${escAttr(cmd)}')" style="cursor:pointer;" title="Tıkla kopyala">${escHTML(cmd)}</code></pre>
          </div>
        `).join("")}

        <h4 style="font-size:11px;text-transform:uppercase;color:var(--text-1);letter-spacing:0.5px;margin-top:14px;">Temel Kullanım</h4>
        <pre><code onclick="copyText('${escAttr(t.usage)}')" style="cursor:pointer;" title="Tıkla kopyala">${escHTML(t.usage)}</code></pre>

        ${t.queries.length ? `
        <h4 style="font-size:11px;text-transform:uppercase;color:var(--text-1);letter-spacing:0.5px;margin-top:14px;">Örnek Sorgular / Komutlar</h4>
        <div class="filter-list">
          ${t.queries.map(q => `
            <div class="filter-item">
              <span class="filter-code" onclick="copyText('${escAttr(q.q)}')">${escHTML(q.q)}</span>
              <span class="filter-desc">${escHTML(q.desc)}</span>
            </div>
          `).join("")}
        </div>
        ` : ""}
      </div>
    `).join("")}
  `;
}

/* ─── Lua Plugins ─── */
function renderLua() {
  const el = document.getElementById("lua");
  el.innerHTML = `
    <div class="section-header">
      <h2>Lua Plugins</h2>
      <div class="description">JA3/JA3S, ASN, exchange protokolleri — kurulum komutları + filtre örnekleri gömülü.</div>
    </div>

    <div class="content-block">
      <h3>Wireshark Plugin Klasör Konumları</h3>
      <table class="data-table">
        <thead><tr><th>İşletim Sistemi</th><th>Klasör</th></tr></thead>
        <tbody>
          ${PLUGIN_LOCATIONS.map(l => `
            <tr><td>${escHTML(l.os)}</td><td><code onclick="copyText('${escAttr(l.path)}')" style="cursor:pointer;" title="Kopyala">${escHTML(l.path)}</code></td></tr>
          `).join("")}
        </tbody>
      </table>
      <p style="margin-top:12px;font-size:12px;color:var(--text-1);">Kurulum sonrası: Wireshark → Analyze → Reload Lua Plugins <code>Ctrl+Shift+L</code></p>
    </div>

    ${LUA_PLUGINS.map(p => `
      <div class="content-block">
        <h3>${escHTML(p.name)}</h3>
        <p>${escHTML(p.desc)}</p>
        <div style="background:var(--bg-2);padding:8px 12px;border-radius:4px;font-size:11px;color:var(--text-1);margin:10px 0;">
          <strong style="color:var(--text-0);">Dosyalar:</strong> ${escHTML(p.files)}
        </div>

        <h4 style="font-size:11px;text-transform:uppercase;color:var(--text-1);letter-spacing:0.5px;margin-top:14px;">Kurulum</h4>
        ${Object.entries(p.install).map(([os, cmd]) => `
          <div style="margin-bottom:6px;">
            <span class="platform-badge" style="margin-bottom:4px;display:inline-block;">${escHTML(os)}</span>
            <pre style="margin:4px 0;"><code onclick="copyText('${escAttr(cmd)}')" style="cursor:pointer;" title="Tıkla kopyala">${escHTML(cmd)}</code></pre>
          </div>
        `).join("")}

        <div style="background:var(--bg-2);border-left:3px solid var(--ok);padding:8px 12px;border-radius:4px;font-size:12px;color:var(--text-1);margin:10px 0;">
          <strong style="color:var(--ok);">✓ Sonrası:</strong> ${escHTML(p.reload)}
        </div>

        ${p.filters.length ? `
        <h4 style="font-size:11px;text-transform:uppercase;color:var(--text-1);letter-spacing:0.5px;margin-top:14px;">Filtre Örnekleri</h4>
        <div class="filter-list">
          ${p.filters.map(f => `
            <div class="filter-item">
              <span class="filter-code" onclick="copyText('${escAttr(f.f)}')">${escHTML(f.f)}</span>
              <span class="filter-desc">${escHTML(f.desc)}</span>
            </div>
          `).join("")}
        </div>
        ` : ""}
      </div>
    `).join("")}
  `;
}

/* ─── Statistics ─── */
function renderStatistics() {
  const el = document.getElementById("statistics");
  el.innerHTML = `
    <div class="section-header">
      <h2>Statistics Menüsü Rehberi</h2>
      <div class="description">Wireshark'ın en kullanılmayan ama en güçlü menüsü.</div>
    </div>

    ${STATISTICS_GUIDE.map(g => `
      <div class="content-block">
        <h3>${escHTML(g.name)}</h3>
        <div style="font-size:12px;color:var(--text-2);margin-bottom:10px;"><code>${escHTML(g.path)}</code></div>
        <p><strong style="color:var(--text-0);">Ne yapar:</strong> ${escHTML(g.what)}</p>
        <p><strong style="color:var(--text-0);">Ne zaman:</strong> ${escHTML(g.when)}</p>
        <div style="background:var(--bg-2);border-left:3px solid var(--info);padding:8px 12px;border-radius:4px;font-size:12px;color:var(--text-1);">
          💡 ${escHTML(g.tip)}
        </div>
      </div>
    `).join("")}
  `;
}

/* ─── Root Cause ─── */
function renderRootCause() {
  const el = document.getElementById("rootcause");
  el.innerHTML = `
    <div class="section-header">
      <h2>Root Cause Analizi</h2>
      <div class="description">"Anlayamıyorum" sorununa çözüm — metodoloji + checklist + hızlı referans.</div>
    </div>

    ${METHODOLOGIES.map(m => `
      <div class="content-block">
        <h3>${escHTML(m.name)}</h3>
        <ol style="margin-left:20px;color:var(--text-1);font-size:13px;line-height:1.8;">
          ${m.steps.map(s => `<li style="margin-bottom:6px;">${escHTML(s)}</li>`).join("")}
        </ol>
      </div>
    `).join("")}

    <div class="content-block">
      <h3>TCP/TLS Handshake — Hızlı Root Cause</h3>
      <table class="data-table">
        <thead><tr><th>Semptom</th><th>Kök Neden</th></tr></thead>
        <tbody>
          ${HANDSHAKE_RC.map(r => `
            <tr><td>${escHTML(r.symptom)}</td><td>${escHTML(r.cause)}</td></tr>
          `).join("")}
        </tbody>
      </table>
    </div>

    <div class="content-block">
      <h3>"Anlayamadığında Sor" Checklist</h3>
      <ul class="checklist">
        ${RC_CHECKLIST.map(c => `<li>${escHTML(c)}</li>`).join("")}
      </ul>
      <p style="margin-top:12px;font-size:12px;color:var(--text-2);">
        Hepsi EVET → sorun başka yerde (uygulama/DB) · Hepsi HAYIR → başka nokta/zamanda capture al
      </p>
    </div>
  `;
}

/* ─── tshark ─── */
function renderTshark() {
  const el = document.getElementById("tshark");
  el.innerHTML = `
    <div class="section-header">
      <h2>tshark CLI Komutları</h2>
      <div class="description">Wireshark'ın komut satırı versiyonu — otomasyon ve script için.</div>
    </div>

    <div class="content-block">
      <table class="data-table">
        <thead><tr><th>Amaç</th><th>Komut</th></tr></thead>
        <tbody>
          ${TSHARK_COMMANDS.map(c => `
            <tr>
              <td style="width:200px;">${escHTML(c.title)}</td>
              <td><span class="filter-code" onclick="copyText('${escHTML(c.cmd).replace(/'/g,"\\'")}')">${escHTML(c.cmd)}</span></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

/* ─── GitHub Katalogu ─── */
function renderGithub() {
  const el = document.getElementById("github");
  el.innerHTML = `
    <div class="section-header">
      <h2>GitHub Katalogu</h2>
      <div class="description">${REPOS.length} proje — profiller, plugin'ler, araçlar, rehberler.</div>
    </div>

    <div class="card-grid">
      ${REPOS.map(r => `
        <div class="card">
          <h3>${escHTML(r.name)}</h3>
          <div class="card-meta">${escHTML(r.type)}</div>
          <p>${escHTML(r.desc)}</p>
          <a href="${escHTML(r.url)}" target="_blank" rel="noopener">Aç →</a>
        </div>
      `).join("")}
    </div>
  `;
}

/* ─── WCA-101 ─── */
function renderWCA() {
  const el = document.getElementById("wca");
  el.innerHTML = `
    <div class="section-header">
      <h2>WCA-101 Sertifikasyon</h2>
      <div class="description">Wireshark Certified Analyst — 2 Haziran 2025'te duyuruldu.</div>
    </div>

    <div class="content-block">
      <h3>Sınav Bilgileri</h3>
      <table class="data-table">
        <tbody>
          <tr><td><strong>Ad</strong></td><td>${WCA_INFO.name}</td></tr>
          <tr><td><strong>Duyuru</strong></td><td>${WCA_INFO.announced}</td></tr>
          <tr><td><strong>Organizasyon</strong></td><td>${WCA_INFO.org}</td></tr>
          <tr><td><strong>Kurucu</strong></td><td>${WCA_INFO.founder}</td></tr>
          <tr><td><strong>Ücret</strong></td><td>${WCA_INFO.price}</td></tr>
          <tr><td><strong>Practice</strong></td><td>${WCA_INFO.practice}</td></tr>
          <tr><td><strong>Geçerlilik</strong></td><td>${WCA_INFO.validity}</td></tr>
          <tr><td><strong>Seviye</strong></td><td>${WCA_INFO.level}</td></tr>
        </tbody>
      </table>
    </div>

    <div class="content-block">
      <h3>Sınav Domain'leri (7 adet)</h3>
      ${WCA_DOMAINS.map(d => `
        <div style="margin-bottom:12px;padding:10px 12px;background:var(--bg-2);border-radius:6px;border-left:3px solid var(--accent);">
          <strong style="color:var(--text-0);">Domain ${d.num}: ${escHTML(d.name)}</strong>
          <div style="font-size:12px;color:var(--text-2);margin-top:4px;">${d.topics.map(escHTML).join(" · ")}</div>
        </div>
      `).join("")}
    </div>

    <div class="content-block">
      <h3>12 Haftalık Öğrenme Planı</h3>
      <table class="data-table">
        <thead><tr><th>Hafta</th><th>Seviye</th><th>Konular</th></tr></thead>
        <tbody>
          ${WCA_PLAN.map(p => `
            <tr><td>${escHTML(p.weeks)}</td><td><span class="platform-badge">${escHTML(p.level)}</span></td><td>${escHTML(p.topics)}</td></tr>
          `).join("")}
        </tbody>
      </table>
    </div>

    <div class="content-block">
      <h3>Eğitim Kaynakları</h3>
      <ul>
        <li><a href="https://www.wireshark.org/certifications/" target="_blank" rel="noopener">Resmi sertifikasyon sayfası</a></li>
        <li><a href="https://www.wireshark.org/pdf/wca-objectives.pdf" target="_blank" rel="noopener">WCA Objectives PDF</a></li>
        <li><a href="https://packetpioneer.com/courses/wca/" target="_blank" rel="noopener">Packet Pioneer WCA kursu</a></li>
        <li><a href="https://www.malware-traffic-analysis.net/training-exercises.html" target="_blank" rel="noopener">Malware traffic analysis exercises</a></li>
      </ul>
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════════
   NAVIGATION, SEARCH, COPY
   ═══════════════════════════════════════════════════════════════ */

const SECTIONS = ["dashboard","builder","wizard","follow","tsharkbuilder","pcapbuilder","checklist","encyclopedia","handshake","profilebuilder","filters","scenarios","f5tls","fortigate","checkpoint","profiles","cheatsheets","ecosystem","lua","statistics","rootcause","tshark","github","wca"];

function showSection(id) {
  document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
  document.querySelectorAll(".nav-list a").forEach(a => a.classList.remove("active"));
  document.getElementById(id)?.classList.add("active");
  document.querySelector(`.nav-list a[data-section="${id}"]`)?.classList.add("active");
  window.scrollTo(0, 0);
  localStorage.setItem("wh-section", id);
}

function copyText(t) {
  const txt = t.replace(/\\'/g, "'");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt).then(() => showToast("Kopyalandı: " + txt.substring(0, 40) + (txt.length > 40 ? "..." : "")));
  } else {
    const ta = document.createElement("textarea");
    ta.value = txt;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    showToast("Kopyalandı");
  }
}

function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => t.classList.remove("show"), 1800);
}

/* Global search */
function handleSearch(q) {
  q = q.trim().toLowerCase();
  if (!q) { renderFilters(); return; }

  // Show filters section with search results
  showSection("filters");
  const tbody = document.getElementById("filter-tbody");
  if (!tbody) return;

  const matches = FILTERS.filter(f =>
    matchesQuery(f, q)
  );

  tbody.innerHTML = matches.length ? matches.map(f => `
    <tr>
      <td><span class="sev-badge sev-${f.sev}"></span></td>
      <td><span class="filter-code" onclick="copyText('${escHTML(f.code).replace(/'/g,"\\'")}')">${escHTML(f.code)}</span></td>
      <td class="filter-desc">${escHTML(f.desc)}</td>
      <td><span class="platform-badge">${f.cat}</span></td>
    </tr>
  `).join("") : `<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--text-2);">Eşleşme yok</td></tr>`;
}

/* ═══════════════════════════════════════════════════════════════
   INIT
   ═══════════════════════════════════════════════════════════════ */

function init() {
  // Render all sections
  renderDashboard();
  renderBuilder();
  renderWizard();
  renderFollow();
  renderTsharkBuilder();
  renderPcapBuilder();
  renderChecklist();
  renderEncyclopedia();
  renderHandshake();
  renderProfileBuilder();
  renderFilters();
  renderScenarios();
  renderF5TLS();
  renderFortiGate();
  renderCheckPoint();
  renderProfiles();
  renderCheatsheets();
  renderEcosystem();
  renderLua();
  renderStatistics();
  renderRootCause();
  renderTshark();
  renderGithub();
  renderWCA();

  // Nav click handlers
  document.querySelectorAll(".nav-list a").forEach(a => {
    a.onclick = () => showSection(a.dataset.section);
  });

  // Search
  let searchTimer;
  document.getElementById("search").addEventListener("input", e => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => handleSearch(e.target.value), 150);
  });

  // Restore last section
  const last = localStorage.getItem("wh-section");
  if (last && SECTIONS.includes(last)) showSection(last);

  // Keyboard shortcuts
  document.addEventListener("keydown", e => {
    const tag = document.activeElement.tagName;
    const inInput = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";

    // Esc → blur input + close help
    if (e.key === "Escape") {
      if (inInput) document.activeElement.blur();
      const help = document.getElementById("shortcut-help");
      if (help) help.remove();
      return;
    }

    if (inInput) return; // Don't trigger shortcuts while typing

    // / → focus search
    if (e.key === "/") {
      e.preventDefault();
      document.getElementById("search").focus();
      return;
    }
    // ? → show help
    if (e.key === "?") {
      e.preventDefault();
      showShortcutHelp();
      return;
    }
    // g then letter → navigate (vim-like)
    // Quick 1-9 → first 9 sections
    const shortcutMap = {
      "1": "dashboard",
      "2": "builder",
      "3": "wizard",
      "4": "follow",
      "5": "tsharkbuilder",
      "6": "pcapbuilder",
      "7": "checklist",
      "8": "encyclopedia",
      "9": "handshake"
    };
    if (shortcutMap[e.key]) {
      e.preventDefault();
      showSection(shortcutMap[e.key]);
      return;
    }
    // f → filters, w → wizard, e → encyclopedia, h → handshake, c → checklist
    const letterMap = {
      "f": "filters",
      "w": "wizard",
      "e": "encyclopedia",
      "h": "handshake",
      "c": "checklist",
      "b": "builder",
      "t": "tsharkbuilder",
      "p": "pcapbuilder",
      "d": "dashboard"
    };
    if (letterMap[e.key]) {
      e.preventDefault();
      showSection(letterMap[e.key]);
    }
  });
}

function showShortcutHelp() {
  // Remove existing help if open
  const existing = document.getElementById("shortcut-help");
  if (existing) { existing.remove(); return; }

  const help = document.createElement("div");
  help.id = "shortcut-help";
  help.style.cssText = "position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--bg-1);border:2px solid var(--accent);border-radius:12px;padding:24px;z-index:2000;max-width:500px;box-shadow:0 8px 32px rgba(0,0,0,0.6);";
  help.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
      <h3 style="color:var(--text-0);font-size:16px;">⌨ Klavye Kısayolları</h3>
      <span style="cursor:pointer;color:var(--text-2);font-size:20px;line-height:1;" onclick="document.getElementById('shortcut-help').remove()">×</span>
    </div>
    <table style="width:100%;font-size:13px;">
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">/</kbd></td><td style="color:var(--text-1);">Arama kutusuna odaklan</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">Esc</kbd></td><td style="color:var(--text-1);">Input'tan çık / popup kapat</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">?</kbd></td><td style="color:var(--text-1);">Bu yardım penceresi</td></tr>
      <tr><td colspan="2" style="padding:10px 0 6px;color:var(--text-2);font-size:11px;text-transform:uppercase;letter-spacing:0.5px;">Hızlı Navigasyon</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">1-9</kbd></td><td style="color:var(--text-1);">İlk 9 araç</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">d</kbd></td><td style="color:var(--text-1);">Dashboard</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">b</kbd></td><td style="color:var(--text-1);">Filter Builder</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">w</kbd></td><td style="color:var(--text-1);">Wizard</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">e</kbd></td><td style="color:var(--text-1);">Encyclopedia</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">h</kbd></td><td style="color:var(--text-1);">Handshake Teşhis</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">c</kbd></td><td style="color:var(--text-1);">Checklist</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">f</kbd></td><td style="color:var(--text-1);">Filtre Kütüphanesi</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">t</kbd></td><td style="color:var(--text-1);">tshark Builder</td></tr>
      <tr><td style="padding:4px 12px 4px 0;"><kbd style="background:var(--bg-3);padding:2px 8px;border-radius:4px;font-family:var(--mono);border:1px solid var(--border);">p</kbd></td><td style="color:var(--text-1);">PCAP Builder</td></tr>
    </table>
  `;
  document.body.appendChild(help);
}

document.addEventListener("DOMContentLoaded", init);
