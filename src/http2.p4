#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<16> HTTP_PORT_NO = 16w80;

typedef bit<48> macAddr_t;
typedef bit<9> egressSpec_t; 

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> opcode;
    bit<48> hwSrcAddr;
    bit<32> protoSrcAddr;
    bit<48> hwDstAddr;
    bit<32> protoDstAddr;
}

 

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
 
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<4>  ctrl1;
    bit<1>  syn;
    bit<1>  ctrl2;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_option_t{
    varbit<512> tcp_opt_h;
}

header http2_t {
    bit<24> h_len;
    bit<8>  h_type;
    bit<8>  h_flags;
    bit<32> h_sid;
	
}

header queueing_metadata_t {
    bit<48> enq_timestamp;
    bit<24> enq_qdepth;
    bit<32> deq_timedelta;
    bit<24> deq_qdepth;
    bit<8>  qid;
}

struct metadata {
    queueing_metadata_t queueing_metadata;
}

struct headers {
    @name(".arp")
    arp_t      arp;

    @name(".ethernet")
    ethernet_t ethernet;

    @name(".ipv4")
    ipv4_t     ipv4;

    @name(".icmp")
    icmp_t        icmp;

    @name(".tcp")
    tcp_t	  tcp;

    @name(".tcp_options")
    tcp_option_t  tcp_options;

    @name(".http2")
    http2_t       http2;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

parser TCP_option_parser(packet_in b, in bit<16> ip_hdr_len,  in bit<4> tcp_hdr_data_offset, out tcp_option_t tcp_option) {
    
    bit<7> tcp_hdr_bytes_left;
  
    state start {
  	    verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
  	    tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        //tcp_hdr_bytes_left = ((4* (bit<7>)(tcp_hdr_data_offset)-20));
  	    transition consume_remaining_tcp_hdr_and_accept;
    }
    
    state consume_remaining_tcp_hdr_and_accept {
        // A more picky sub-parser implementation would verify that
        // all of the remaining bytes are 0, as specified in RFC 793,
        // setting an error and rejecting if not.  This one skips past
        // the rest of the TCP header without checking this.

        // tcp_hdr_bytes_left might be as large as 40, so multiplying
        // it by 8 it may be up to 320, which requires 9 bits to avoid
        // losing any information.
        b.extract(tcp_option, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }
}
 
parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    @name(".start") state start {
        transition parse_ethernet;
    }

    @name(".parse_arp") state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
	        IPPROTO_ICMP: parse_icmp;
            IPPROTO_TCP: parse_tcp;
	        default: accept;
        }
    }

    @name(".parse_icmp") state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
	    TCP_option_parser.apply(packet, hdr.ipv4.totalLen, hdr.tcp.dataOffset, hdr.tcp_options);
        transition select(hdr.tcp.dstPort) {
	        HTTP_PORT_NO: parse_http2;
	        1 : accept;
	        // IPERF_PORT_NO: accept;
            default: parse_tcp_syn;
	    }
	    //transition accept;
    }

    @name(".parse_tcp_syn") state parse_tcp_syn {
        transition select(hdr.tcp.srcPort){
            HTTP_PORT_NO: parse_http2;
            // IPERF_PORT_NO: accept;
            default : accept;	
        }
    }

    @name(".parse_http2") state parse_http2 {
    	packet.extract(hdr.http2);
        transition accept;
        //transition select(hdr.http2.h_sid){
        //    1: accept;
        //    3: accept;  	
        //    default: accept;
        //}
    }
}

 

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {

    }
}

 

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".set_nhop") action set_nhop(macAddr_t fastDstAddr, egressSpec_t fastPort, macAddr_t slowDstAddr, egressSpec_t slowPort) {

        // Set the new source MAC address to the MAC address of the node
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; 

        // Only consider HTTP2 traffic for QoS
        if (hdr.http2.isValid()) {
            // If the source/destination port is 80, we consider it to be important traffic that should be transmitted on the fast path
            // This is a pretty rudimentary way to differentiate the cross traffic from video streaming traffic
            if (hdr.tcp.srcPort==HTTP_PORT_NO || hdr.tcp.dstPort==HTTP_PORT_NO){
                // Set the destination to the "fast path" destination
                hdr.ethernet.dstAddr = fastDstAddr;
                standard_metadata.egress_spec = fastPort;
            } 
            else {
                // If the port is wrong, use the slow path instead
                hdr.ethernet.dstAddr = slowDstAddr;
                standard_metadata.egress_spec = slowPort;
            }
        } 
        else {
            // If the traffic isn't HTTP/2 use the slow path too
            hdr.ethernet.dstAddr = slowDstAddr;
            standard_metadata.egress_spec = slowPort;
        }

        // Decrease Time to Live by 1 for all packets
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }

    @name(".ipv4_lpm") table ipv4_lpm {
        actions = {
            set_nhop;
            _drop;
        }

        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        size = 512;
        const default_action = _drop();
    }

    apply {
        ipv4_lpm.apply();
    }

}

 

control DeparserImpl(packet_out packet, in headers hdr) {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options);
        packet.emit(hdr.http2);
    }

}

 

control verifyChecksum(inout headers hdr, inout metadata meta) {

    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }

}

 

control computeChecksum(inout headers hdr, inout metadata meta) {

    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }

}

 

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;