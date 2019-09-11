/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

<<<<<<< HEAD
const bit<16> TYPE_IPV4 = 0x800;
=======
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
>>>>>>> e50cf33d5a2f0743e361911bb61f7a0f3f1e12b0

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

<<<<<<< HEAD
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

=======
>>>>>>> e50cf33d5a2f0743e361911bb61f7a0f3f1e12b0
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

<<<<<<< HEAD
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
=======
struct metadata {
>>>>>>> e50cf33d5a2f0743e361911bb61f7a0f3f1e12b0
}

struct headers {
    ethernet_t   ethernet;
<<<<<<< HEAD
    ipv4_t       ipv4;
=======
>>>>>>> e50cf33d5a2f0743e361911bb61f7a0f3f1e12b0
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
<<<<<<< HEAD
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

=======
        transition accept;
    }
>>>>>>> e50cf33d5a2f0743e361911bb61f7a0f3f1e12b0
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
<<<<<<< HEAD
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
=======

    action drop() {
        mark_to_drop();
    }

    action simple_forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }


    table eth_exact{
        key = {
            hdr.ethernet.srcAddr:exact;
        }
        actions={
             simple_forward();
             NoAction;
             drop;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
	   eth_exact.apply();
>>>>>>> e50cf33d5a2f0743e361911bb61f7a0f3f1e12b0
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
<<<<<<< HEAD

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

=======
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {   }
}


>>>>>>> e50cf33d5a2f0743e361911bb61f7a0f3f1e12b0
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
<<<<<<< HEAD
        packet.emit(hdr.ipv4);
=======
>>>>>>> e50cf33d5a2f0743e361911bb61f7a0f3f1e12b0
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
