header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header ethernet_t{
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t{
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


        parser MyParser(packet_in packet,
                        out headers hdr,
                        inout metadata meta,
                        inout standard_metadata_t standard_metadata) {
         {

 state start { 
transition parse_ethernet; 
}
 state parse_ipv4 { 
packet.extract(hdr.ipv4);
transition select(hdr.ipv4.protocol){
default:accept; 
6:parse_tcp; 
}
}
 state parse_tcp { 
packet.extract(hdr.tcp);
transition accept; 
}
 state parse_ethernet { 
packet.extract(hdr.ethernet);
transition accept; 
}
}



control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
            action set_chaining(egressSpec_t prog){
         meta.context_control = 1;
         meta.extension_id1 = prog;
        } action drop() {
        mark_to_drop();
    }

action simple_forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }

action drop() {
        mark_to_drop();
    }

action simple_forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }

action drop() {
        mark_to_drop();
    }

action set_ecmp_select(bit<16> ecmp_base, bit<32> ecmp_count) {
        /* TODO: hash on 5-tuple and save the hash result in meta.ecmp_select 
           so that the ecmp_nhop table can use it to make a forwarding decision accordingly */
    }

action set_nhop(bit<48> nhop_dmac, bit<32> nhop_ipv4, bit<9> port) {
        hdr.ethernet.dstAddr = nhop_dmac;
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }

action drop() {
        mark_to_drop();
    }

table shadow{
           key = {
              hdr.ethernet.dstAddr: lpm;
           }
           actions = {
               set_chaining;
               NoAction;
           }
           size = 1024;
           default_action = NoAction();
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

table ecmp_group{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
        }
        size = 1024;
    }

table ecmp_nhop{
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 2;
    }

table send_frame{
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            rewrite_mac;
            drop;
        }
        size = 256;
    }

}
        apply {
            shadow.apply();
            if(meta.context_control == 1){ 
if(meta.extension_host_id==1) { 

                     {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            ecmp_group.apply();
            ecmp_nhop.apply();
        }
    }
                }if(meta.extension_host_id==666){
                     {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            ecmp_group.apply();
            ecmp_nhop.apply();
        }
    }
                }
            
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
            control MyComputeChecksum(inout headers hdr, inout metadata meta) {
                apply {   }
            }


            /*************************************************************************
            ***********************  D E P A R S E R  *******************************
            *************************************************************************/

            control MyDeparser(packet_out packet, in headers hdr) {
                apply {
                    packet.emit(hdr.ethernet);
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