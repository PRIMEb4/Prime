/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


/*this is perfumaria*/
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

struct custom_metadata_t {
    bit<32> nhop_ipv4;
    bit<16> hash_val1;
    bit<16> hash_val2;
    bit<16> count_val1;
    bit<16> count_val2;
    bit<64> ts_val1;
    bit<64> ts_val2;
    bit<16> tresh;
    bit<16> smalltresh;
    bit<64> ts_aux;
    bit<64> ts_modulo;
    bit<64> ts_zone;
    bit<64> ts_power;
    bit<64> ts_aux1;
    bit<64> ts_aux2;
    bit<64> ts_aux3;
    bit<64> ts_zone_sz;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

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
    custom_metadata_t custom_metadata;
    bit<32> warning_t1;
    bit<32> warning_t2;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
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
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
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

    register<bit<16>>(32w16) heavy_hitter_counter1;
    register<bit<16>>(32w16) heavy_hitter_counter2;
    register<bit<16>>(1) smalltresh;
    register<bit<16>>(1) tresh;

    action set_heavy_hitter_count() {       
          hash(meta.custom_metadata.hash_val1, HashAlgorithm.csum16, (bit<16>)0, { hdr.ipv4.dstAddr }, (bit<32>)16);

          heavy_hitter_counter1.read(meta.custom_metadata.count_val1, (bit<32>)meta.custom_metadata.hash_val1);
          
          meta.custom_metadata.count_val1 = meta.custom_metadata.count_val1 + 16w1;

          heavy_hitter_counter1.write((bit<32>)meta.custom_metadata.hash_val1, (bit<16>)meta.custom_metadata.count_val1);

          heavy_hitter_counter2.read(meta.custom_metadata.count_val2, (bit<32>)meta.custom_metadata.hash_val1);

          meta.custom_metadata.count_val2 = meta.custom_metadata.count_val2+hdr.ipv4.totalLen;

          heavy_hitter_counter2.write((bit<32>)meta.custom_metadata.hash_val1, (bit<16>)meta.custom_metadata.count_val2);
      }

      table set_heavy_hitter_count_table {
          actions = {
              set_heavy_hitter_count;
          }
          default_action = set_heavy_hitter_count;
          size = 1;
      }

      apply {
        if(hdr.ipv4.isValid()){
            set_heavy_hitter_count_table.apply();

            smalltresh.read(meta.custom_metadata.smalltresh,0);

            tresh.read(meta.custom_metadata.tresh,0);

            if( meta.custom_metadata.count_val1 > meta.custom_metadata.smalltresh ){
                meta.custom_metadata.warning_t1 = 100;    
            }
            if( meta.count_val2 > meta.custom_metadata.tresh ){
                meta.warning_t2 = 100 
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
        packet.emit(hdr.ipv4);
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