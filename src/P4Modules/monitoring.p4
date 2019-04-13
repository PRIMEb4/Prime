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

    action drop() {
        mark_to_drop();
    }

    register<bit<16>>(32w16) heavy_hitter_counter1;
    register<bit<16>>(32w16) heavy_hitter_counter2;
    register<bit<16>>(1) smalltresh;
    
    register<bit<16>>(1) tresh;
    register<bit<64>>(1024) ts;  //256 regs  8 regs/zone  32 zones 
    register<bit<64>>(256) ts_sender;
    register<bit<64>>(256) ts_recver;
    register<bit<1>>(256) ts_valid;

    //maxmin
    register<bit<32>>(32w16) Whois;
    register<bit<16>>(32w16) flowMax;
    register<bit<16>>(32w16) flowMin;

    action do_copy_to_cpu() { 
        clone3(CloneType.I2E, (bit<32>)32w250, { standard_metadata });
    }

    action watch_ts() {
      meta.custom_metadata.ts_aux= (bit<64>) standard_metadata.ingress_global_timestamp;

      meta.custom_metadata.ts_zone= (bit<64>)hdr.ipv4.dstAddr & 0x000000000000000F;//zone number = src modulo 256  (and 8 bits)
      ts_sender.read(meta.custom_metadata.ts_aux1, (bit<32>) meta.custom_metadata.ts_zone);
      ts_recver.read(meta.custom_metadata.ts_aux2, (bit<32>) meta.custom_metadata.ts_zone);
      
      if ((meta.custom_metadata.ts_aux1== (bit<64>) hdr.ipv4.srcAddr && meta.custom_metadata.ts_aux2== (bit<64>)  hdr.ipv4.dstAddr) || meta.custom_metadata.ts_aux1==0 || meta.custom_metadata.ts_aux2==0 ){ 

        meta.custom_metadata.ts_power=meta.custom_metadata.ts_aux>>8;
        meta.custom_metadata.ts_modulo=meta.custom_metadata.ts_aux & 0x00000000000000FF;
          
        if(meta.custom_metadata.ts_power<5){
          if(meta.custom_metadata.ts_power==0){
            meta.custom_metadata.ts_power=1;
          } else{
            if(meta.custom_metadata.ts_power==1){
              meta.custom_metadata.ts_power=2;
            } else{
              if(meta.custom_metadata.ts_power==2){
                meta.custom_metadata.ts_power=4;
              } else{
                if(meta.custom_metadata.ts_power==3){
                  meta.custom_metadata.ts_power=8;
                } else{
                  if(meta.custom_metadata.ts_power==4){
                    meta.custom_metadata.ts_power=16;
                  } else{
                    if(meta.custom_metadata.ts_power==5)
                    meta.custom_metadata.ts_power=32;
                  }
                }
              }
            }
          }
        }
      }else{
        meta.custom_metadata.ts_zone=-1;
      }
      ts.read(meta.custom_metadata.ts_val1, (bit<32>) meta.custom_metadata.ts_zone + (bit<32>)meta.custom_metadata.ts_modulo);
          
      ts.write( (bit<32>)meta.custom_metadata.ts_zone + (bit<32>)meta.custom_metadata.ts_modulo, meta.custom_metadata.ts_val1 + meta.custom_metadata.ts_power);
    /////////////////END WATCH TS///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /////////////////BEGIN wATCHLims////////////////////////////////////////////////////////////////////////////////////////////////////////

    }

  action set_heavy_hitter_count() {
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        hash(meta.custom_metadata.hash_val1, HashAlgorithm.csum16, (bit<16>)0, { hdr.ipv4.dstAddr }, (bit<32>)16);
        heavy_hitter_counter1.read(meta.custom_metadata.count_val1, (bit<32>)meta.custom_metadata.hash_val1);
        
        meta.custom_metadata.count_val1 = meta.custom_metadata.count_val1 + 16w1;

        heavy_hitter_counter1.write((bit<32>)meta.custom_metadata.hash_val1, (bit<16>)meta.custom_metadata.count_val1);

        heavy_hitter_counter2.read(meta.custom_metadata.count_val2, (bit<32>)meta.custom_metadata.hash_val1);

        meta.custom_metadata.count_val2=meta.custom_metadata.count_val2+hdr.ipv4.totalLen;
        heavy_hitter_counter2.write((bit<32>)meta.custom_metadata.hash_val1, (bit<16>)meta.custom_metadata.count_val2);
    }


    action simple_forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }


    table set_heavy_hitter_count_table {
        actions = {
            set_heavy_hitter_count;
        }
        default_action = set_heavy_hitter_count;
        size = 1;
    }

  
     table copy_to_cpu {
          actions = {
              do_copy_to_cpu;
          }
          default_action = do_copy_to_cpu;
          size = 1;
     }
    
    table monitor{

      actions = {
        watch_ts;
      }
      default_action = watch_ts;
      size = 1;
    }

    apply {
        //flowguard_ingress(); this line should call the modular function
        //For now im calling it here

        if(hdr.ipv4.isValid()){

            set_heavy_hitter_count_table.apply();

            smalltresh.read(meta.custom_metadata.smalltresh,0);

            tresh.read(meta.custom_metadata.tresh,0);

            if( meta.custom_metadata.count_val1 > meta.custom_metadata.smalltresh ){
                monitor.apply();
            }
            if( meta.custom_metadata.count_val1 > meta.custom_metadata.tresh ){
              copy_to_cpu.apply();
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