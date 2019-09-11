/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 6

const bit<16> TYPE_IPV4 = 0x800;
const bit<32> CHAIN_SIZE = 10;
const bit<16> TYPE_INT_HEADER = 0x1212;

/*********************************************************************
*********************** H E A D E R S  *******************************
**********************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> qdepth_t;
typedef bit<32> switchID_t;

struct custom_metadata_t_1 {
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

struct custom_metadata_t {
    bit<8>                 nf_01_id;
    bit<8>                 nf_02_id; 
    bit<8>                 nf_03_id;
    bit<8>                 nf_04_id;
    bit<32>                rounds;
    bit<8>                 next_function; 
    bit<32>                total_rounds;
}


struct ingress_metadata_t {
    bit<32> flow_ipg;
    bit<13> flowlet_map_index;
    bit<16> flowlet_id;
    bit<32> flowlet_lasttime;
    bit<14> ecmp_offset;
    bit<32> nhop_ipv4;
}

struct intrinsic_metadata_t {
    bit<32> deq_timedelta;
    bit<32> enq_timestamp;
    bit<32> ingress_global_timestamp;
    bit<32> egress_global_timestamp;
}



header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header int_header_t {
  bit<16>     proto_id;
  switchID_t  swid;
  qdepth_t    qdepth;
  switchID_t  hop_delay;
  bit<48>     in_timestamp;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
  bit<16> srcAddr;
  bit<16> dstAddr;
  bit<32> seqNumber;
  bit<32> ackNumber;
  bit<4> dataOffset;
  bit<4> res;
  bit<8> flags;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgentPtr;
}

struct metadata {
    custom_metadata_t_1                             custom_metadata_1;
    custom_metadata_t                                  custom_metadata;
    standard_metadata_t                               aux;
    egressSpec_t                                                  port_aux;
    @name(".ingress_metadata") 
    ingress_metadata_t                                   ingress_metadata;
    @name(".intrinsic_metadata") 
    intrinsic_metadata_t                                  intrinsic_metadata;
    bit<64>                                                                aux_ingress_metadata;
    bit<64>                                                                aux_swap;
}

struct headers {
    ethernet_t                                           ethernet;
    ipv4_t                                                     ipv4;
    int_header_t[MAX_HOPS]        int_header;
    tcp_t       						       tcp;
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
      TYPE_INT_HEADER: parse_hint;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

  state parse_hint {
    packet.extract(hdr.int_header.next);
    transition select(hdr.int_header.last.proto_id) {
      TYPE_IPV4: parse_ipv4;
      TYPE_INT_HEADER : parse_hint;
      default: accept;
    }
  }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol){
      6       : parse_tcp;
      default : accept;
  }
    }

  state parse_tcp {
    packet.extract(hdr.tcp);
    transition accept;
  }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


@name(".flowlet_id") register<bit<16>>(32w8192) flowlet_id;
@name(".flowlet_lasttime") register<bit<32>>(32w8192) flowlet_lasttime;


   register<bit<64>>(1) timestamps_bank;
   register<bit<64>>(1) packet_count;


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
    register<bit<64>>(1024) ts;  //256 regs  8 regs/zone  32 zones 
    register<bit<64>>(256) ts_sender;
    register<bit<64>>(256) ts_recver;
    register<bit<1>>(256) ts_valid;
    //maxmin --trexoulds
    register<bit<32>>(32w16) Whois;
    register<bit<16>>(32w16) flowMax;
    register<bit<16>>(32w16) flowMin;

    action do_copy_to_cpu() { 
        clone3(CloneType.I2E, (bit<32>)32w250, { standard_metadata });
    }

    action watch_ts() {
        meta.custom_metadata_1.ts_aux= (bit<64>) standard_metadata.ingress_global_timestamp;

        meta.custom_metadata_1.ts_zone= (bit<64>)hdr.ipv4.dstAddr & 0x000000000000000F;//zone number = src modulo 256  (and 8 bits)
        ts_sender.read(meta.custom_metadata_1.ts_aux1, (bit<32>) meta.custom_metadata_1.ts_zone);
        ts_recver.read(meta.custom_metadata_1.ts_aux2, (bit<32>) meta.custom_metadata_1.ts_zone);
        
        if ((meta.custom_metadata_1.ts_aux1== (bit<64>) hdr.ipv4.srcAddr && meta.custom_metadata_1.ts_aux2== (bit<64>)  hdr.ipv4.dstAddr) || meta.custom_metadata_1.ts_aux1==0 || meta.custom_metadata_1.ts_aux2==0 ){ 
          meta.custom_metadata_1.ts_power=meta.custom_metadata_1.ts_aux>>8;
          meta.custom_metadata_1.ts_modulo=meta.custom_metadata_1.ts_aux & 0x00000000000000FF;
          
          if(meta.custom_metadata_1.ts_power<5){
            if(meta.custom_metadata_1.ts_power==0){
                meta.custom_metadata_1.ts_power=1;
              } else{
                if(meta.custom_metadata_1.ts_power==1){
                    meta.custom_metadata_1.ts_power=2;
                } else{
                    if(meta.custom_metadata_1.ts_power==2){
                      meta.custom_metadata_1.ts_power=4;
                    } else{
                      if(meta.custom_metadata_1.ts_power==3){
                          meta.custom_metadata_1.ts_power=8;
                      } else{
                          if(meta.custom_metadata_1.ts_power==4){
                            meta.custom_metadata_1.ts_power=16;
                          } else{
                            if(meta.custom_metadata_1.ts_power==5)
                              meta.custom_metadata_1.ts_power=32;
                          }
                      }
                    }
                }
              }
          }
        }else{
          meta.custom_metadata_1.ts_zone=-1;
        }
        ts.read(meta.custom_metadata_1.ts_val1, (bit<32>) meta.custom_metadata_1.ts_zone + (bit<32>)meta.custom_metadata_1.ts_modulo);   
        ts.write( (bit<32>)meta.custom_metadata_1.ts_zone + (bit<32>)meta.custom_metadata_1.ts_modulo, meta.custom_metadata_1.ts_val1 + meta.custom_metadata_1.ts_power);
        /////////////////END WATCH TS///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /////////////////BEGIN wATCHLims////////////////////////////////////////////////////////////////////////////////////////////////////////
    }

    action set_heavy_hitter_count() {
      //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        hash(meta.custom_metadata_1.hash_val1, HashAlgorithm.csum16, (bit<16>)0, { hdr.ipv4.dstAddr }, (bit<32>)16);
        heavy_hitter_counter1.read(meta.custom_metadata_1.count_val1, (bit<32>)meta.custom_metadata_1.hash_val1);        
        meta.custom_metadata_1.count_val1 = meta.custom_metadata_1.count_val1 + 16w1;
        heavy_hitter_counter1.write((bit<32>)meta.custom_metadata_1.hash_val1, (bit<16>)meta.custom_metadata_1.count_val1);
        heavy_hitter_counter2.read(meta.custom_metadata_1.count_val2, (bit<32>)meta.custom_metadata_1.hash_val1);
        meta.custom_metadata_1.count_val2=meta.custom_metadata_1.count_val2+hdr.ipv4.totalLen;
        heavy_hitter_counter2.write((bit<32>)meta.custom_metadata_1.hash_val1, (bit<16>)meta.custom_metadata_1.count_val2);
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

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action catalogue( bit<8> nf1, bit<8> nf2, bit<8> nf3, bit<8> nf4, bit<32> ttl_rounds) {
        meta.custom_metadata.nf_01_id  =   nf1;
        meta.custom_metadata.nf_02_id  =   nf2;
        meta.custom_metadata.nf_03_id  =   nf3;
        meta.custom_metadata.nf_04_id  =   nf4;
        meta.custom_metadata.total_rounds = ttl_rounds;
     }

    table shadow{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            catalogue;
        }
         size = 1024;
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
    }

    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }

    @name(".set_ecmp_select") action set_ecmp_select(bit<8> ecmp_base, bit<8> ecmp_count) {
        hash(meta.ingress_metadata.ecmp_offset, HashAlgorithm.crc16, (bit<10>)ecmp_base, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcAddr, hdr.tcp.dstAddr, meta.ingress_metadata.flowlet_id }, (bit<20>)ecmp_count);
    }
    @name(".set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.ingress_metadata.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    @name(".lookup_flowlet_map") action lookup_flowlet_map() {
        hash(meta.ingress_metadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcAddr, hdr.tcp.dstAddr }, (bit<26>)13);
        flowlet_id.read(meta.ingress_metadata.flowlet_id, (bit<32>)meta.ingress_metadata.flowlet_map_index);
        meta.ingress_metadata.flow_ipg = meta.intrinsic_metadata.ingress_global_timestamp;
        flowlet_lasttime.read(meta.ingress_metadata.flowlet_lasttime, (bit<32>)meta.ingress_metadata.flowlet_map_index);
        meta.ingress_metadata.flow_ipg = meta.ingress_metadata.flow_ipg - meta.ingress_metadata.flowlet_lasttime;
        flowlet_lasttime.write((bit<32>)meta.ingress_metadata.flowlet_map_index, (bit<32>)meta.intrinsic_metadata.ingress_global_timestamp);
    }
    @name(".set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    @name(".update_flowlet_id") action update_flowlet_id() {
        meta.ingress_metadata.flowlet_id = meta.ingress_metadata.flowlet_id + 16w1;
        flowlet_id.write((bit<32>)meta.ingress_metadata.flowlet_map_index, (bit<16>)meta.ingress_metadata.flowlet_id);
    }
    @name(".ecmp_group") table ecmp_group {
        actions = {
            _drop;
            set_ecmp_select;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    @name(".ecmp_nhop") table ecmp_nhop {
        actions = {
            set_nhop;
        }
        key = {
            meta.ingress_metadata.ecmp_offset: exact;
        }
        size = 16384;
    }
    @name(".flowlet") table flowlet {
        actions = {
            lookup_flowlet_map;
        }
    }
    @name(".forward") table forward {
        actions = {
            set_dmac;
            _drop;
        }
        key = {
            meta.ingress_metadata.nhop_ipv4: exact;
        }
        size = 512;
    }
    @name(".new_flowlet") table new_flowlet {
        actions = {
            update_flowlet_id;
        }
    }

    apply {
      if(meta.custom_metadata.rounds > 0) {
        standard_metadata.egress_spec = meta.port_aux;
      }

      if (meta.custom_metadata.rounds == 0){
          shadow.apply();
           meta.custom_metadata.next_function = meta.custom_metadata.nf_01_id;
           meta.aux_ingress_metadata = (    bit<64>    ) standard_metadata.ingress_global_timestamp;
           packet_count.read(meta.aux_swap,0);
	   packet_count.write(0, meta.aux_swap + 1);
      }

        //if the next function to be processed is the function with ID=1
        if (meta.custom_metadata.next_function == 1){
          if(hdr.ipv4.isValid()){
            set_heavy_hitter_count_table.apply();
            smalltresh.read(meta.custom_metadata_1.smalltresh,0);
            tresh.read(meta.custom_metadata_1.tresh,0);
            if( meta.custom_metadata_1.count_val1 > meta.custom_metadata_1.smalltresh ){
              monitor.apply();
            }
            if( meta.custom_metadata_1.count_val1 > meta.custom_metadata_1.tresh ){
              copy_to_cpu.apply();
            }
          }
        }
   
        if (meta.custom_metadata.next_function == 2){
            if (hdr.ipv4.isValid()) {
                ipv4_lpm.apply();
            }
        }

        if (meta.custom_metadata.next_function == 4){
            flowlet.apply();
            if (meta.ingress_metadata.flow_ipg > 32w50000) {
              new_flowlet.apply();
            }
            ecmp_group.apply();
            ecmp_nhop.apply();
            forward.apply();
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
   
  action add_swtrace1(switchID_t swid){
    hdr.int_header[0].proto_id = TYPE_INT_HEADER;
    hdr.int_header[0].swid = swid;
    hdr.int_header[0].qdepth = (qdepth_t) standard_metadata.deq_qdepth;
    hdr.int_header[0].hop_delay = (bit <32>) standard_metadata.deq_timedelta;  //Hop delay is in microsseconds
    hdr.int_header[0].in_timestamp = (bit <48>) standard_metadata.ingress_global_timestamp;
  }

  action add_swtrace2(switchID_t swid){
    hdr.int_header[1].proto_id = TYPE_INT_HEADER;
    hdr.int_header[1].swid = swid;
    hdr.int_header[1].qdepth = (qdepth_t) standard_metadata.deq_qdepth;
    hdr.int_header[1].hop_delay = (bit <32>) standard_metadata.deq_timedelta;  //Hop delay is in microsseconds
    hdr.int_header[1].in_timestamp = (bit <48>) standard_metadata.ingress_global_timestamp;
  }

  action add_swtrace3(switchID_t swid){
    hdr.int_header[2].proto_id = TYPE_INT_HEADER;
    hdr.int_header[2].swid = swid;
    hdr.int_header[2].qdepth = (qdepth_t) standard_metadata.deq_qdepth;
    hdr.int_header[2].hop_delay = (bit <32>) standard_metadata.deq_timedelta;  //Hop delay is in microsseconds
    hdr.int_header[2].in_timestamp = (bit <48>) standard_metadata.ingress_global_timestamp;
  }

  action add_swtrace4(switchID_t swid){
    hdr.int_header[3].proto_id = TYPE_INT_HEADER;
    hdr.int_header[3].swid = swid;
    hdr.int_header[3].qdepth = (qdepth_t) standard_metadata.deq_qdepth;
    hdr.int_header[3].hop_delay = (bit <32>) standard_metadata.deq_timedelta;  //Hop delay is in microsseconds
    hdr.int_header[3].in_timestamp = (bit <48>) standard_metadata.ingress_global_timestamp;
  }

  action add_swtrace5(switchID_t swid){
    hdr.int_header[4].proto_id = TYPE_INT_HEADER;
    hdr.int_header[4].swid = swid;
    hdr.int_header[4].qdepth = (qdepth_t) standard_metadata.deq_qdepth;
    hdr.int_header[4].hop_delay = (bit <32>) standard_metadata.deq_timedelta;  //Hop delay is in microsseconds
    hdr.int_header[4].in_timestamp = (bit <48>) standard_metadata.ingress_global_timestamp;
  }

  action add_swtrace6(switchID_t swid){
    hdr.int_header[5].proto_id = TYPE_IPV4;
    hdr.int_header[5].swid = swid;
    hdr.int_header[5].qdepth = (qdepth_t) standard_metadata.deq_qdepth;
    hdr.int_header[5].hop_delay = (bit <32>) standard_metadata.deq_timedelta;  //Hop delay is in microsseconds
    hdr.int_header[5].in_timestamp = (bit <48>) standard_metadata.ingress_global_timestamp;
  }

  @name(".rewrite_mac") action rewrite_mac(bit<48> smac) {
      hdr.ethernet.srcAddr = smac;
  }
  @name("._drop") action _drop() {
      mark_to_drop(standard_metadata);
  }
  @name(".send_frame") table send_frame {
      actions = {
          rewrite_mac;
          _drop;
      }
      key = {
          standard_metadata.egress_port: exact;
      }
      size = 256;
  }

  table swtrace {
    actions = {
      add_swtrace1;
        add_swtrace2;
        add_swtrace3;
        add_swtrace4;
        add_swtrace5;
        add_swtrace6;
        NoAction;
    }
      default_action = NoAction();
  }
 
   apply {
     //set next function

  if(meta.custom_metadata.next_function == 3){
    swtrace.apply();
  }

  if(meta.custom_metadata.next_function == 4){
        send_frame.apply();    
  }

        if(meta.custom_metadata.rounds < meta.custom_metadata.total_rounds){
              meta.custom_metadata.rounds = meta.custom_metadata.rounds + 1;
              if(meta.custom_metadata.rounds == 1)
                  meta.custom_metadata.next_function = meta.custom_metadata.nf_01_id;
              else if(meta.custom_metadata.rounds == 2)
                      meta.custom_metadata.next_function = meta.custom_metadata.nf_02_id;
              else if(meta.custom_metadata.rounds == 3)
                      meta.custom_metadata.next_function = meta.custom_metadata.nf_03_id;
              else if(meta.custom_metadata.rounds == 4)
                      meta.custom_metadata.next_function = meta.custom_metadata.nf_04_id;
             
        //-------- DO IT FOR N FUNCTIONS
              meta.port_aux = standard_metadata.egress_spec;
             recirculate(meta);
	}else{
                timestamps_bank.read(meta.aux_swap,0);
                //timestamps_bank.write(0, meta.aux_ingress_metadata + 1);
		timestamps_bank.write(0, meta.aux_swap + (   ( bit<64>  )  standard_metadata.egress_global_timestamp - 	meta.aux_ingress_metadata));
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.int_header[0]);
        packet.emit(hdr.int_header[1]);
        packet.emit(hdr.int_header[2]);
        packet.emit(hdr.int_header[3]);
        packet.emit(hdr.int_header[4]);
        packet.emit(hdr.int_header[5]);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
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
