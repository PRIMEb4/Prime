#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<32> CHAIN_SIZE = 10;
const bit<16> TYPE_INT_HEADER = 0x1212;
typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> qdepth_t;
typedef bit<32> switchID_t;
header tcp_t {
    bit<16> srcAddr;
    bit<16> dstAddr;
    bit<32> seqNumber;
    bit<32> ackNumber;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct custom_metadata_t_02 {
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
    bit<8>  nf_01_id;
    bit<8>  nf_02_id;
    bit<8>  nf_03_id;
    bit<32> rounds;
    bit<8>  next_function;
    bit<32> total_rounds;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header int_header_t {
    bit<16>    proto_id;
    switchID_t swid;
    qdepth_t   qdepth;
    switchID_t hop_delay;
    bit<48>    in_timestamp;
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
    custom_metadata_t    custom_metadata;
    standard_metadata_t  aux;
    egressSpec_t         port_aux;
    bit<64>              aux_ingress_metadata;
    bit<64>              aux_swap;
    custom_metadata_t_02 custom_metadata_02;
}

struct headers {
    ethernet_t      ethernet;
    int_header_t[7] int_header;
    ipv4_t          ipv4;
    tcp_t           tcp;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
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
            TYPE_INT_HEADER: parse_hint;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

register<bit<64>>(1) timestamps_bank;

register<bit<64>>(1) packet_count;

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    register<bit<16>>(32w16) heavy_hitter_counter1;
    register<bit<16>>(32w16) heavy_hitter_counter2;
    register<bit<16>>(1) smalltresh;
    register<bit<16>>(1) tresh;
    register<bit<64>>(1024) ts;
    register<bit<64>>(256) ts_sender;
    register<bit<64>>(256) ts_recver;
    register<bit<1>>(256) ts_valid;
    register<bit<32>>(32w16) Whois;
    register<bit<16>>(32w16) flowMax;
    register<bit<16>>(32w16) flowMin;
    action do_copy_to_cpu() {
        clone3(CloneType.I2E, (bit<32>)32w250, { standard_metadata });
    }
    action watch_ts() {
        meta.custom_metadata_02.ts_aux = (bit<64>)standard_metadata.ingress_global_timestamp;
        meta.custom_metadata_02.ts_zone = (bit<64>)hdr.ipv4.dstAddr & 0xf;
        ts_sender.read(meta.custom_metadata_02.ts_aux1, (bit<32>)meta.custom_metadata_02.ts_zone);
        ts_recver.read(meta.custom_metadata_02.ts_aux2, (bit<32>)meta.custom_metadata_02.ts_zone);
        if (meta.custom_metadata_02.ts_aux1 == (bit<64>)hdr.ipv4.srcAddr && meta.custom_metadata_02.ts_aux2 == (bit<64>)hdr.ipv4.dstAddr || meta.custom_metadata_02.ts_aux1 == 0 || meta.custom_metadata_02.ts_aux2 == 0) {
            meta.custom_metadata_02.ts_power = meta.custom_metadata_02.ts_aux >> 8;
            meta.custom_metadata_02.ts_modulo = meta.custom_metadata_02.ts_aux & 0xff;
            if (meta.custom_metadata_02.ts_power < 5) {
                if (meta.custom_metadata_02.ts_power == 0) {
                    meta.custom_metadata_02.ts_power = 1;
                } else {
                    if (meta.custom_metadata_02.ts_power == 1) {
                        meta.custom_metadata_02.ts_power = 2;
                    } else {
                        if (meta.custom_metadata_02.ts_power == 2) {
                            meta.custom_metadata_02.ts_power = 4;
                        } else {
                            if (meta.custom_metadata_02.ts_power == 3) {
                                meta.custom_metadata_02.ts_power = 8;
                            } else {
                                if (meta.custom_metadata_02.ts_power == 4) {
                                    meta.custom_metadata_02.ts_power = 16;
                                } else {
                                    if (meta.custom_metadata_02.ts_power == 5) {
                                        meta.custom_metadata_02.ts_power = 32;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            meta.custom_metadata_02.ts_zone = -1;
        }
        ts.read(meta.custom_metadata_02.ts_val1, (bit<32>)meta.custom_metadata_02.ts_zone + (bit<32>)meta.custom_metadata_02.ts_modulo);
        ts.write((bit<32>)meta.custom_metadata_02.ts_zone + (bit<32>)meta.custom_metadata_02.ts_modulo, meta.custom_metadata_02.ts_val1 + meta.custom_metadata_02.ts_power);
    }
    action set_heavy_hitter_count() {
        hash(meta.custom_metadata_02.hash_val1, HashAlgorithm.csum16, (bit<16>)0, { hdr.ipv4.dstAddr }, (bit<32>)16);
        heavy_hitter_counter1.read(meta.custom_metadata_02.count_val1, (bit<32>)meta.custom_metadata_02.hash_val1);
        meta.custom_metadata_02.count_val1 = meta.custom_metadata_02.count_val1 + 16w1;
        heavy_hitter_counter1.write((bit<32>)meta.custom_metadata_02.hash_val1, (bit<16>)meta.custom_metadata_02.count_val1);
        heavy_hitter_counter2.read(meta.custom_metadata_02.count_val2, (bit<32>)meta.custom_metadata_02.hash_val1);
        meta.custom_metadata_02.count_val2 = meta.custom_metadata_02.count_val2 + hdr.ipv4.totalLen;
        heavy_hitter_counter2.write((bit<32>)meta.custom_metadata_02.hash_val1, (bit<16>)meta.custom_metadata_02.count_val2);
    }
    action simple_forward(egressSpec_t port) {
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
    table monitor {
        actions = {
            watch_ts;
        }
        default_action = watch_ts;
        size = 1;
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action catalogue(bit<8> nf1, bit<8> nf2, bit<8> nf3, bit<32> ttl_rounds) {
        meta.custom_metadata.nf_01_id = nf1;
        meta.custom_metadata.nf_02_id = nf2;
        meta.custom_metadata.nf_03_id = nf3;
        meta.custom_metadata.total_rounds = ttl_rounds;
    }
    table shadow {
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
    apply {
        if (meta.custom_metadata.rounds > 0) {
            standard_metadata.egress_spec = meta.port_aux;
        }
        if (meta.custom_metadata.rounds == 0) {
            shadow.apply();
            meta.custom_metadata.next_function = meta.custom_metadata.nf_01_id;
            meta.aux_ingress_metadata = (bit<64>)standard_metadata.ingress_global_timestamp;
            packet_count.read(meta.aux_swap, 0);
            packet_count.write(0, meta.aux_swap + 1);
        }
        if (meta.custom_metadata.next_function == 1) {
            if (hdr.ipv4.isValid()) {
                ipv4_lpm.apply();
            }
        }
        if (meta.custom_metadata.next_function == 2) {
            if (hdr.ipv4.isValid()) {
                set_heavy_hitter_count_table.apply();
                smalltresh.read(meta.custom_metadata_02.smalltresh, 0);
                tresh.read(meta.custom_metadata_02.tresh, 0);
                if (meta.custom_metadata_02.count_val1 > meta.custom_metadata_02.smalltresh) {
                    monitor.apply();
                }
                if (meta.custom_metadata_02.count_val1 > meta.custom_metadata_02.tresh) {
                    copy_to_cpu.apply();
                }
            }
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_swtrace(switchID_t swid) {
        hdr.int_header.push_front(1);
        hdr.int_header[0].setValid();
        hdr.int_header[0].proto_id = TYPE_INT_HEADER;
        hdr.int_header[0].swid = swid;
        hdr.int_header[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;
        hdr.int_header[0].hop_delay = (bit<32>)standard_metadata.deq_timedelta;
        hdr.int_header[0].in_timestamp = (bit<48>)standard_metadata.ingress_global_timestamp;
    }
    table swtrace {
        actions = {
            add_swtrace;
            NoAction;
        }
        default_action = NoAction();
    }
    apply {
        if (meta.custom_metadata.next_function == 3) {
            swtrace.apply();
        }
        if (meta.custom_metadata.rounds < meta.custom_metadata.total_rounds) {
            meta.custom_metadata.rounds = meta.custom_metadata.rounds + 1;
            if (meta.custom_metadata.rounds == 1) {
                meta.custom_metadata.next_function = meta.custom_metadata.nf_01_id;
            } else if (meta.custom_metadata.rounds == 2) {
                meta.custom_metadata.next_function = meta.custom_metadata.nf_02_id;
            } else if (meta.custom_metadata.rounds == 3) {
                meta.custom_metadata.next_function = meta.custom_metadata.nf_03_id;
            }
            meta.port_aux = standard_metadata.egress_spec;
            recirculate(meta);
        } else {
            timestamps_bank.read(meta.aux_swap, 0);
            timestamps_bank.write(0, meta.aux_swap + ((bit<64>)standard_metadata.egress_global_timestamp - meta.aux_ingress_metadata));
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
	packet.emit(hdr.int_header);
	packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;

