/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<32> CHAIN_SIZE = 10;

/*********************************************************************
*********************** H E A D E R S  *******************************
**********************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

struct custom_metadata_t {
    bit<8>                 nf_01_id;
    bit<8>                 nf_02_id; 
    bit<8>                 nf_03_id;
    bit<8>                 nf_04_id;
    bit<8>                 nf_05_id;
    bit<8>                 nf_06_id;
    bit<8>                 nf_07_id;
    bit<8>                 nf_08_id;                    
    bit<32>                rounds;
    bit<8>                 next_function; 
    bit<32>                total_rounds;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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

struct metadata {
    custom_metadata_t                     custom_metadata;
    standard_metadata_t   			      aux;
    egressSpec_t               		      port_aux;
    bit<64>                               aux_ingress_metadata;
    bit<64>                               aux_swap;
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

/************ registers for Whippersnapper evaluation ***********************/
register<bit<64>>(1) timestamps_bank;
register<bit<64>>(1) packet_count;

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action catalogue( bit<8> nf1, bit<8> nf2, bit<8> nf3, bit<8> nf4, bit<8> nf5, bit<8> nf6, bit<8> nf6, bit<8> nf7, bit<8> nf8, bit<32> ttl_rounds) {
        meta.custom_metadata.nf_01_id  =   nf1;
        meta.custom_metadata.nf_02_id  =   nf2;
        meta.custom_metadata.nf_02_id  =   nf3;
        meta.custom_metadata.nf_02_id  =   nf4;
        meta.custom_metadata.nf_02_id  =   nf5;
        meta.custom_metadata.nf_02_id  =   nf6;
        meta.custom_metadata.nf_02_id  =   nf7;
        meta.custom_metadata.nf_02_id  =   nf8;                        
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

    table ipv4_lpm_2 {
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
	   		//Function_1
        }
        if (meta.custom_metadata.next_function == 2){
    	    //Function_2    	
        }
        if (meta.custom_metadata.next_function == 3){
    	    //Function_3  
        }
        if (meta.custom_metadata.next_function == 4){
    	    //Function_4  
        }
        if (meta.custom_metadata.next_function == 5){
    	    //Function_5 
        }
        if (meta.custom_metadata.next_function == 6){
    	    //Function_6 
        }
        if (meta.custom_metadata.next_function == 7){
            //Function_7
        }
        if (meta.custom_metadata.next_function == 8){
         	//Function_8
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
   apply {

	    if (meta.custom_metadata.next_function == 1){
	   		//Function_1
        }
        if (meta.custom_metadata.next_function == 2){
    	    //Function_2    	
        }
        if (meta.custom_metadata.next_function == 3){
    	    //Function_3  
        }
        if (meta.custom_metadata.next_function == 4){
    	    //Function_4  
        }
        if (meta.custom_metadata.next_function == 5){
    	    //Function_5 
        }
        if (meta.custom_metadata.next_function == 6){
    	    //Function_6 
        }
        if (meta.custom_metadata.next_function == 7){
            //Function_7
        }
        if (meta.custom_metadata.next_function == 8){
         	//Function_8
        }

	    //set next function
	    //-------- DO IT FOR N FUNCTIONS
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
                    		    else if(meta.custom_metadata.rounds == 5)
                    				meta.custom_metadata.next_function = meta.custom_metadata.nf_05_id;
                    		            else if(meta.custom_metadata.rounds == 6)
                    						meta.custom_metadata.next_function = meta.custom_metadata.nf_06_id;
          									    else if(meta.custom_metadata.rounds == 7)
                    								meta.custom_metadata.next_function = meta.custom_metadata.nf_07_id; 
                    						         	else if(meta.custom_metadata.rounds == 7)
                    										meta.custom_metadata.next_function = meta.custom_metadata.nf_07_id; 
 				
 				//save 
	        	meta.port_aux = standard_metadata.egress_spec;
    	        recirculate(meta);

	    }else{
	    	    //collecting timestamps for analysis purposes
                //stores packet processing times
                timestamps_bank.read(meta.aux_swap,0);
				timestamps_bank.write(0, meta.aux_swap + (( bit<64>)  standard_metadata.egress_global_timestamp - meta.aux_ingress_metadata));
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
