/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


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

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

struct ingress_metadata_t {
    bit<16> ifindex;
    bit<2>  port_type;
    bit<16>  count;
}

struct fwd_metadata_t {
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    fwd_metadata_t fwd_metadata;
}

struct headers {
    ethernet_t         ethernet;
    ipv4_t             ipv4;
    ipv4_option_t      ipv4_option;
}

error { IPHeaderTooShort }

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

// ingress_port - the port on which the packet arrived 

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /*-----------------Action Definitions-----------------------------*/
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }


/*************************************************************************
************** T O D O ***************************************************
************** CHECK THE INGRESS PORT TO MAP THE INCOMING PACKET *********
*************************************************************************/

/*----------------------------Match Tables------------------*/
    
    table p1_ingress_port_mapping {
        key = {
            /*standard_metadata.ingress_port: exact;*/
            hdr.ethernet.dstAddr: lpm;
        }

        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        //PORTMAP_TABLE_SIZE (may need to change the size)
        size = 64; // One rule per port;

        default_action = drop();
    }

    table p2_ingress_port_mapping {
        key = {
            hdr.ethernet.dstAddr: lpm;
        }

        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        //PORTMAP_TABLE_SIZE (may need to change the size)
        size = 64; // One rule per port;
        
        default_action = drop();  
    }

    table p3_ingress_port_mapping {
        key = {
            hdr.ethernet.dstAddr: lpm;
        }

        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        //PORTMAP_TABLE_SIZE (may need to change the size)
        size = 64; // One rule per port;
        
        default_action = drop();  
    }


/*************************************************************************
******** Ingress Control Flow ********************************************
**************** Ingress Port match, apply table*************************
************************************************************************/

    apply {
        if (hdr.ipv4.isValid()) {
            if (standard_metadata.ingress_port == 1) {
                p1_ingress_port_mapping.apply();
                } else {
                    if (standard_metadata.ingress_port == 2) {
                        p1_ingress_port_mapping.apply();
                    } 
                } else {
                    if (standard_metadata.ingress_port == 3) {
                        p1_ingress_port_mapping.apply();
                    } 
                } else {
                    if (standard_metadata.ingress_port == 4) {
                        p2_ingress_port_mapping.apply();
                    } 
                } else {
                    if (standard_metadata.ingress_port == 5) {
                        p2_ingress_port_mapping.apply();
                    } 
                } else {
                    if (standard_metadata.ingress_port == 6) {
                        p3_ingress_port_mapping.apply();
                    } 
                } else {
                    if (standard_metadata.ingress_port == 7) {
                        p3_ingress_port_mapping.apply();
                    } 
                } else {
                    if (standard_metadata.ingress_port == 8) {
                        p3_ingress_port_mapping.apply();
                    } 
                } 
            }
        } 
    }

}

// egress_spec - the port to which the packet should be sent to
// egress_port - the port on which the packet is departing from (read only in egress pipeline)

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {}
    
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
        packet.emit(hdr.ipv4_option);                
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
