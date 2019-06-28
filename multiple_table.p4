-----------------------------------------------
control MyIngress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

   action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
       standard_metadata.egress_spec = port;
       hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
       hdr.ethernet.dstAddr = dstAddr;
       hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
   }

   action drop() {
       mark_to_drop(standard_metadata);
   }


/*----------------------------Match Tables------------------*/

   table s1 {
       key = {
           standard_metadata.ingress_port: exact;
           hdr.ipv4.dstAddr: lpm;
       }

       actions = {
           ipv4_forward;
           drop;
           NoAction;
       }

       size = 64; // One rule per port;

       default_action = drop();
   }

   table s2 {
       key = {
           hdr.ipv4.dstAddr: lpm;
       }

       actions = {
           ipv4_forward;
           drop;
           NoAction;
       }

       size = 64; // One rule per port;

       default_action = drop();
   }


   apply {
       if (hdr.ipv4.isValid()) {
           if (standard_metadata.ingress_port == 1) {
               s1.apply();
           } else {
               if (standard_metadata.ingress_port == 2) {
                   s2.apply();
               }

           }
       }
   }

}