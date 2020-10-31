meta:
  id: dns
  license: CC0-1.0
  endian: be
seq:
  - id: length
    type: u2
  - id: id
    type: u2
  - id: flags
    type: dns_flags
  - id: qdcount
    type: u2
    if: flags.opcode !=5
  - id: zocount
    type: u2
    if: flags.opcode ==5
  - id: ancount
    type: u2
    if: flags.opcode !=5
  - id: prcount
    type: u2
    if: flags.opcode == 5
  - id: nscount
    type: u2
    if: flags.opcode !=5
  - id: upcount
    type: u2
    if: flags.opcode == 5
  - id: arcount
    type: u2
  - id: queries
    type: query
    repeat: expr
    repeat-expr: qdcount
    if: flags.opcode !=5
  - id: zones
    type: query
    repeat: expr
    repeat-expr: zocount
    if: flags.opcode == 5
  - id: answers
    type: answer
    repeat: expr
    repeat-expr: ancount
    if: flags.opcode !=5
  - id: prerequisities
    type: answer
    repeat: expr
    repeat-expr: prcount
    if: flags.opcode ==5
  - id: authorities
    type: authority
    repeat: expr
    repeat-expr: nscount
    if: flags.opcode !=5
  - id: updates
    type: answer
    repeat: expr
    repeat-expr: upcount
    if: flags.opcode ==5
  - id: additionalities
    type: additional
    repeat: expr
    repeat-expr: arcount

types:
  dns_flags:
    seq:
      - id: flag
        type: u2
    instances:
      qr:
        value: (flag & 0b1000_0000_0000_0000) >> 15
      opcode:
        value: (flag & 0b0111_1000_0000_0000) >> 11
      aa:
        value: (flag & 0b0000_0100_0000_0000) >> 10
      tc:
        value: (flag & 0b0000_0010_0000_0000) >> 9
      rd:
        value: (flag & 0b0000_0001_0000_0000) >> 8
      ra:
        value: (flag & 0b0000_0000_1000_0000) >> 7
      z:
        value: (flag & 0b0000_0000_0100_0000) >> 6
      ad:
        value: (flag & 0b0000_0000_0010_0000) >> 5
      cd:
        value: (flag & 0b0000_0000_0001_0000) >> 4
      rcode:
        value: (flag & 0b0000_0000_0000_1111) >> 0

  query:
    seq: 
      - id: name
        type: domain_name
      - id: type
        type: u2
        enum: type_type
      - id: class
        type: u2
        enum: class_type
  answer:
   seq:
    - id: data
      type: section
              

  authority:
   seq:
    - id: data
      type: section
  additional:
    seq:
    - id: data
      type: section
              
  domain_name:
    seq:
      - id: name
        type: label
        repeat: until
        doc: "Consist of series labels. Repeat until the length is 0 or it is a pointer (bit-hack to get around lack of OR operator)"
        repeat-until: "_.length == 0 or (_.length & 0b1100_0000) == 0b1100_0000"
    instances:
      length:
        value:        (name.size >= 6 ?
                      name[0].overalllength 
                      + name[1].overalllength
                      + name[2].overalllength
                      + name[3].overalllength
                      + name[4].overalllength 
                      + name[5].overalllength: 
        
                      (name.size >= 5 ?
                      name[0].overalllength 
                      + name[1].overalllength
                      + name[2].overalllength
                      + name[3].overalllength
                      + name[4].overalllength: 
        
                      (name.size >= 4 ?
                      name[0].overalllength 
                      + name[1].overalllength
                      + name[2].overalllength
                      + name[3].overalllength: 
                      
                      (name.size >= 3 ?
                      name[0].overalllength 
                      + name[1].overalllength
                      + name[2].overalllength: 
                      
                      (name.size  >= 2 ? 
                      name[0].overalllength 
                      + name[1].overalllength 
                      : name[0].overalllength)))))
  label:
    seq:
      - id: length
        doc: "RFC1035 4.1.4: If the first two bits are raised it's a pointer-offset to a previously defined name"
        type: u1
      - id: pointer
        if: "is_pointer"
        type: pointer_struct
      - id: name
        if: "not is_pointer"
        doc: "Otherwise its a string the length of the length value"
        type: str
        encoding: "ASCII"
        size: length
    instances:
      is_pointer:
        value: (length & 0b1100_0000) == 0b1100_0000
      overalllength:
        value: (is_pointer ? 2 : length+1)
  pointer_struct:
    seq:
      - id: value
        doc: "Read one byte, then offset to that position, read one domain-name and return"
        type: u1
    instances:
      contents:
        io: _root._io
        pos: value
        type: domain_name
  character_string:
    seq:
      - id: length
        type: s1
      - id: data
        type: str
        encoding: "ASCII"
        size: length
    instances:
      overalllength:
        value: length+1
        
  character_strings:
    seq:
      - id: character_strings
        type: character_string
        repeat: eos
        
  section:
    seq:
      - id: name
        type: domain_name
      - id: type
        type: u2
        enum: type_type
      - id: class
        type: u2
        enum: class_type
        if: type != type_type::opt
      - id: udp_payload_size
        type: u2
        if: type == type_type::opt
      - id: ttl
        doc: "Time to live (in seconds)"
        type: s4
        if: type != type_type::opt
      - id: extended_rcode
        type: u1
        if: type == type_type::opt
      - id: version
        type: u1
        if: type == type_type::opt
      - id: do
        type: b1
        if: type == type_type::opt
      - id: z
        type: b15
        if: type == type_type::opt
      - id: rdlength
        doc: "Length in octets of the following payload"
        type: u2
        
      - id: rdata
        size: rdlength
        type:
          switch-on: type
          cases:
              type_type::cname: cname_type
              type_type::a: a_type(rdlength)
              type_type::aaaa: aaaa_type(rdlength)
              type_type::ptr: ptr_type
              type_type::txt: txt_type(rdlength)
              type_type::mx: mx_type
              type_type::ns: ns_type
              type_type::soa: soa_type
              type_type::srv: srv_type
              type_type::hinfo: hinfo_type
              type_type::loc: loc_type
              type_type::rp:  rp_type
              type_type::spf: spf_type(rdlength)
              type_type::naptr:  naptr_type
              type_type::tlsa: tlsa_type(rdlength)
              type_type::caa: caa_type(rdlength)
              type_type::ds: ds_type(rdlength)
              type_type::sshfp: sshfp_type(rdlength)
              type_type::tsig: tsig_type(rdlength)
              type_type::dnskey: dnskey_type(rdlength)
              type_type::mb: mb_type
              type_type::mg: mg_type
              type_type::mr: mr_type
              type_type::wks: wks_type(rdlength)
              type_type::minfo: minfo_type
              type_type::afsdb: afsdb_type
              type_type::x25: x25_type
              type_type::isdn: isdn_type(rdlength)
              type_type::rt: rt_type
              type_type::nsap: nsap_type(rdlength)
              type_type::key: key_type(rdlength)
              type_type::px: px_type
              type_type::kx: kx_type
              type_type::cert: cert_type(rdlength)
              type_type::dhcid: dhcid_type(rdlength)
              type_type::nid: nid_type
              type_type::l32: l32_type(rdlength)
              type_type::l64: l64_type(rdlength)
              type_type::lp: lp_type(rdlength)
              type_type::eui48: eui48_type(rdlength)
              type_type::eui64: eui64_type(rdlength)
              type_type::uri: uri_type(rdlength)
              type_type::ninfo: ninfo_type(rdlength)
              type_type::rkey: rkey_type(rdlength)
              type_type::talink: talink_type(rdlength)
              type_type::openpgpkey: openpgpkey_type(rdlength)
              type_type::sink: sink_type(rdlength)
              type_type::apl: apl_type(rdlength)
              type_type::sig: sig_type(rdlength)
              type_type::nsec: nsec_type(rdlength)
              type_type::nsec3param: nsec3param_type(rdlength)
              type_type::rrsig: rrsig_type(rdlength)
              type_type::nsec3: nsec3_type(rdlength)
              type_type::ipseckey: ipseckey_type(rdlength)
              type_type::csync: csync_type(rdlength)
              type_type::gpos: gpos_type
              type_type::hip: hip_type(rdlength)
              type_type::cds: cds_type(rdlength)
              type_type::cdnskey: cdnskey_type(rdlength)
              type_type::ta: ta_type(rdlength)
              type_type::dname: dname_type
              type_type::ta: ta_type(rdlength)
              type_type::tkey: tkey_type
              type_type::zonemd: zonemd_type(rdlength)
              type_type::avc: avc_type(rdlength)
              type_type::doa: doa_type(rdlength)
              type_type::amtrelay: amtrelay_type(rdlength)
              type_type::smimea: smimea_type(rdlength)
              type_type::eid: eid_type(rdlength)
              type_type::nimloc: nimloc_type(rdlength)
              type_type::atma: atma_type(rdlength)
              type_type::opt: opt_type(rdlength)
              type_type::nsap_ptr: nsap_ptr_type(rdlength)
              
  cname_type:
    seq:
      - id: cname
        type: domain_name

  a_type:
    params:
      - id: rdlength               
        type: u2
    seq:
      - id: address
        type: u1
        repeat: expr
        repeat-expr: rdlength

  aaaa_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: address
        type: u1
        repeat: expr
        repeat-expr: rdlength
        
  ptr_type: 
    seq:
      - id: ptrdname
        type: domain_name
        
        
  txt_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: txtdata
        type: character_strings
        size: rdlength
        
        
  mx_type:
    seq:
      - id: preference
        type: s2
      - id: exchange
        type: domain_name

  ns_type:
    seq:
      - id: nsdname
        type: domain_name
        
  soa_type:
    seq:
      - id: mname
        type: domain_name
      - id: rname
        type: domain_name
      - id: serial
        type: u4
      - id: refresh
        type: s4
      - id: retry
        type: s4
      - id: expire
        type: s4
      - id: minimum
        type: u4
        
  srv_type:
    seq:
      - id: priority
        type: u2
      - id: weight
        type: u2
      - id: port
        type: u2
      - id: target
        type: domain_name
        
  hinfo_type:
    seq:
    - id: cpu
      type: character_string
    - id: os
      type: character_string
  
  loc_type:
    seq:
    - id: version
      type: u1
    - id: size
      type: u1
      if: version == 0
    - id: horizpre
      type: u1
      if: version == 0
    - id: vertpre
      type: u1
      if: version == 0
    - id: latitude
      type: u4
      if: version == 0
    - id: longtitude
      type: u4
      if: version == 0
    - id: altitude
      type: u4
      if: version == 0
    - id: undefineddata
      type: str
      encoding: "ASCII"
      size: 15
      if: version != 0
  rp_type:
    seq:
      - id: mbox_dname
        type: domain_name
      - id: txt_dname
        type: domain_name
  spf_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: spfdata
        type: character_strings
        size: rdlength
  naptr_type:
    seq:
      - id: order
        type: u2
      - id: preference
        type: u2
      - id: flags
        type: character_string
      - id: services
        type: character_string
      - id: regexp
        type: character_string
      - id: replacement
        type: domain_name
  tlsa_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: certificate_usage
        type: u1
      - id: selector
        type: u1
      - id: matching_type
        type: u1
      - id: certificate_association_data
        type: str
        encoding: "ASCII"
        size: rdlength-3
  caa_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: flags
        type: s1
      - id: tag_length
        type: u1
      - id: tag
        type: str
        encoding: "ASCII"
        size: tag_length
      - id: value
        type: str
        encoding: "ASCII"
        size: rdlength-tag_length-2
  ds_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: key_tag
        type: u2
      - id: algorithm
        type: u1
      - id: digest_type
        type: u1
      - id: digest
        size: rdlength-4
  sshfp_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: algorithm
        type: u1
      - id: fp_type
        type: u1
      - id: fingerprint
        size: rdlength-2
  tsig_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: algorithm_name
        type: domain_name
      - id: time_signed
        doc: "u_int48_t not supported by Kaitai"
        size: 6
      - id: fudge
        type: u2
      - id: mac_size
        type: u2
      - id: mac_stream
        size: mac_size
      - id: original_id
        type: u2
      - id: error
        type: u2
      - id: other_len
        type: u2
      - id: other
        size: other_len
  dnskey_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: flags
        type: u2
      - id: protocol
        type: u1
      - id: algorithm
        type: u1
      - id: public_key
        size: rdlength-4
  mb_type: 
    seq:
      - id: madname
        type: domain_name

  mg_type: 
    seq:
      - id: mgname
        type: domain_name
  mr_type: 
    seq:
      - id: newname
        type: domain_name
  wks_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: address
        type: u1
        repeat: expr
        repeat-expr: 4
      - id: protocol
        type: u1
      - id: bit_map
        size: rdlength-5
  minfo_type:
    seq:
      - id: rmailbx
        type: domain_name
      - id: emailbx
        type: domain_name
  afsdb_type:
    seq:
      - id: subtype
        type: u2
      - id: hostname
        type: domain_name
  x25_type:
    seq:
      - id: psdn_adress
        type: character_string
  isdn_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: isdn_address
        type: character_string
      - id: sa
        type: character_string
        if: rdlength - isdn_address.length > 1
        doc: "1 byte obsahuje nulovou delku dalsiho characterstringu"
  rt_type:
    seq:
      - id: preference
        type: u2
      - id: intermediate_host
        type: domain_name
  nsap_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: nsap_address
        type: character_string
        
  key_flags:
    seq:
      - id: flag
        type: u2
    instances:
      ac:
        value: (flag & 0b1100_0000_0000_0000) >> 14
      z1:
        value: (flag & 0b0010_0000_0000_0000) >> 13
      xt:
        value: (flag & 0b0001_0000_0000_0000) >> 12
      z2:
        value: (flag & 0b0000_1000_0000_0000) >> 11
      z3:
        value: (flag & 0b0000_0100_0000_0000) >> 10
      namtyp:
        value: (flag & 0b0000_0011_0000_0000) >> 8
      z4:
        value: (flag & 0b0000_0000_1000_0000) >> 7
      z5:
        value: (flag & 0b0000_0000_0100_0000) >> 6
      z6:
        value: (flag & 0b0000_0000_0010_0000) >> 5
      z7:
        value: (flag & 0b0000_0000_0001_0000) >> 4
      sig:
        value: (flag & 0b0000_0000_0000_1111) >> 0
        
  
  key_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: flags
        type: key_flags
      - id: protocol
        type: u1
        enum: key_protocol
      - id: algorithm
        type: u1
        enum: key_algorithm
      - id: public_key
        size: rdlength-4
  
  px_type:
    seq:
      - id: preference
        type: s2
      - id: map822
        type: domain_name
      - id: mapx400
        type: domain_name
  kx_type:
    seq:
      - id: preference
        type: u2
      - id: exchanger
        type: domain_name

  cert_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: type
        type: u2
        enum: cert_type_enum
      - id: key_tag
        type: u2
      - id: algorithm
        type: u1
        enum: dnssec_algorithm_enum
      - id: certificate_or_crl
        size: rdlength-5
  dhcid_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: dhcid_data
        size: rdlength
  nid_type:
    seq:
      - id: preference
        type: u2
      - id: nodeid
        type: u8
  l32_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: preference
        type: u2
      - id: locator32
        type: u1
        repeat: expr
        repeat-expr: rdlength

  l64_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: preference
        type: u2
      - id: locator64
        type: u1
        repeat: expr
        repeat-expr: rdlength

  lp_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: preference
        type: u2
      - id: fqdn
        type: domain_name 
  
  
  eui48_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: eui48_address
        size: rdlength 
        
  eui64_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: eui64_address
        size: rdlength 
  
  uri_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: priority
        type: u2 
      - id: weight
        type: u2
      - id: target
        size: rdlength -4
  
          
  ninfo_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: ninfodata
        type: character_strings
        size: rdlength
  
  
            
  rkey_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: flags
        contents: [0,0]
      - id: protocol
        contents: [1]
      - id: algorithm
        type: u1
        enum: key_algorithm
      - id: public_key
        size: rdlength-4
        
  talink_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: domain_name1
        type: domain_name
      - id: domain_name2
        type: domain_name
        
  openpgpkey_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: openpgp_key
        size: rdlength
    
  sink_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: coding
        type: u1
        enum: sink_coding_enum
      - id: subcoding_asn
        type: u1
        enum: sink_subcoding_asn_enum
        if: coding == sink_coding_enum::osi_asn1_1990 or 
            coding == sink_coding_enum::osi_asn1_1994
      - id: subcoding_mime
        type: u1
        enum: sink_subcoding_mime_enum
        if: coding == sink_coding_enum::mime_structured_data
      - id: subcoding_text
        type: u1
        enum: sink_subcoding_text_enum
        if: coding == sink_coding_enum::text_tagged_data
      - id: subcoding
        type: u1
        if: coding != sink_coding_enum::text_tagged_data and 
            coding != sink_coding_enum::mime_structured_data and
            coding != sink_coding_enum::osi_asn1_1990 and
            coding != sink_coding_enum::osi_asn1_1994
      - id: data
        size: rdlength-2
  apl_items:
    seq:
      - id: entries
        type: apl_item
        repeat: eos
  apl_item:
    seq:
      - id: addressfamily
        type: u2
      - id: prefix
        type: u1
      - id: n
        type: b1
      - id: afdlenght
        type: b7
      - id: afdpart
        type: u1
        repeat: expr
        repeat-expr: afdlenght
  
  apl_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: items
        type: apl_items
        size: rdlength
        
  sig_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: type_covered
        type: u2
        enum: type_type
      - id: algorithm
        type: u1
        enum: key_algorithm
      - id: labels
        type: u1
      - id: original_ttl
        type: u4
      - id: signature_expiration
        type: u4
      - id: signature_inception
        type: u4
      - id: key_tag
        type: u2
      - id: signers_name
        type: domain_name
      - id: siganture_field
        size: rdlength-18-signers_name.length
    
      

      
  bitmaps:
    seq:
      - id: bitmap
        type: bitmap
        repeat: eos
  
  
  bitmap:
    seq:
      - id: window_number
        type: u1
      - id: bitmap_length
        type: u1
      - id: bitmap_items
        type: bitmap_item(_index,window_number)
        repeat: expr
        repeat-expr: bitmap_length
  
        
  bitmap_item:
    params:
      - id: index    
        type: u4
      - id: window_number
        type: u2
    seq:
      - id: item
        type: 
          switch-on: index+window_number*32
          cases:
            0: bitmap_item_0
            1: bitmap_item_1
            2: bitmap_item_2
            3: bitmap_item_3
            4: bitmap_item_4
            5: bitmap_item_5
            6: bitmap_item_6
            7: bitmap_item_7
            11: bitmap_item_11
            12: bitmap_item_12
            31: bitmap_item_31
            32: bitmap_item_32
            4096: bitmap_item_4096
            
  bitmap_item_0:
    seq:
      - id: dato
        type: u1
    instances: 
      a:
        value: (dato & 0b0100_0000) >> 6
      ns:
        value: (dato & 0b0010_0000) >> 5
      md:
        value: (dato & 0b0001_0000) >> 4
      mf:
        value: (dato & 0b0000_1000) >> 3
      cname:
        value: (dato & 0b0000_0100) >> 2
      soa:
        value: (dato & 0b0000_0010) >> 1
      mb:
        value: (dato & 0b0000_0001) >> 0
  
  bitmap_item_1:
    seq:
      - id: dato
        type: u1
    instances: 
      mg:
        value: (dato & 0b1000_0000) >> 7
      mr:
        value: (dato & 0b0100_0000) >> 6
      null:
        value: (dato & 0b0010_0000) >> 5
      wks:
        value: (dato & 0b0001_0000) >> 4
      ptr:
        value: (dato & 0b0000_1000) >> 3
      hinfo:
        value: (dato & 0b0000_0100) >> 2
      minfo:
        value: (dato & 0b0000_0010) >> 1
      mx:
        value: (dato & 0b0000_0001) >> 0
        
  bitmap_item_2:
    seq:
      - id: dato
        type: u1
    instances: 
      txt:
        value: (dato & 0b1000_0000) >> 7
      rp:
        value: (dato & 0b0100_0000) >> 6
      afsdb:
        value: (dato & 0b0010_0000) >> 5
      x25:
        value: (dato & 0b0001_0000) >> 4
      isdn:
        value: (dato & 0b0000_1000) >> 3
      rt:
        value: (dato & 0b0000_0100) >> 2
      nsap:
        value: (dato & 0b0000_0010) >> 1
      nsap_ptr:
        value: (dato & 0b0000_0001) >> 0
        

  bitmap_item_3:
    seq:
      - id: dato
        type: u1
    instances: 
      sig:
        value: (dato & 0b1000_0000) >> 7
      key:
        value: (dato & 0b0100_0000) >> 6
      px:
        value: (dato & 0b0010_0000) >> 5
      gpos:
        value: (dato & 0b0001_0000) >> 4
      aaaa:
        value: (dato & 0b0000_1000) >> 3
      loc:
        value: (dato & 0b0000_0100) >> 2
      nxt:
        value: (dato & 0b0000_0010) >> 1
      eid:
        value: (dato & 0b0000_0001) >> 0

  bitmap_item_4:
    seq:
    - id: dato
      type: u1
    instances: 
      nimloc:
        value: (dato & 0b1000_0000) >> 7
      srv:
        value: (dato & 0b0100_0000) >> 6
      atma:
        value: (dato & 0b0010_0000) >> 5
      naptr:
        value: (dato & 0b0001_0000) >> 4
      kx:
        value: (dato & 0b0000_1000) >> 3
      cert:
        value: (dato & 0b0000_0100) >> 2
      a6:
        value: (dato & 0b0000_0010) >> 1
      dname:
        value: (dato & 0b0000_0001) >> 0
       

  bitmap_item_5:
    seq:
    - id: dato
      type: u1
    instances: 
      sink:
        value: (dato & 0b1000_0000) >> 7
      opt:
        value: (dato & 0b0100_0000) >> 6
      apl:
        value: (dato & 0b0010_0000) >> 5
      ds:
        value: (dato & 0b0001_0000) >> 4
      sshfp:
        value: (dato & 0b0000_1000) >> 3
      ipseckey:
        value: (dato & 0b0000_0100) >> 2
      rrsig:
        value: (dato & 0b0000_0010) >> 1
      nsec:
        value: (dato & 0b0000_0001) >> 0
  
  bitmap_item_6:
    seq:
    - id: dato
      type: u1
    instances: 
      dnskey:
        value: (dato & 0b1000_0000) >> 7
      dhcid:
        value: (dato & 0b0100_0000) >> 6
      nsec3:
        value: (dato & 0b0010_0000) >> 5
      nsec3param:
        value: (dato & 0b0001_0000) >> 4
      tlsa:
        value: (dato & 0b0000_1000) >> 3
      smimea:
        value: (dato & 0b0000_0100) >> 2
      #unassigned:
        #value: (dato & 0b0000_0010) >> 1
        # 54 is not assigned
      hip:
        value: (dato & 0b0000_0001) >> 0
        

  bitmap_item_7:
    seq:
    - id: dato
      type: u1

    instances: 
      ninfo:
        value: (dato & 0b1000_0000) >> 7
      rkey:
        value: (dato & 0b0100_0000) >> 6
      talink:
        value: (dato & 0b0010_0000) >> 5
      cds:
        value: (dato & 0b0001_0000) >> 4
      cdnskey:
        value: (dato & 0b0000_1000) >> 3
      openpgpkey:
        value: (dato & 0b0000_0100) >> 2
      csync:
        value: (dato & 0b0000_0010) >> 1
      zonemd:
        value: (dato & 0b0000_0001) >> 0
        
  # 64- 97 unassigned
        
  bitmap_item_11:
    seq:
    - id: dato
      type: u1
    instances: 
      #unassigned:
        #value: (dato & 0b1000_0000) >> 7
        # 98 unassigned
      spf:
        value: (dato & 0b0100_0000) >> 6
      uinfo:
        value: (dato & 0b0010_0000) >> 5
      uid:
        value: (dato & 0b0001_0000) >> 4
      gid:
        value: (dato & 0b0000_1000) >> 3
      unspec:
        value: (dato & 0b0000_0100) >> 2
      nid:
        value: (dato & 0b0000_0010) >> 1
      l32:
        value: (dato & 0b0000_0001) >> 0   
        
  bitmap_item_12:
    seq:
    - id: dato
      type: u1
    instances: 
      l64:
        value: (dato & 0b1000_0000) >> 7
      lp:
        value: (dato & 0b0100_0000) >> 6
      eui48:
        value: (dato & 0b0010_0000) >> 5
      eui64:
        value: (dato & 0b0001_0000) >> 4
     # 110 - 113 unassigned


  # 114 - 247 unassigned 
  
  bitmap_item_31:
    seq:
    - id: dato
      type: u1
      
    instances: 
      #unassigned:
       # value: (dato & 0b1000_0000) >> 7
       # 248 unassigned
      tkey:
        value: (dato & 0b0100_0000) >> 6
      tsig:
        value: (dato & 0b0010_0000) >> 5
      ixfr:
        value: (dato & 0b0001_0000) >> 4
      axfr:
        value: (dato & 0b0000_1000) >> 3
      mailb:
        value: (dato & 0b0000_0100) >> 2
      maila:
        value: (dato & 0b0000_0010) >> 1
      aany:
        value: (dato & 0b0000_0001) >> 0
        # 248 - 255 unassigned 
        
  bitmap_item_32:
    seq:
    - id: dato
      type: u1
    instances: 
      uri:
        value: (dato & 0b1000_0000) >> 7
      caa:
        value: (dato & 0b0100_0000) >> 6
      avc:
        value: (dato & 0b0010_0000) >> 5
      doa:
        value: (dato & 0b0001_0000) >> 4
      amtrelay:
        value: (dato & 0b0000_1000) >> 3
      #unassigned:
        #value: (dato & 0b0000_0100) >> 2
      #unassigned:
        #value: (dato & 0b0000_0010) >> 1
      #unassigned:
        #value: (dato & 0b0000_0001) >> 0
    # 261 - 263 unassigned 
    
  bitmap_item_4096:
    seq:
    - id: dato
      type: u1
    instances: 
      ta:
        value: (dato & 0b1000_0000) >> 7
      # 32769 - 32775 unassigned     


        
  nsec_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: next_domain_name
        type: domain_name
      - id: bitmaps
        type: bitmaps
        size: rdlength-next_domain_name.length
        
  nsec3param_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: hash_algorithm
        type: u1
      - id: flags
        contents: [0]
      - id: iterations
        type: u2
      - id: salt_length
        type: u1
      - id: salt
        size: salt_length

  rrsig_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: type_covered
        type: u2
        enum: type_type
      - id: algorithm
        type: u1
        enum: key_algorithm
      - id: labels
        type: u1
      - id: original_ttl
        type: u4
      - id: signature_expiration
        type: u4
      - id: signature_inception
        type: u4
      - id: key_tag
        type: u2
      - id: signers_name
        type: domain_name
      - id: siganture
        size: rdlength-18-signers_name.length
        
  nsec3_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: hash_algorithm
        type: u1
      - id: flags
        contents: [0]
      - id: iterations
        type: u2
      - id: salt_length
        type: u1
      - id: salt
        size: salt_length
      - id: hash_length
        type: u1
      - id: next_hashed_owner_name
        size: hash_length
      - id: bitmap
        type: bitmaps
        size: rdlength-6-hash_length-salt_length
  
  ipseckey_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: precedence
        type: s1
      - id: gateway_type
        type: u1
        enum: ipseckey_gateway_type_enum
      - id: algorithm
        type: u1
        enum: ipseckey_algorithm_enum
      - id: gateway_domain_name
        type: domain_name
        if: gateway_type == ipseckey_gateway_type_enum::domain_name
      - id: gateway_ipv4
        type: u1
        repeat: expr
        repeat-expr: 4
        if: gateway_type == ipseckey_gateway_type_enum::ipv4
      - id: gateway_ipv6
        type: u1
        repeat: expr
        repeat-expr: 16
        if: gateway_type == ipseckey_gateway_type_enum::ipv6
      - id: public_key
        size: rdlength - 3 -
          ( gateway_type == ipseckey_gateway_type_enum::domain_name ?
              gateway_domain_name.length : (
                gateway_type == ipseckey_gateway_type_enum::ipv4 ? 4 : 
                  gateway_type == ipseckey_gateway_type_enum::ipv6 ? 16 : 0))
        if: algorithm != ipseckey_algorithm_enum::no_key

  
  csync_flags:
    seq:
      - id: flags
        type: s2
    instances:
      immediate:
        value: (flags & 0b0000_0000_0000_0001) >> 0
      soaminimum:
        value: (flags & 0b0010_0000_0000_0010) >> 1

  csync_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: soa_serial
        type: s4
      - id: flags
        type: csync_flags
      - id: bitmap
        type: bitmaps
        size: rdlength-6

  gpos_type:
    seq:
      - id: longtitude
        type: character_string
      - id: latitude
        type: character_string
      - id: altitude
        type: character_string
  domain_names:
      seq:
      - id: domain_names
        type: domain_name
        repeat: eos
        
  hip_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: hit_length
        type: u1
      - id: pk_algorithm
        type: u1
        enum: ipseckey_algorithm_enum
      - id: pk_length
        type: u2
      - id: hit
        size: hit_length
      - id: public_key
        size: pk_length
      - id: rendezvous_servers
        type: domain_names
        size: rdlength - 4-hit_length-pk_length
  
  cds_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: key_tag
        type: u2
      - id: algorithm
        type: u1
      - id: digest_type
        type: u1
      - id: digest
        size: rdlength-4 
        
  cdnskey_type:
    params:
      - id: rdlength
        type: u2
    seq:
      - id: flags
        type: u2
      - id: protocol
        type: u1
      - id: algorithm
        type: u1
      - id: public_key
        size: rdlength-4
  
  ta_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: key_tag
        type: u2
      - id: algorithm
        type: u1
      - id: digest_type
        type: u1
      - id: digest
        size: rdlength-4 
        
  dname_type:
    seq:
      - id: target
        type: domain_name
        
  tkey_type:
    seq:
      - id: algorithm
        type: domain_name
      - id: inception
        type: u4
      - id: expiration
        type: u4
      - id: mode
        type: u2
        enum: tkey_mode_enum
      - id: error
        type: u2
        enum: tkey_error_enum
      - id: key_size
        type: u2
      - id: key_data
        size: key_size
      - id: other_size
        type: u2
      - id: other_data
        size: other_size
    
  zonemd_type: 
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: serial
        type: u4
      - id: digest_type
        type: u1
      - id: reserved
        type: u1
      - id: digest
        size: rdlength-6 
  
  avc_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: avcdata
        type: character_strings
        size: rdlength
  
  doa_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: doa_enterprise
        type: u4
      - id: doa_type
        type: u4
      - id: doa_location
        type: u1
      - id: doa_media_type
        type: character_string
      - id: doa_data
        size: rdlength - 9 - doa_media_type.overalllength

  amtrelay_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: precedence
        type: s1
      - id: d
        type: b1
      - id: type
        type: b7
        enum: ipseckey_gateway_type_enum
      - id: relay_domain_name
        type: domain_name
        if: type == ipseckey_gateway_type_enum::domain_name
      - id: relay_ipv4
        type: u1
        repeat: expr
        repeat-expr: 4
        if: type == ipseckey_gateway_type_enum::ipv4
      - id: relay_ipv6
        type: u1
        repeat: expr
        repeat-expr: 16
        if: type == ipseckey_gateway_type_enum::ipv6

  smimea_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: certificate_usage
        type: u1
      - id: selector
        type: u1
      - id: matching_type
        type: u1
      - id: certificate_association_data
        type: str
        encoding: "ASCII"
        size: rdlength-3
  
  eid_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: endpoint_identifier
        size: rdlength
  
  nimloc_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: nimrod_locator
        size: rdlength

  atma_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: format
        type: u1
      - id: address
        size: rdlength-1
        
  opt_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: option_code
        type: u2
        enum: opt_option_code_enum
      - id: option_length
        type: u2 
      - id: option_data
        size: rdlength -4
  
  nsap_ptr_type:
    params:
      - id: rdlength                
        type: u2
    seq:
      - id: nsap_address
        type: character_strings
        size: rdlength
enums:
  class_type:
    1: in
    3: ch
    4: hs
    254: none
    255: any
  type_type:
    1: a
    2: ns
    5: cname
    6: soa
    7: mb
    8: mg
    9: mr
    10: null_record
    11: wks
    12: ptr
    13: hinfo
    14: minfo
    15: mx
    16: txt
    17: rp
    18: afsdb
    19: x25
    20: isdn
    21: rt
    22: nsap
    23: nsap_ptr
    24: sig
    25: key
    26: px
    27: gpos
    28: aaaa
    29: loc
    31: eid
    32: nimloc
    33: srv
    34: atma
    35: naptr
    36: kx
    37: cert
    39: dname
    40: sink
    41: opt
    42: apl
    43: ds
    44: sshfp
    45: ipseckey
    46: rrsig
    47: nsec
    48: dnskey
    49: dhcid
    50: nsec3 
    51: nsec3param
    52: tlsa
    53: smimea
    55: hip
    56: ninfo
    57: rkey
    58: talink
    59: cds
    60: cdnskey
    61: openpgpkey
    62: csync
    63: zonemd
    99: spf
    100: uinfo
    101: uid
    102: gid
    103: unspec
    104: nid
    105: l32
    106: l64
    107: lp
    108: eui48
    109: eui64
    249: tkey
    250: tsig
    251: ixfr 
    252: axfr
    253: mailb
    255: any
    256: uri
    257: caa
    258: avc
    259: doa
    260: amtrelay
    32768: ta
    65281: wins
    65282: wins_r
    65422: xpf
  
  key_protocol:
    1: tls
    2: email
    3: dnssec
    4: ipsec
    
  key_algorithm:
     0: reserved
     1: rsa_md5
     2: diffie_hellman
     3: dsa
     4: eliptic_curves
     5: rsa_sha1
     10: rsa_sha512
    
  cert_type_enum:
    #0            Reserved
    1: pkix      #X.509 as per PKIX
    2: spki      #SPKI certificate
    3: pgp       #OpenPGP packet
    4: ipkix     #The URL of an X.509 data object
    5: ispki     #The URL of an SPKI certificate
    6: ipgp      #The fingerprint and URL of an OpenPGP packet
    7: acpkix    #Attribute Certificate
    8: iacpkix   #The URL of an Attribute Certificate
    #9-252            Available for IANA assignment
    253: uri     #URI private
    254:  oid    #OID private
    #255            Reserved
    #256-65279            Available for IANA assignment
    #65280-65534            Experimental
    #65535            Reserved
  dnssec_algorithm_enum:
    #0   reserved
    1:   rsa_md5        
    2:   diffie_hellman 
    3:   dsa_sha1 
    4:   elliptic_curve
    5:   rsa_sha1
   #252   Indirect [INDIRECT]      n                  -
   #253   Private [PRIVATEDNS]     y      see below  OPTIONAL
   #254   Private [PRIVATEOID]     y      see below  OPTIONAL
   #255   reserved
  sink_coding_enum:
   #0: reserved
   1: the_snmp_subset_of_asn1
   2: osi_asn1_1990
   3: osi_asn1_1994
   #4-62 - Reserved for IANA assignment for future versions of OSI ASN.*.
   63: private 
   64: dns_rrs
   65: mime_structured_data
   66: text_tagged_data
   #67-253 - Available for general assignment to codings by IANA.
   #254 - Private formats indicated by a URL. 
   #255: reserved
  sink_subcoding_asn_enum:
    #0: reserved
    1: ber
    2: der
    3: per
    4: per_unaligned
    5: cer
    #6-253 - available for IANA assignment to future OSI encoding
    254: private
    #255: reserved
  sink_subcoding_mime_enum:
   #0: reserved.
    1: bit7
    2: bit8
    3: binary
    4: quoted_printable
    5: base64
    #6 - 253 - available for assignment to future content transfer encodings.
    #254 - private
    #255 - reserved.
  
  sink_subcoding_text_enum:
    #0 - reserved.
    1: ascii
    2: utf7
    3: utf8
    4: ascii_witth_mime_header_escapes
    #5 - 253 - available for assignment to future text encodings.
    #254 - private. 
  
  ipseckey_gateway_type_enum:
    0: empty
    1: ipv4
    2: ipv6
    3: domain_name
  
  ipseckey_algorithm_enum:
    0: no_key
    1: dsa
    2: rsa
    
  tkey_mode_enum:
 #   0        - reserved
    1: server_assignment
    2: diffie_hellman_exchange
    3: gss_api_negotiation
    4: resolver_assignment
    5: key_deletion
   #6-65534   - available
   #65535     - reserved
   
  tkey_error_enum:
    0: no_error
    #1-15   a non-extended RCODE
    16: badsig
    17: badkey
    18: badtime
    19: badmode
    20: badname
    21: badalg
  
  opt_option_code_enum:
    1: 	llq
    2: 	ul
    3: 	nsid
    5: 	dau
    6: 	dhu
    7: 	n3u
    8: 	edns_client_subnet 
    9: 	edns_expire
    10: cookie
    11: edns_tcp_keepalive
    12: padding
    13: chain
    14:	edns_key_tag
    16: edns_client_tag 
    17: edns_server_tag
    26946: 	device_id