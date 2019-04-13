(* (c) 2017 Hannes Mehnert, all rights reserved *)
open Udns
open Astring

open Packet

let of_hex s =
  let hexchar = function
    | 'a' .. 'f' as x -> int_of_char x - 0x57
    | '0' .. '9' as x -> int_of_char x - 0x30
    | _ -> invalid_arg "unknown char"
  in
  let cs = Cstruct.create (succ (String.length s) / 2) in
  let idx, part =
    String.fold_left (fun (i, part) c ->
        if Char.Ascii.is_white c then
          (i, part)
        else match part with
          | None -> (i, Some (hexchar c lsl 4))
          | Some data -> Cstruct.set_uint8 cs i (data lor hexchar c) ; (succ i, None))
      (0, None) s
  in
  (match part with None -> () | Some _ -> invalid_arg "missing a hex char") ;
  Cstruct.sub cs 0 idx

let n_of_s = Domain_name.of_string_exn

let p_cs = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

let p_err =
  let module M = struct
    type t = err
    let pp = pp_err
    let equal a b = match a, b with
      | `Not_implemented _, `Not_implemented _
      | `Leftover _, `Leftover _
      | `Malformed _, `Malformed _
      | `Partial, `Partial
      | `Bad_edns_version _, `Bad_edns_version _ -> true
      | _ -> false
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

module Packet = struct
  let t_ok =
    let module M = Packet in
    (module Packet: Alcotest.TESTABLE with type t = M.t)

  let bad_query () =
    let cs = of_hex "0000 0000 0001 0000 0000 0000 0000 0100 02" in
    Alcotest.(check (result t_ok p_err) "query with bad class"
                (Error (`Not_implemented (0, "BadClass 2")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 0100 03" in
    Alcotest.(check (result t_ok p_err) "query with unsupported class"
                (Error (`Not_implemented (0, "UnsupportedClass 0")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 0000 01" in
    Alcotest.(check (result t_ok p_err) "question with unsupported typ"
                (Error (`Not_implemented (0, "typ 0")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 2100 01" in
    Alcotest.(check (result t_ok p_err) "question with bad SRV"
                (Error (`Malformed (0, "BadContent")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0102 0000 0200 01" in
    Alcotest.(check (result t_ok p_err) "question with bad hostname"
                (Error (`Malformed (0, "BadContent")))
                (decode cs))

  let regression0 () =
    let data = of_hex
        {___|d4 e4 85 83 00 01 00 00 00 01 00 00 01 36 02 31
             36 03 31 35 30 03 31 33 38 07 69 6e 2d 61 64 64
             72 04 61 72 70 61 00 00 0c 00 01 03 31 35 30 03
             31 33 38 07 49 4e 2d 41 44 44 52 04 41 52 50 41
             00 00 06 00 01 00 00 2a 30 00 3f 05 43 4f 4e 31
             52 04 4e 49 50 52 03 4d 49 4c 00 13 44 41 4e 49
             45 4c 2e 57 2e 4b 4e 4f 50 50 53 2e 43 49 56 04
             4d 41 49 4c c0 56 78 39 c3 d1 00 00 2a 30 00 00
             03 84 00 12 75 00 00 00 2a 30|___}
    in
    let flags = Header.FS.(add `Authoritative (add `Recursion_desired (singleton `Recursion_available)))
    and content =
      let soa = {
      Soa.nameserver = n_of_s "CON1R.NIPR.MIL" ;
      hostmaster =
        Domain_name.of_strings_exn ~hostname:false
          ["DANIEL.W.KNOPPS.CIV" ; "MAIL" ; "MIL" ] ;
      serial = 0x7839c3d1l ; refresh = 0x2a30l ; retry = 0x384l ;
      expiry = 0x127500l ; minimum = 0x2a30l
    } in
      Domain_name.Map.empty,
      Domain_name.Map.singleton (n_of_s "150.138.in-addr.arpa")
        Rr_map.(singleton Soa soa)
    in
    let res =
      Packet.create (0xD4E4, flags)
        (n_of_s "6.16.150.138.in-addr.arpa", Rr.PTR)
        (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some content))
    in
    Alcotest.(check (result t_ok p_err) "regression 0 decodes"
                (Ok res) (decode data))

  let regression1 () =
    let data = of_hex {___|83 d9 01 00 00 01 00 00 00 00 00 00 04 6b 65 79
                           73 06 72 69 73 65 75 70 03 6e 65 74 00 00 1c 00
                           01|___}
    in
    let flags = Header.FS.singleton `Recursion_desired in
    let res =
      Packet.create (0x83D9, flags) (n_of_s "keys.riseup.net", Rr.AAAA) `Query
    in
    Alcotest.(check (result t_ok p_err) "regression 1 decodes"
                (Ok res) (decode data))

  let regression2 () =
    let data = of_hex {___|ae 00 84 03 00 01 00 00 00 01 00 00 04 6e 65 77
                           73 03 62 62 63 03 6e 65 74 02 75 6b 00 00 02 00
                           01 03 62 62 63 03 6e 65 74 02 75 6b 00 00 06 00
                           01 00 00 0e 10 00 34 03 32 31 32 02 35 38 03 32
                           33 30 03 32 30 30 00 04 62 6f 66 68 03 62 62 63
                           02 63 6f 02 75 6b 00 59 5c bd ce 00 01 51 80 00
                           01 51 80 00 01 51 80 00 00 01 2c|___}
    in
    let flags = Header.FS.singleton `Authoritative
    and content =
      let soa = {
        Soa.nameserver = n_of_s ~hostname:false "212.58.230.200" ;
        hostmaster = n_of_s "bofh.bbc.co.uk" ;
        serial = 0x595cbdcel ; refresh = 0x00015180l ; retry = 0x00015180l ;
        expiry = 0x00015180l ; minimum = 0x0000012cl
      } in
      (Domain_name.Map.empty,
       Domain_name.Map.singleton (n_of_s "bbc.net.uk") Rr_map.(singleton Soa soa))
    in
    let res = Packet.create (0xAE00, flags) (n_of_s "news.bbc.net.uk", Rr.NS)
        (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some content))
    in
    Alcotest.(check (result t_ok p_err) "regression 2 decodes"
                (Ok res) (decode data))

  let regression3 () =
    let data = of_hex {___|e213 8180 0001
        0001 0000 0001 0366 6f6f 0363 6f6d 0000
        0f00 01c0 0c00 0f00 0100 0002 2c00 0b03
        e801 3001 3001 3001 3000 0000 2901 c2 00
        0000 0000 00|___}
    in
    let flags = Header.FS.(add `Recursion_desired (singleton `Recursion_available))
    and question =
      (Domain_name.of_string_exn ~hostname:false "foo.com", Rr.MX)
    and answer =
      let mx = {
        Mx.preference = 1000 ;
        mail_exchange = Domain_name.of_string_exn ~hostname:false "0.0.0.0"
      } in
      Domain_name.Map.singleton (Domain_name.of_string_exn "foo.com")
        Rr_map.(singleton Mx (556l, Mx_set.singleton mx))
    and edns = Edns.create ~payload_size:450 ()
    in
    let res = Packet.create ~edns (0xe213, flags) question
        (`Answer (answer, Domain_name.Map.empty))
    in
    Alcotest.(check (result t_ok p_err) "regression 4 decodes"
                (Ok res) (decode data))

  (* still not sure whether to allow this or not... -- since the resolver code
     now knows about SRV records (and drops _foo._tcp), this shouldn't appear *)
  let regression4 () =
    let data = of_hex {___|9f ca 84 03 00 01 00 00  00 01 00 01 04 5f 74 63
                           70 04 6b 65 79 73 06 72  69 73 65 75 70 03 6e 65
                           74 00 00 02 00 01 c0 16  00 06 00 01 00 00 01 2c
                           00 2b 07 70 72 69 6d 61  72 79 c0 16 0a 63 6f 6c
                           6c 65 63 74 69 76 65 c0  16 78 48 8b 04 00 00 1c
                           20 00 00 0e 10 00 12 75  00 00 00 01 2c 00 00 29
                           10 00 00 00 00 00 00 00|___}
    in
    let question =
      (Domain_name.of_string_exn ~hostname:false "_tcp.keys.riseup.net", Rr.NS)
    and authority =
      let soa = { Soa.nameserver = Domain_name.of_string_exn "primary.riseup.net" ;
                  hostmaster = Domain_name.of_string_exn "collective.riseup.net" ;
                  serial = 0x78488b04l ; refresh = 0x1c20l ; retry = 0x0e10l ;
                  expiry = 0x127500l ; minimum = 0x012cl }
      in
      Domain_name.Map.singleton (Domain_name.of_string_exn "riseup.net")
        Rr_map.(singleton Soa soa)
    and edns = Edns.create ~payload_size:4096 ()
    in
    let res =
      Packet.create ~edns (0x9FCA, Header.FS.empty) question
        (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (Name_rr_map.empty, authority)))
    in
    Alcotest.(check (result t_ok p_err) "regression 4 decodes"
                (Ok res) (decode data))

  let regression5 () =
    (* this is what bbc returns me (extra bytes) since it doesn't like EDNS *)
    let data = of_hex {___|5b 12 84 01 00 01 00 00  00 00 00 00 03 6e 73 34
                           03 62 62 63 03 6e 65 74  02 75 6b 00 00 02 00 01
                           00 00 29 05 cc 00 00 00  00 00 00|___}
    in
    let flags = Header.FS.singleton `Authoritative
    and question = (Domain_name.of_string_exn "ns4.bbc.net.uk", Rr.NS)
    in
    let res = Packet.create (0x5B12, flags) question
        (`Rcode_error (Rcode.FormErr, Opcode.Query, None))
    in
    Alcotest.(check (result t_ok p_err) "regression 5 decodes"
                (Ok res) (decode data))

  let regression6 () =
    let data = of_hex {|00 03 00 00 00 b5 00 00  00 00 00 00 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 |}
    in
    match decode data with
    | Error _ -> ()
    | Ok _ -> Alcotest.fail "got ok, expected to fail with multiple questions"

  let regression7 () =
    (* encoding a remove_single in an update frame lead to wrong rdlength (off by 2) *)
    let header = 0xAE00, Header.FS.empty
    and update =
      let up =
        Domain_name.Map.singleton
          (n_of_s "www.example.com")
          [ Packet.Update.Remove_single Rr_map.(B (A, (0l, Ipv4_set.singleton Ipaddr.V4.localhost))) ]
      in
      (Domain_name.Map.empty, up)
    and zone = n_of_s "example.com", Rr.SOA
    in
    let res = Packet.create header zone (`Update update) in
    let encoded = fst @@ Packet.encode `Udp res in
    Cstruct.hexdump encoded;
    (* encode followed by decode should lead to same data *)
    Alcotest.(check (result t_ok p_err) "regression 7 decode encode works"
                (Ok res) (decode @@ encoded))

  let regression8 () =
    (* encoding a exists_data in an update frame lead to wrong rdlength (off by 2) *)
    let header = 0xAE00, Header.FS.empty
    and prereq =
      let pre =
        Domain_name.Map.singleton (n_of_s "www.example.com")
          [ Packet.Update.Exists_data Rr_map.(B (A, (0l, Ipv4_set.singleton Ipaddr.V4.localhost)))]
      in
      (pre, Domain_name.Map.empty)
    and zone = (n_of_s "example.com", Rr.SOA)
    in
    let res = Packet.create header zone (`Update prereq) in
    (* encode followed by decode should lead to same data *)
    Alcotest.(check (result t_ok p_err) "regression 8 decode encode works"
                (Ok res) (decode @@ fst @@ Packet.encode `Udp res))

  let regression9 () =
    (* from ednscomp.isc.org *)
    let data = Cstruct.of_hex {|
a8 6c 00 00 00 01 00 00  00 00 00 01 04 6e 71 73
62 02 69 6f 00 00 01 00  01 00 00 29 10 00 00 00
00 00 00 1c 00 03 00 00  00 08 00 04 00 01 00 00
00 0a 00 08 c8 9a 2a f8  aa 77 31 af 00 09 00 00
|}
    in
    let header = 0xa86c, Header.FS.empty
    and question = (n_of_s "nqsb.io", Rr.A)
    and edns =
      let extensions = [
        Edns.Nsid Cstruct.empty ;
        Edns.Extension (8, Cstruct.of_hex "00 01 00 00") ;
        Edns.Cookie (Cstruct.of_hex "c8 9a 2a f8 aa 77 31 af") ;
        Edns.Extension (9, Cstruct.empty)
      ] in
      Edns.create ~payload_size:4096 ~extensions ()
    in
    let res = Packet.create ~edns header question `Query in
    Alcotest.(check (result t_ok p_err) "regression 9 decodes"
                (Ok res) (decode data))

  let code_tests = [
    "bad query", `Quick, bad_query ;
    "regression0", `Quick, regression0 ;
    "regression1", `Quick, regression1 ;
    "regression2", `Quick, regression2 ;
    "regression3", `Quick, regression3 ;
    (* "regression4", `Quick, regression4 ; *)
    "regression5", `Quick, regression5 ;
    "regression6", `Quick, regression6 ;
    "regression7", `Quick, regression7 ;
    "regression8", `Quick, regression8 ;
    "regression9", `Quick, regression9 ;
  ]
end

let tests = [
  "Packet decode", Packet.code_tests ;
]

let () = Alcotest.run "DNS name and packet tests" tests
