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

module Name = struct
  let p_err =
    let module M = struct
      type t = Name.err
      let pp = Name.pp_err
      let equal a b = match a, b with
        | `Partial, `Partial -> true
        | `TooLong, `TooLong -> true
        | `BadOffset a, `BadOffset b -> a = b
        | `BadTag a, `BadTag b -> a = b
        | `BadContent a, `BadContent b -> String.compare a b = 0
        | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let p_ok =
    let module M = struct
      type t = Domain_name.t * (Domain_name.t * int) Name.IntMap.t * int
      let pp ppf (name, map, off) =
        Fmt.pf ppf "%a (map: %a) %d"
          Domain_name.pp name
          (Fmt.list ~sep:(Fmt.unit ";@ ")
             (Fmt.pair ~sep:(Fmt.unit "->") Fmt.int
                (Fmt.pair ~sep:(Fmt.unit " ") Domain_name.pp Fmt.int)))
          (Name.IntMap.bindings map)
          off
      let equal (n, m, off) (n', m', off') =
        Domain_name.equal n n' && off = off' &&
        Name.IntMap.equal
          (fun (nam, siz) (nam', siz') -> Domain_name.equal nam nam' && siz = siz')
          m m'
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let p_msg =
    let module M = struct
      type t = [ `Msg of string ]
      let pp ppf (`Msg s) = Fmt.string ppf s
      let equal _ _ = true
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let p_name = Alcotest.testable Domain_name.pp Domain_name.equal

  let p_enc =
    let module M = struct
      type t = int Domain_name.Map.t * int
      let pp ppf (names, off) =
        Fmt.pf ppf "map: %a, off: %d"
          (Fmt.list ~sep:(Fmt.unit ";@ ")
             (Fmt.pair ~sep:(Fmt.unit "->") Domain_name.pp Fmt.int))
          (Domain_name.Map.bindings names)
          off
      let equal (m, off) (m', off') =
        off = off' &&
        Domain_name.Map.equal (fun off off' -> off = off') m m'
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let simple () =
    let m =
      Name.IntMap.add 0 (n_of_s "foo.com", 9)
        (Name.IntMap.add 4 (n_of_s "com", 5)
           (Name.IntMap.add 8 (Domain_name.root, 1) Name.IntMap.empty))
    in
    Alcotest.(check (result p_ok p_err) "simple name decode test"
                (Ok (n_of_s "foo.com", m, 9))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\003foo\003com\000") 0)) ;
    Alcotest.(check (result p_ok p_err) "another simple name decode test"
                (Ok (n_of_s "foo.com", Name.IntMap.add 9 (n_of_s "foo.com", 9) m, 11))
                (Name.decode m (Cstruct.of_string "\003foo\003com\000\xC0\000") 9)) ;
    Alcotest.(check (result p_ok p_err) "a ptr added to the name decode test"
                (Ok (n_of_s "bar.foo.com",
                     Name.IntMap.add 13 (n_of_s "foo.com", 9)
                       (Name.IntMap.add 9 (n_of_s "bar.foo.com", 13) m),
                     15))
                (Name.decode m (Cstruct.of_string "\003foo\003com\000\003bar\xC0\000") 9)) ;
    Alcotest.(check (result p_ok p_err) "a ptr with bar- added to the name decode test"
                (Ok (n_of_s "bar-.foo.com",
                     Name.IntMap.add 14 (n_of_s "foo.com", 9)
                       (Name.IntMap.add 9 (n_of_s "bar-.foo.com", 14) m),
                     16))
                (Name.decode m (Cstruct.of_string "\003foo\003com\000\004bar-\xC0\000") 9)) ;
    let m =
      Name.IntMap.add 0 (n_of_s "f23", 5) (Name.IntMap.add 4 (Domain_name.root, 1) Name.IntMap.empty)
    in
    Alcotest.(check (result p_ok p_err) "simple name decode test of f23"
                (Ok (n_of_s "f23", m, 5))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\003f23\000") 0)) ;
    let m = Name.IntMap.add 0 (n_of_s ~hostname:false "23", 4)
        (Name.IntMap.add 3 (Domain_name.root, 1) Name.IntMap.empty)
    in
    Alcotest.(check (result p_ok p_err) "simple DNS name decode test of 23"
                (Ok (n_of_s ~hostname:false "23", m, 4))
                (Name.decode ~hostname:false Name.IntMap.empty
                   (Cstruct.of_string "\00223\000") ~off:0))

  let encode () =
    let cs = Cstruct.create 30 in
    Alcotest.check p_enc "compressed encode of root is good"
      (Domain_name.Map.empty, 1) (Name.encode Domain_name.root Domain_name.Map.empty cs 0) ;
    Alcotest.check p_cs "cstruct is good" (of_hex "00") (Cstruct.sub cs 0 1) ;
    Alcotest.check p_enc "uncompressed encode of root is good"
      (Domain_name.Map.empty, 1) (Name.encode ~compress:false Domain_name.root Domain_name.Map.empty cs 0) ;
    Alcotest.check p_cs "cstruct is good" (of_hex "00") (Cstruct.sub cs 0 1) ;
    let map =
      Domain_name.Map.add (n_of_s "foo.bar") 0
        (Domain_name.Map.add (n_of_s "bar") 4 Domain_name.Map.empty)
    in
    Alcotest.check p_enc "encode of 'foo.bar' is good"
      (map, 9) (Name.encode (n_of_s "foo.bar") Domain_name.Map.empty cs 0) ;
    Alcotest.check p_cs "cstruct is good" (of_hex "03 66 6f 6f 03 62 61 72 00")
      (Cstruct.sub cs 0 9) ;
    Alcotest.check p_enc "uncompressed encode of 'foo.bar' is good"
      (map, 9) (Name.encode ~compress:false (n_of_s "foo.bar") Domain_name.Map.empty cs 0) ;
    Alcotest.check p_cs "cstruct is good" (of_hex "03 66 6f 6f 03 62 61 72 00")
      (Cstruct.sub cs 0 9) ;
    let emap = Domain_name.Map.add (n_of_s "baz.foo.bar") 9 map in
    Alcotest.check p_enc "encode of 'baz.foo.bar' is good"
      (emap, 15) (Name.encode (n_of_s "baz.foo.bar") map cs 9) ;
    Alcotest.check p_cs "cstruct is good"
      (of_hex "03 66 6f 6f 03 62 61 72 00 03 62 61 7a c0 00")
      (Cstruct.sub cs 0 15) ;
    let map' =
      Domain_name.Map.add (n_of_s "baz.foo.bar") 9
        (Domain_name.Map.add (n_of_s "foo.bar") 13
           (Domain_name.Map.add (n_of_s "bar") 17 Domain_name.Map.empty))
    in
    Alcotest.check p_enc "uncompressed encode of 'baz.foo.bar' is good"
      (map', 22) (Name.encode ~compress:false (n_of_s "baz.foo.bar") map cs 9) ;
    Alcotest.check p_cs "cstruct is good"
      (of_hex "03 66 6f 6f 03 62 61 72 00 03 62 61 7a 03 66 6f 6f 03 62 61 72 00")
      (Cstruct.sub cs 0 22)

  let partial () =
    Alcotest.(check (result p_ok p_err) "partial domain name (bar)"
                (Error `Partial)
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\003bar") 0));
    Alcotest.(check (result p_ok p_err) "partial domain name (one byte ptr)"
                (Error `Partial)
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\xC0") 0)) ;
    Alcotest.(check (result p_ok p_err) "partial domain name (5foo)"
                (Error `Partial)
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\005foo") 0))

  let bad_ptr () =
    Alcotest.(check (result p_ok p_err) "bad pointer in label"
                (Error (`BadOffset 10))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\xC0\x0A") 0)) ;
    Alcotest.(check (result p_ok p_err) "cyclic self-pointer in label"
                (Error (`BadOffset 0))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\xC0\x00") 0)) ;
    Alcotest.(check (result p_ok p_err) "cyclic self-pointer in label"
                (Error (`BadOffset 1))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\xC0\x01") 0))

  let bad_tag () =
    Alcotest.(check (result p_ok p_err) "bad tag (0x40) in label"
                (Error (`BadTag 0x40))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\x40") 0)) ;
    Alcotest.(check (result p_ok p_err) "bad tag (0x80) in label"
                (Error (`BadTag 0x80))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\x80") 0))

  let bad_content () =
    Alcotest.(check (result p_ok p_err) "bad content '-' in label"
                (Error (`BadContent "-"))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\001-\000") 0)) ;
    Alcotest.(check (result p_ok p_err) "bad content 'foo-+' in label"
                (Error (`BadContent "foo-+"))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\005foo-+\000") 0)) ;
    Alcotest.(check (result p_ok p_err) "bad content '23' in label"
                (Error (`BadContent "23"))
                (Name.decode Name.IntMap.empty (Cstruct.of_string "\00223\000") 0))

  let length () =
    let max = "s23456789012345678901234567890123456789012345678901234567890123" in
    let lst, _ = String.span ~max:61 max in
    let full = n_of_s (String.concat ~sep:"." [ max ; max ; max ; lst ]) in
    Alcotest.(check (result p_ok p_err) "longest allowed domain name"
                (Ok (full,
                     Name.IntMap.add 0 (full, 255)
                       (Name.IntMap.add 64 (n_of_s (String.concat ~sep:"." [ max ; max ; lst ]), 191)
                          (Name.IntMap.add 128 (n_of_s (String.concat ~sep:"." [ max ; lst ]), 127)
                             (Name.IntMap.add 192 (n_of_s lst, 63)
                                (Name.IntMap.add 254 (Domain_name.root, 1) Name.IntMap.empty)))),
                     255))
                (Name.decode Name.IntMap.empty
                   (Cstruct.of_string ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3D" ^ lst ^ "\000"))
                   0)) ;
    Alcotest.(check (result p_ok p_err) "domain name too long"
                (Error `TooLong)
                (Name.decode Name.IntMap.empty
                   (Cstruct.of_string ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3E" ^ lst ^ "1\000"))
                   0)) ;
    Alcotest.(check (result p_ok p_err) "domain name really too long"
                (Error `TooLong)
                (Name.decode Name.IntMap.empty
                   (Cstruct.of_string ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\000"))
                   0))

  let code_tests = [
    "simple decode", `Quick, simple ;
    "encode", `Quick, encode ;
    "partial", `Quick, partial ;
    "bad pointer", `Quick, bad_ptr ;
    "bad tag", `Quick, bad_tag ;
    "bad content", `Quick, bad_content ;
    "length checks", `Quick, length ;
  ]
end


module Packet = struct
  let p_err =
    let module M = struct
      type t = Packet.err
      let pp = Packet.pp_err
      let equal a b = match a, b with
        | `Partial, `Partial -> true
        | `TooLong, `TooLong -> true
        | `BadOffset a, `BadOffset b -> a = b
        | `BadTag a, `BadTag b -> a = b
        | `BadContent a, `BadContent b -> String.compare a b = 0
        | `BadTTL a, `BadTTL b -> Int32.compare a b = 0
        | `BadRRTyp a, `BadRRTyp b -> a = b
        | `UnsupportedRRTyp a, `UnsupportedRRTyp b -> a = b
        | `BadClass a, `BadClass b -> a = b
        | `UnsupportedClass a, `UnsupportedClass b -> a = b
        | `BadOpcode a, `BadOpcode b -> a = b
        | `UnsupportedOpcode a, `UnsupportedOpcode b -> a = b
        | `BadRcode a, `BadRcode b -> a = b
        | `BadCaaTag, `BadCaaTag -> true
        | `LeftOver, `LeftOver -> true
        | `BadProto a, `BadProto b -> a = b
        | `BadAlgorithm a, `BadAlgorithm b -> a = b
        | `BadEdns, `BadEdns -> true
        | `BadKeepalive, `BadKeepalive -> true
        | `InvalidTimestamp a, `InvalidTimestamp b -> a = b
        | `InvalidAlgorithm a, `InvalidAlgorithm b -> Domain_name.equal a b
        | `NonZeroTTL a, `NonZeroTTL b -> a = b
        | `NonZeroRdlen a, `NonZeroRdlen b -> a = b
        | `InvalidZoneCount a, `InvalidZoneCount b -> a = b
        | `InvalidZoneRR a, `InvalidZoneRR b -> a = b
        | `BadTlsaCertUsage u, `BadTlsaCertUsage v -> u = v
        | `BadTlsaSelector s, `BadTlsaSelector t -> s = t
        | `BadTlsaMatchingType m, `BadTlsaMatchingType n -> m = n
        | `BadSshfpAlgorithm i, `BadSshfpAlgorithm j -> i = j
        | `BadSshfpType i, `BadSshfpType j -> i = j
        | `Bad_edns_version a, `Bad_edns_version b -> a = b
        | `None_or_multiple_questions, `None_or_multiple_questions -> true
        | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let question_equal a b = Question.compare a b = 0

(*  let prereq_equal a b = match a, b with
    | Exists (name, typ), Exists (name', typ') ->
      Domain_name.equal name name' && typ = typ'
    | Exists_data (name, rd), Exists_data (name', rd') ->
      Domain_name.equal name name' && compare_rdata rd rd' = 0
    | Not_exists (name, typ), Not_exists (name', typ') ->
      Domain_name.equal name name' && typ = typ'
    | Name_inuse name, Name_inuse name' ->
      Domain_name.equal name name'
    | Not_name_inuse name, Not_name_inuse name' ->
      Domain_name.equal name name'
    | _ -> false

  let update_equal a b = match a, b with
    | Remove (name, typ), Remove (name', typ') ->
      Domain_name.equal name name' && typ = typ'
    | Remove_all name, Remove_all name' ->
      Domain_name.equal name name'
    | Remove_single (name, rd), Remove_single (name', rd') ->
      Domain_name.equal name name' && compare_rdata rd rd' = 0
    | Add rr, Add rr' ->
      rr_equal rr rr'
    | _ -> false
*)
  let header_equal a b = Header.compare a b = 0

  let h_ok = Alcotest.testable Header.pp header_equal

  let q_ok =
    let module M = struct
      type t = Header.t * Packet.t
      let pp = Fmt.(pair Header.pp Packet.pp)
      let equal (ah, a) (bh, b) = Header.compare ah bh = 0 && Packet.equal a b
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let basic_header () =
    let hdr = { Header.id = 1 ; query = true ; operation = Udns_enum.Query ;
                rcode = Udns_enum.NoError ; flags = Header.FS.empty }
    in
    let cs = Cstruct.create 12 in
    Header.encode cs hdr ;
    Alcotest.check p_cs "first encoded header is good"
      (of_hex "00 01 00 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "first encoded header can be decoded"
                (Ok hdr) (Header.decode cs)) ;
    let hdr' = { hdr with query = false ; rcode = Udns_enum.NXDomain } in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "second encoded header' is good"
      (of_hex "00 01 80 03") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "second encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Authentic_data in
      { hdr with Header.operation = Udns_enum.Update ; flags }
    in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "third encoded header' is good"
      (of_hex "00 01 28 20") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "third encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Truncation in
      { hdr with Header.flags }
    in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "fourth encoded header' is good"
      (of_hex "00 01 02 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "fourth encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Checking_disabled in
      { hdr with Header.flags } in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "fifth encoded header' is good"
      (of_hex "00 01 00 10") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "fifth encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    Alcotest.(check (result h_ok p_err) "header with bad opcode"
                (Error (`BadOpcode 14))
                (Header.decode (of_hex "0000 7000 0000 0000 0000 0000"))) ;
    Alcotest.(check (result h_ok p_err) "header with bad rcode"
                (Error (`BadRcode 14))
                (Header.decode (of_hex "0000 000e 0000 0000 0000 0000"))) ;
    let hdr' =
      let flags = Header.FS.singleton `Authoritative in
      { hdr with Header.flags }
    in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "sixth encoded header' is good"
      (of_hex "00 01 04 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "sixth encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Recursion_desired in
      { hdr with Header.flags } in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "seventh encoded header' is good"
      (of_hex "00 01 01 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "seventh encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.(add `Recursion_desired (singleton `Authoritative)) in
      { hdr with Header.flags }
    in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "eigth encoded header' is good"
      (of_hex "00 01 05 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "eigth encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Recursion_available in
      { hdr with Header.flags } in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "nineth encoded header' is good"
      (of_hex "00 01 00 80") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "nineth encoded header can be decoded"
                (Ok hdr') (Header.decode cs))

  let decode cs =
    match Packet.decode cs with
    | Error e -> Error e
    | Ok (header, v, _, _) -> Ok (header, v)

  let bad_query () =
    let cs = of_hex "0000 0000 0001 0000 0000 0000 0000 0100 02" in
    Alcotest.(check (result q_ok p_err) "query with bad class"
                (Error (`BadClass 2))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 0100 03" in
    Alcotest.(check (result q_ok p_err) "query with unsupported class"
                (Error (`UnsupportedClass Udns_enum.CHAOS))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 0000 01" in
    Alcotest.(check (result q_ok p_err) "question with unsupported typ"
                (Error (`BadRRTyp 0))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 2100 01" in
    Alcotest.(check (result q_ok p_err) "question with bad SRV"
                (Error (`BadContent ""))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0102 0000 0200 01" in
    Alcotest.(check (result q_ok p_err) "question with bad hostname"
                (Error (`BadContent "\002"))
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
    let header =
      let flags = Header.FS.(add `Authoritative (add `Recursion_desired (singleton `Recursion_available))) in
      { Header.id = 0xD4E4 ; query = false ; operation = Udns_enum.Query ;
        rcode = Udns_enum.NXDomain ; flags }
    in
    let soa = {
      Soa.nameserver = n_of_s "CON1R.NIPR.MIL" ;
      hostmaster =
        Domain_name.of_strings_exn ~hostname:false
          ["DANIEL.W.KNOPPS.CIV" ; "MAIL" ; "MIL" ] ;
      serial = 0x7839c3d1l ; refresh = 0x2a30l ; retry = 0x384l ;
      expiry = 0x127500l ; minimum = 0x2a30l
    }
    in
    Alcotest.(check (result q_ok p_err) "regression 0 decodes"
                (Ok (header, `Query {
                     question = (n_of_s "6.16.150.138.in-addr.arpa", Udns_enum.PTR) ;
                     answer = Domain_name.Map.empty ;
                     authority =
                       Domain_name.Map.singleton (n_of_s "150.138.in-addr.arpa")
                         Umap.(singleton Soa soa) ;
                     additional = Domain_name.Map.empty}))
                (decode data))

  let regression1 () =
    let data = of_hex {___|83 d9 01 00 00 01 00 00 00 00 00 00 04 6b 65 79
                           73 06 72 69 73 65 75 70 03 6e 65 74 00 00 1c 00
                           01|___}
    in
    let header =
      let flags = Header.FS.singleton `Recursion_desired in
      { Header.id = 0x83D9 ; query = true ; operation = Udns_enum.Query ;
        rcode = Udns_enum.NoError ; flags }
    in
    Alcotest.(check (result q_ok p_err) "regression 1 decodes"
                (Ok (header, `Query (Packet.Query.create (n_of_s "keys.riseup.net", Udns_enum.AAAA))))
                (decode data))

  let regression2 () =
    let data = of_hex {___|ae 00 84 03 00 01 00 00 00 01 00 00 04 6e 65 77
                           73 03 62 62 63 03 6e 65 74 02 75 6b 00 00 02 00
                           01 03 62 62 63 03 6e 65 74 02 75 6b 00 00 06 00
                           01 00 00 0e 10 00 34 03 32 31 32 02 35 38 03 32
                           33 30 03 32 30 30 00 04 62 6f 66 68 03 62 62 63
                           02 63 6f 02 75 6b 00 59 5c bd ce 00 01 51 80 00
                           01 51 80 00 01 51 80 00 00 01 2c|___}
    in
    let header =
      let rcode = Udns_enum.NXDomain
      and flags = Header.FS.singleton `Authoritative
      in
      { Header.query = false ; id = 0xAE00 ; operation = Udns_enum.Query ;
        rcode ; flags }
    in
    let soa = {
      Soa.nameserver = n_of_s ~hostname:false "212.58.230.200" ;
      hostmaster = n_of_s "bofh.bbc.co.uk" ;
      serial = 0x595cbdcel ; refresh = 0x00015180l ; retry = 0x00015180l ;
      expiry = 0x00015180l ; minimum = 0x0000012cl
    } in
    Alcotest.(check (result q_ok p_err) "regression 2 decodes"
                (Ok (header, `Query {
                     question = (n_of_s "news.bbc.net.uk", Udns_enum.NS) ;
                     authority =
                       Domain_name.Map.singleton (n_of_s "bbc.net.uk")
                         Umap.(singleton Soa soa) ;
                     answer = Domain_name.Map.empty ;
                     additional = Domain_name.Map.empty }))
                (decode data))

  let regression3 () =
    let data = of_hex {___|e213 8180 0001
        0001 0000 0001 0366 6f6f 0363 6f6d 0000
        0f00 01c0 0c00 0f00 0100 0002 2c00 0b03
        e801 3001 3001 3001 3000 0000 2901 c2 00
        0000 0000 00|___}
    in
    let header =
      let rcode = Udns_enum.NoError
      and flags = Header.FS.(add `Recursion_desired (singleton `Recursion_available))
      in
      { Header.query = false ; id = 0xe213 ; operation = Udns_enum.Query ;
        rcode ; flags }
    in
    let question =
      (Domain_name.of_string_exn ~hostname:false "foo.com", Udns_enum.MX)
    and answer =
      let mx = {
        Mx.preference = 1000 ;
        mail_exchange = Domain_name.of_string_exn ~hostname:false "0.0.0.0"
      } in
      Domain_name.Map.singleton (Domain_name.of_string_exn "foo.com")
        Umap.(singleton Mx (556l, Mx_set.singleton mx))
    and additional = Domain_name.Map.empty
    in
(*      let opt = Udns_packet.opt ~payload_size:450 () in
      [ { name = Domain_name.root ; ttl = 0l ; rdata = OPTS opt } ]
        in *)
    Alcotest.(check (result q_ok p_err) "regression 4 decodes"
                (Ok (header, `Query {
                     question ; authority = additional ; answer ; additional}))
                (decode data))

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
    let header =
      let rcode = Udns_enum.NXDomain in
      { Header.query = false ; id = 0x9FCA ; operation = Udns_enum.Query ;
        rcode ; flags = Header.FS.empty }
    in
    let question =
      (Domain_name.of_string_exn ~hostname:false "_tcp.keys.riseup.net", Udns_enum.NS)
    and authority =
      let soa = { Soa.nameserver = Domain_name.of_string_exn "primary.riseup.net" ;
                  hostmaster = Domain_name.of_string_exn "collective.riseup.net" ;
                  serial = 0x78488b04l ; refresh = 0x1c20l ; retry = 0x0e10l ;
                  expiry = 0x127500l ; minimum = 0x012cl }
      in
      Domain_name.Map.singleton (Domain_name.of_string_exn "riseup.net")
        Umap.(singleton Soa soa)
    and additional = Domain_name.Map.empty
(*      let opt = Udns_packet.opt ~payload_size:4096 () in
        [ { name = Domain_name.root ; ttl = 0l ; rdata = OPTS opt } ] *)
    in
    Alcotest.(check (result q_ok p_err) "regression 4 decodes"
                (Ok (header, `Query {
                     question ; authority ;
                     answer = additional ; additional}))
                (decode data))

  let regression5 () =
    (* this is what bbc returns me (extra bytes) since it doesn't like EDNS *)
    let data = of_hex {___|5b 12 84 01 00 01 00 00  00 00 00 00 03 6e 73 34
                           03 62 62 63 03 6e 65 74  02 75 6b 00 00 02 00 01
                           00 00 29 05 cc 00 00 00  00 00 00|___}
    in
    let header =
      let rcode = Udns_enum.FormErr
      and flags = Header.FS.singleton `Authoritative
      in
      { Header.query = false ; id = 0x5B12 ; operation = Udns_enum.Query ;
        rcode ; flags }
    in
    let question =
      (Domain_name.of_string_exn "ns4.bbc.net.uk", Udns_enum.NS)
    in
    Alcotest.(check (result q_ok p_err) "regression 5 decodes"
                (Ok (header, `Query (Packet.Query.create question)))
                (decode data))


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
    | Error `None_or_multiple_questions -> ()
    | Error _ -> Alcotest.fail "expected to fail with none or multiple questions"
    | Ok _ -> Alcotest.fail "got ok, expected to fail with multiple questions"

  let regression7 () =
    (* encoding a remove_single in an update frame lead to wrong rdlength (off by 2) *)
    let header, update =
      let header =
        let rcode = Udns_enum.NoError in
        { Header.query = true ; id = 0xAE00 ; operation = Udns_enum.Update ;
          rcode ; flags = Header.FS.empty }
      and update = Domain_name.Map.singleton
          (n_of_s "www.example.com")
          [ Packet.Update.Remove_single Umap.(B (A, (0l, Ipv4_set.singleton Ipaddr.V4.localhost))) ]
      and zone = n_of_s "example.com", Udns_enum.SOA
      in
      header, { Packet.Update.zone ; prereq = Domain_name.Map.empty ;
                update = update ; addition = Domain_name.Map.empty }
    in
    (* encode followed by decode should lead to same data *)
    Alcotest.(check (result q_ok p_err) "regression 7 decode encode works"
                (Ok (header, `Update update))
                (decode @@ fst @@ Packet.encode `Udp header (`Update update)))

  let regression8 () =
    (* encoding a exists_data in an update frame lead to wrong rdlength (off by 2) *)
    let header, update =
      let header =
        let rcode = Udns_enum.NoError in
        { Header.query = true ; id = 0xAE00 ; operation = Udns_enum.Update ;
          rcode ; flags = Header.FS.empty }
      and prereq =
        Domain_name.Map.singleton (n_of_s "www.example.com")
          [ Packet.Update.Exists_data Umap.(B (A, (0l, Ipv4_set.singleton Ipaddr.V4.localhost)))]
      and zone = (n_of_s "example.com", Udns_enum.SOA)
      in
      header, Packet.Update.create ~prereq zone
    in
    (* encode followed by decode should lead to same data *)
    Alcotest.(check (result q_ok p_err) "regression 8 decode encode works"
                (Ok (header, `Update update))
                (decode @@ fst @@ Packet.encode `Udp header (`Update update)))

  let code_tests = [
    "basic header", `Quick, basic_header ;
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
  ]
end

let tests = [
  "Name code", Name.code_tests ;
  "Packet decode", Packet.code_tests ;
]

let () = Alcotest.run "DNS name and packet tests" tests
