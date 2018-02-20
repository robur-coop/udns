(* (c) 2017 Hannes Mehnert, all rights reserved *)

let n_of_s = Dns_name.of_string_exn

module Trie = struct
  open Dns_trie

  let e =
    let module M = struct
      type t =
        [ `Delegation of Dns_name.t * (int32 * Dns_name.DomSet.t)
        | `EmptyNonTerminal of Dns_name.t * int32 * Dns_packet.soa
        | `NotAuthoritative
        | `NotFound of Dns_name.t * int32 * Dns_packet.soa ]
      let pp = Dns_trie.pp_e
      let equal a b = match a, b with
        | `Delegation (na, (ttl, n)), `Delegation (na', (ttl', n')) ->
          Dns_name.equal na na' && ttl = ttl' && Dns_name.DomSet.equal n n'
        | `EmptyNonTerminal (nam, ttl, soa), `EmptyNonTerminal (nam', ttl', soa') ->
          Dns_name.equal nam nam' && ttl = ttl' && Dns_packet.compare_soa soa soa' = 0
        | `NotFound (nam, ttl, soa), `NotFound (nam', ttl', soa') ->
          Dns_name.equal nam nam' && ttl = ttl' && Dns_packet.compare_soa soa soa' = 0
        | `NotAuthoritative, `NotAuthoritative -> true
        | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let v_ok =
    let module M = struct
      type t = Dns_map.v
      let pp = Dns_map.pp_v
      let equal = Dns_map.equal_v
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let l_ok =
    let module M = struct
      type t = Dns_map.v * (Dns_name.t * int32 * Dns_name.DomSet.t)
      let pp ppf (v, (name, ttl, ns)) =
        Fmt.pf ppf "%a auth %a TTL %lu %a" Dns_map.pp_v v Dns_name.pp name ttl
          Fmt.(list ~sep:(unit ",@,") Dns_name.pp) (Dns_name.DomSet.elements ns)
      let equal (a, (name, ttl, ns)) (a', (name', ttl', ns')) =
        ttl = ttl' && Dns_name.equal name name' && Dns_name.DomSet.equal ns ns' &&
        Dns_map.equal_v a a'
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let sn = Dns_name.DomSet.singleton
  let ip = Ipaddr.V4.of_string_exn

  let ins_zone name soa ttl ns t =
    insert name Dns_map.(V (K.Ns, (ttl, ns)))
      (insert name Dns_map.(V (K.Soa, (soa.Dns_packet.minimum, soa))) t)

  let simple () =
    Alcotest.(check (result l_ok e)
                "lookup for root returns NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup Dns_name.root Dns_enum.A empty)) ;
    let soa = {
      Dns_packet.nameserver = n_of_s "a" ; hostmaster = n_of_s "hs" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t = ins_zone Dns_name.root soa 6l (sn (n_of_s "a")) empty in
    Alcotest.(check (result l_ok e) "lookup for .com is NoDomain"
                (Error (`NotFound (Dns_name.root, 4l, soa)))
                (lookup (n_of_s "com") Dns_enum.A t)) ;
    Alcotest.(check (result l_ok e) "lookup for SOA . is SOA"
                (Ok (Dns_map.V (Dns_map.K.Soa, (4l, soa)),
                     (Dns_name.root, 6l, sn (n_of_s "a"))))
                (lookup Dns_name.root Dns_enum.SOA t)) ;
    let t = insert (n_of_s "foo.com") (Dns_map.V (Dns_map.K.A, (23l, [ ip "1.4.5.2" ]))) t in
    Alcotest.(check (result l_ok e) "lookup for A foo.com is A"
                (Ok (Dns_map.V (Dns_map.K.A, (23l, [ ip "1.4.5.2" ])),
                     (Dns_name.root, 6l, sn (n_of_s "a"))))
                (lookup (n_of_s "foo.com") Dns_enum.A t)) ;
    Alcotest.(check (result l_ok e) "lookup for SOA com is ENT"
                (Error (`EmptyNonTerminal (Dns_name.root, 4l, soa)))
                (lookup (n_of_s "com") Dns_enum.SOA t)) ;
    Alcotest.(check (result l_ok e) "lookup for SOA foo.com is NoDomain"
                (Error (`EmptyNonTerminal (Dns_name.root, 4l, soa)))
                (lookup (n_of_s "foo.com") Dns_enum.SOA t))

  let basic () =
    let soa = {
      Dns_packet.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result l_ok e) "lookup for SOA bar.com is NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup (n_of_s "bar.com") Dns_enum.SOA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for SOA foo.com (after insert) is good"
                (Ok (Dns_map.V (Dns_map.K.Soa, (4l, soa)),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup (n_of_s "foo.com") Dns_enum.SOA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for NS foo.com (after insert) is good"
                (Ok (Dns_map.V (Dns_map.K.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup (n_of_s "foo.com") Dns_enum.NS t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", 4l, soa)))
                (lookup (n_of_s "foo.com") Dns_enum.AAAA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for A foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", 4l, soa)))
                (lookup (n_of_s "foo.com") Dns_enum.A t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", 4l, soa)))
                (lookup (n_of_s "foo.com") Dns_enum.MX t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for MX bar.foo.com (after insert) is NoDomain"
                (Error (`NotFound (n_of_s "foo.com", 4l, soa)))
                (lookup (n_of_s "bar.foo.com") Dns_enum.MX t)) ;
    let t = insert (n_of_s "foo.com") (Dns_map.V (Dns_map.K.A, (12l, [ ip "1.2.3.4" ]))) t in
    Alcotest.(check (result l_ok e)
                "lookup for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", 4l, soa)))
                (lookup (n_of_s "foo.com") Dns_enum.AAAA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for A foo.com (after insert) is Found"
                (Ok (Dns_map.V (Dns_map.K.A, (12l, [ ip "1.2.3.4" ])),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup (n_of_s "foo.com") Dns_enum.A t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", 4l, soa)))
                (lookup (n_of_s "foo.com") Dns_enum.MX t)) ;
    let t = remove (n_of_s "foo.com") Dns_enum.A t in
    Alcotest.(check (result l_ok e)
                "lookup for A foo.com (after insert and remove) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", 4l, soa)))
                (lookup (n_of_s "foo.com") Dns_enum.A t)) ;
    let t = remove (n_of_s "foo.com") Dns_enum.ANY t in
    Alcotest.(check (result l_ok e)
                "lookup for SOA foo.com (after remove) is NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup (n_of_s "foo.com") Dns_enum.SOA t))

  let alias () =
    let soa = {
      Dns_packet.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    let t = insert (n_of_s "bar.foo.com") (Dns_map.V (Dns_map.K.Cname, (14l, n_of_s "foo.bar.com"))) t in
    Alcotest.(check (result l_ok e)
                "lookup for SOA bar.foo.com (after insert) is good"
                (Ok (Dns_map.V (Dns_map.K.Cname, (14l, n_of_s "foo.bar.com")),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup (n_of_s "bar.foo.com") Dns_enum.SOA t))

  let dele () =
    let soa = {
      Dns_packet.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result l_ok e)
                "lookup for SOA foo.com (after insert) is good"
                (Ok (Dns_map.V (Dns_map.K.Soa, (4l, soa)),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup (n_of_s "foo.com") Dns_enum.SOA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for NS foo.com (after insert) is good"
                (Ok (Dns_map.V (Dns_map.K.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup (n_of_s "foo.com") Dns_enum.NS t)) ;
    let t = insert (n_of_s "bar.foo.com") (Dns_map.V (Dns_map.K.Ns, (12l, sn (n_of_s "ns3.bar.com")))) t in
    Alcotest.(check (result l_ok e) "lookup for A bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup (n_of_s "bar.foo.com") Dns_enum.A t)) ;
    Alcotest.(check (result l_ok e) "lookup for NS foo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup (n_of_s "foo.bar.foo.com") Dns_enum.NS t)) ;
    Alcotest.(check (result l_ok e) "lookup for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup (n_of_s "foobar.boo.bar.foo.com") Dns_enum.AAAA t)) ;
    let t = ins_zone (n_of_s "a.b.bar.foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) t in
    Alcotest.(check (result l_ok e) "lookup for NS a.b.bar.foo.com is ns1.foo.com"
                (Ok (Dns_map.V (Dns_map.K.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "a.b.bar.foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup (n_of_s "a.b.bar.foo.com") Dns_enum.NS t)) ;
    Alcotest.(check (result l_ok e) "lookup for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup (n_of_s "foobar.boo.bar.foo.com") Dns_enum.AAAA t))

  let r_fst = function Ok (v, _) -> Ok (v) | Error e -> Error e

  let rmzone () =
    let soa = {
      Dns_packet.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result v_ok e) "lookup for NS foo.com is good"
                (Ok (Dns_map.V (Dns_map.K.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup (n_of_s "foo.com") Dns_enum.NS t))) ;
    let t' = remove_zone (n_of_s "foo.com") t in
    Alcotest.(check (result v_ok e) "lookup for NS foo.com after removing zone is notauthoritative"
                (Error `NotAuthoritative)
                (r_fst (lookup (n_of_s "foo.com") Dns_enum.NS t'))) ;
    let t =
      ins_zone (n_of_s "bar.foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) t
    in
    Alcotest.(check (result v_ok e) "lookup for NS bar.foo.com is good"
                (Ok (Dns_map.V (Dns_map.K.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup (n_of_s "bar.foo.com") Dns_enum.NS t))) ;
    Alcotest.(check (result v_ok e) "lookup for NS foo.com is good"
                (Ok (Dns_map.V (Dns_map.K.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup (n_of_s "foo.com") Dns_enum.NS t))) ;
    let t' = remove_zone (n_of_s "foo.com") t in
    Alcotest.(check (result v_ok e) "lookup for NS bar.foo.com is good (after foo.com is removed)"
                (Ok (Dns_map.V (Dns_map.K.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup (n_of_s "bar.foo.com") Dns_enum.NS t'))) ;
    Alcotest.(check (result v_ok e) "lookup for NS foo.com is not authoritative"
                (Error `NotAuthoritative)
                (r_fst (lookup (n_of_s "foo.com") Dns_enum.NS t'))) ;
    let t' = remove_zone (n_of_s "bar.foo.com") t in
    Alcotest.(check (result v_ok e) "lookup for NS bar.foo.com is not authoritative"
                (Error (`NotFound (n_of_s "foo.com", 4l, soa)))
                (r_fst (lookup (n_of_s "bar.foo.com") Dns_enum.NS t'))) ;
    Alcotest.(check (result v_ok e) "lookup for NS foo.com is good"
                (Ok (Dns_map.V (Dns_map.K.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup (n_of_s "foo.com") Dns_enum.NS t')))


  let tests = [
    "simple", `Quick, simple ;
    "basic", `Quick, basic ;
    "alias", `Quick, alias ;
    "delegation", `Quick, dele ;
    "rmzone", `Quick, rmzone ;
  ]
end

let tests = [
  "Trie", Trie.tests ;
]

let () = Alcotest.run "DNS server tests" tests
