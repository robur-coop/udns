(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Udns

let n_of_s = Domain_name.of_string_exn

module Trie = struct
  open Udns_trie

  let e =
    let module M = struct
      type t = e
      let pp = Udns_trie.pp_e
      let equal a b = match a, b with
        | `Delegation (na, (ttl, n)), `Delegation (na', (ttl', n')) ->
          Domain_name.equal na na' && ttl = ttl' && Domain_name.Set.equal n n'
        | `EmptyNonTerminal (nam, soa), `EmptyNonTerminal (nam', soa') ->
          Domain_name.equal nam nam' && Soa.compare soa soa' = 0
        | `NotFound (nam, soa), `NotFound (nam', soa') ->
          Domain_name.equal nam nam' && Soa.compare soa soa' = 0
        | `NotAuthoritative, `NotAuthoritative -> true
        | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let b_ok =
    let module M = struct
      type t = Rr_map.b
      let pp = Rr_map.pp_b
      let equal = Rr_map.equalb
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let l_ok =
    let module M = struct
      type t = Rr_map.b * (Domain_name.t * int32 * Domain_name.Set.t)
      let pp ppf (v, (name, ttl, ns)) =
        Fmt.pf ppf "%a auth %a TTL %lu %a" Rr_map.pp_b v Domain_name.pp name ttl
          Fmt.(list ~sep:(unit ",@,") Domain_name.pp) (Domain_name.Set.elements ns)
      let equal (a, (name, ttl, ns)) (a', (name', ttl', ns')) =
        ttl = ttl' && Domain_name.equal name name' && Domain_name.Set.equal ns ns' &&
        Rr_map.equalb a a'
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let sn = Domain_name.Set.singleton
  let ip = Ipaddr.V4.of_string_exn

  let ins_zone name soa ttl ns t =
    insert name Rr_map.Ns (ttl, ns)
      (insert name Rr_map.Soa soa t)

  let simple () =
    Alcotest.(check (result l_ok e)
                "lookup for root returns NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup_with_cname Domain_name.root A empty)) ;
    let soa = {
      Soa.nameserver = n_of_s "a" ; hostmaster = n_of_s "hs" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t = ins_zone Domain_name.root soa 6l (sn (n_of_s "a")) empty in
    Alcotest.(check (result l_ok e) "lookup for .com is NoDomain"
                (Error (`NotFound (Domain_name.root, soa)))
                (lookup_with_cname (n_of_s "com") A t)) ;
    Alcotest.(check (result l_ok e) "lookup for SOA . is SOA"
                (Ok (Rr_map.B (Rr_map.Soa, soa),
                     (Domain_name.root, 6l, sn (n_of_s "a"))))
                (lookup_with_cname Domain_name.root Soa t)) ;
    let a_record = (23l, Rr_map.Ipv4_set.singleton (ip "1.4.5.2")) in
    let t = insert (n_of_s "foo.com") Rr_map.A a_record t in
    Alcotest.(check (result l_ok e) "lookup for A foo.com is A"
                (Ok (Rr_map.B (Rr_map.A, a_record),
                     (Domain_name.root, 6l, sn (n_of_s "a"))))
                (lookup_with_cname (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result l_ok e) "lookup for SOA com is ENT"
                (Error (`EmptyNonTerminal (Domain_name.root, soa)))
                (lookup_with_cname (n_of_s "com") Soa t)) ;
    Alcotest.(check (result l_ok e) "lookup for SOA foo.com is NoDomain"
                (Error (`EmptyNonTerminal (Domain_name.root, soa)))
                (lookup_with_cname (n_of_s "foo.com") Soa t))

  let basic () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result l_ok e) "lookup for SOA bar.com is NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup_with_cname (n_of_s "bar.com") Soa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for SOA foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Soa, soa),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") Ns t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") Aaaa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for A foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") Mx t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for MX bar.foo.com (after insert) is NoDomain"
                (Error (`NotFound (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "bar.foo.com") Mx t)) ;
    let a_record = (12l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")) in
    let t = insert (n_of_s "foo.com") Rr_map.A a_record t in
    Alcotest.(check (result l_ok e)
                "lookup for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") Aaaa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for A foo.com (after insert) is Found"
                (Ok (Rr_map.B (Rr_map.A, a_record),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") Mx t)) ;
    let t = remove (n_of_s "foo.com") A t in
    Alcotest.(check (result l_ok e)
                "lookup for A foo.com (after insert and remove) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") A t)) ;
    let t = remove_all (n_of_s "foo.com") t in
    Alcotest.(check (result l_ok e)
                "lookup for SOA foo.com (after remove) is NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup_with_cname (n_of_s "foo.com") Soa t))

  let alias () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    let t = insert (n_of_s "bar.foo.com") Rr_map.Cname (14l, n_of_s "foo.bar.com") t in
    Alcotest.(check (result l_ok e)
                "lookup for SOA bar.foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Cname, (14l, n_of_s "foo.bar.com")),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "bar.foo.com") Soa t))

  let dele () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result l_ok e)
                "lookup for SOA foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Soa, soa),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") Ns t)) ;
    let t = insert (n_of_s "bar.foo.com") Rr_map.Ns (12l, sn (n_of_s "ns3.bar.com")) t in
    Alcotest.(check (result l_ok e) "lookup for A bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_with_cname (n_of_s "bar.foo.com") A t)) ;
    Alcotest.(check (result l_ok e) "lookup for NS foo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_with_cname (n_of_s "foo.bar.foo.com") Ns t)) ;
    Alcotest.(check (result l_ok e) "lookup for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_with_cname (n_of_s "foobar.boo.bar.foo.com") Aaaa t)) ;
    let t = ins_zone (n_of_s "a.b.bar.foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) t in
    Alcotest.(check (result l_ok e) "lookup for NS a.b.bar.foo.com is ns1.foo.com"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "a.b.bar.foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "a.b.bar.foo.com") Ns t)) ;
    Alcotest.(check (result l_ok e) "lookup for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_with_cname (n_of_s "foobar.boo.bar.foo.com") Aaaa t))

  let r_fst = function Ok (v, _) -> Ok (v) | Error e -> Error e

  let rmzone () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result b_ok e) "lookup for NS foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t))) ;
    let t' = remove_zone (n_of_s "foo.com") t in
    Alcotest.(check (result b_ok e) "lookup for NS foo.com after removing zone is notauthoritative"
                (Error `NotAuthoritative)
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t'))) ;
    let t =
      ins_zone (n_of_s "bar.foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) t
    in
    Alcotest.(check (result b_ok e) "lookup for NS bar.foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "bar.foo.com") Ns t))) ;
    Alcotest.(check (result b_ok e) "lookup for NS foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t))) ;
    let t' = remove_zone (n_of_s "foo.com") t in
    Alcotest.(check (result b_ok e) "lookup for NS bar.foo.com is good (after foo.com is removed)"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "bar.foo.com") Ns t'))) ;
    Alcotest.(check (result b_ok e) "lookup for NS foo.com is not authoritative"
                (Error `NotAuthoritative)
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t'))) ;
    let t' = remove_zone (n_of_s "bar.foo.com") t in
    Alcotest.(check (result b_ok e) "lookup for NS bar.foo.com is not authoritative"
                (Error (`NotFound (n_of_s "foo.com", soa)))
                (r_fst (lookup_with_cname (n_of_s "bar.foo.com") Ns t'))) ;
    Alcotest.(check (result b_ok e) "lookup for NS foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t')))


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
