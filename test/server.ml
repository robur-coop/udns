(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Udns

let n_of_s = Domain_name.of_string_exn

module Trie = struct
  open Udns_trie

  let e =
    let module M = struct
      type t =
        [ `Delegation of Domain_name.t * (int32 * Domain_name.Set.t)
        | `EmptyNonTerminal of Domain_name.t * (int32 * Soa.t)
        | `NotAuthoritative
        | `NotFound of Domain_name.t * (int32 * Soa.t) ]
      let pp = Udns_trie.pp_e
      let equal a b = match a, b with
        | `Delegation (na, (ttl, n)), `Delegation (na', (ttl', n')) ->
          Domain_name.equal na na' && ttl = ttl' && Domain_name.Set.equal n n'
        | `EmptyNonTerminal (nam, (ttl, soa)), `EmptyNonTerminal (nam', (ttl', soa')) ->
          Domain_name.equal nam nam' && ttl = ttl' && Soa.compare soa soa' = 0
        | `NotFound (nam, (ttl, soa)), `NotFound (nam', (ttl', soa')) ->
          Domain_name.equal nam nam' && ttl = ttl' && Soa.compare soa soa' = 0
        | `NotAuthoritative, `NotAuthoritative -> true
        | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let b_ok =
    let module M = struct
      type t = Umap.b
      let pp = Umap.pp_b
      let equal = Umap.equal_b
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let l_ok =
    let module M = struct
      type t = Umap.b * (Domain_name.t * int32 * Domain_name.Set.t)
      let pp ppf (v, (name, ttl, ns)) =
        Fmt.pf ppf "%a auth %a TTL %lu %a" Umap.pp_b v Domain_name.pp name ttl
          Fmt.(list ~sep:(unit ",@,") Domain_name.pp) (Domain_name.Set.elements ns)
      let equal (a, (name, ttl, ns)) (a', (name', ttl', ns')) =
        ttl = ttl' && Domain_name.equal name name' && Domain_name.Set.equal ns ns' &&
        Umap.equal_b a a'
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let sn = Domain_name.Set.singleton
  let ip = Ipaddr.V4.of_string_exn

  let ins_zone name soa ttl ns t =
    insert name Umap.Ns (ttl, ns)
      (insert name Umap.Soa (soa.Soa.minimum, soa) t)

  let simple () =
    Alcotest.(check (result l_ok e)
                "lookup for root returns NotAuthoritative"
                (Error `NotAuthoritative)
                (lookupb Domain_name.root Udns_enum.A empty)) ;
    let soa = {
      Soa.nameserver = n_of_s "a" ; hostmaster = n_of_s "hs" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t = ins_zone Domain_name.root soa 6l (sn (n_of_s "a")) empty in
    Alcotest.(check (result l_ok e) "lookup for .com is NoDomain"
                (Error (`NotFound (Domain_name.root, (4l, soa))))
                (lookupb (n_of_s "com") Udns_enum.A t)) ;
    Alcotest.(check (result l_ok e) "lookup for SOA . is SOA"
                (Ok (Umap.B (Umap.Soa, (4l, soa)),
                     (Domain_name.root, 6l, sn (n_of_s "a"))))
                (lookupb Domain_name.root Udns_enum.SOA t)) ;
    let a_record = (23l, Umap.Ipv4_set.singleton (ip "1.4.5.2")) in
    let t = insert (n_of_s "foo.com") Umap.A a_record t in
    Alcotest.(check (result l_ok e) "lookup for A foo.com is A"
                (Ok (Umap.B (Umap.A, a_record),
                     (Domain_name.root, 6l, sn (n_of_s "a"))))
                (lookupb (n_of_s "foo.com") Udns_enum.A t)) ;
    Alcotest.(check (result l_ok e) "lookup for SOA com is ENT"
                (Error (`EmptyNonTerminal (Domain_name.root, (4l, soa))))
                (lookupb (n_of_s "com") Udns_enum.SOA t)) ;
    Alcotest.(check (result l_ok e) "lookup for SOA foo.com is NoDomain"
                (Error (`EmptyNonTerminal (Domain_name.root, (4l, soa))))
                (lookupb (n_of_s "foo.com") Udns_enum.SOA t))

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
                (lookupb (n_of_s "bar.com") Udns_enum.SOA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for SOA foo.com (after insert) is good"
                (Ok (Umap.B (Umap.Soa, (4l, soa)),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookupb (n_of_s "foo.com") Udns_enum.SOA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for NS foo.com (after insert) is good"
                (Ok (Umap.B (Umap.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookupb (n_of_s "foo.com") Udns_enum.NS t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", (4l, soa))))
                (lookupb (n_of_s "foo.com") Udns_enum.AAAA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for A foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", (4l, soa))))
                (lookupb (n_of_s "foo.com") Udns_enum.A t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", (4l, soa))))
                (lookupb (n_of_s "foo.com") Udns_enum.MX t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for MX bar.foo.com (after insert) is NoDomain"
                (Error (`NotFound (n_of_s "foo.com", (4l, soa))))
                (lookupb (n_of_s "bar.foo.com") Udns_enum.MX t)) ;
    let a_record = (12l, Umap.Ipv4_set.singleton (ip "1.2.3.4")) in
    let t = insert (n_of_s "foo.com") Umap.A a_record t in
    Alcotest.(check (result l_ok e)
                "lookup for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", (4l, soa))))
                (lookupb (n_of_s "foo.com") Udns_enum.AAAA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for A foo.com (after insert) is Found"
                (Ok (Umap.B (Umap.A, a_record),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookupb (n_of_s "foo.com") Udns_enum.A t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", (4l, soa))))
                (lookupb (n_of_s "foo.com") Udns_enum.MX t)) ;
    let t = remove (n_of_s "foo.com") Udns_enum.A t in
    Alcotest.(check (result l_ok e)
                "lookup for A foo.com (after insert and remove) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", (4l, soa))))
                (lookupb (n_of_s "foo.com") Udns_enum.A t)) ;
    let t = remove (n_of_s "foo.com") Udns_enum.ANY t in
    Alcotest.(check (result l_ok e)
                "lookup for SOA foo.com (after remove) is NotAuthoritative"
                (Error `NotAuthoritative)
                (lookupb (n_of_s "foo.com") Udns_enum.SOA t))

  let alias () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    let t = insert (n_of_s "bar.foo.com") Umap.Cname (14l, n_of_s "foo.bar.com") t in
    Alcotest.(check (result l_ok e)
                "lookup for SOA bar.foo.com (after insert) is good"
                (Ok (Umap.B (Umap.Cname, (14l, n_of_s "foo.bar.com")),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookupb (n_of_s "bar.foo.com") Udns_enum.SOA t))

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
                (Ok (Umap.B (Umap.Soa, (4l, soa)),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookupb (n_of_s "foo.com") Udns_enum.SOA t)) ;
    Alcotest.(check (result l_ok e)
                "lookup for NS foo.com (after insert) is good"
                (Ok (Umap.B (Umap.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookupb (n_of_s "foo.com") Udns_enum.NS t)) ;
    let t = insert (n_of_s "bar.foo.com") Umap.Ns (12l, sn (n_of_s "ns3.bar.com")) t in
    Alcotest.(check (result l_ok e) "lookup for A bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookupb (n_of_s "bar.foo.com") Udns_enum.A t)) ;
    Alcotest.(check (result l_ok e) "lookup for NS foo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookupb (n_of_s "foo.bar.foo.com") Udns_enum.NS t)) ;
    Alcotest.(check (result l_ok e) "lookup for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookupb (n_of_s "foobar.boo.bar.foo.com") Udns_enum.AAAA t)) ;
    let t = ins_zone (n_of_s "a.b.bar.foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) t in
    Alcotest.(check (result l_ok e) "lookup for NS a.b.bar.foo.com is ns1.foo.com"
                (Ok (Umap.B (Umap.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "a.b.bar.foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookupb (n_of_s "a.b.bar.foo.com") Udns_enum.NS t)) ;
    Alcotest.(check (result l_ok e) "lookup for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookupb (n_of_s "foobar.boo.bar.foo.com") Udns_enum.AAAA t))

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
                (Ok (Umap.B (Umap.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookupb (n_of_s "foo.com") Udns_enum.NS t))) ;
    let t' = remove_zone (n_of_s "foo.com") t in
    Alcotest.(check (result b_ok e) "lookup for NS foo.com after removing zone is notauthoritative"
                (Error `NotAuthoritative)
                (r_fst (lookupb (n_of_s "foo.com") Udns_enum.NS t'))) ;
    let t =
      ins_zone (n_of_s "bar.foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) t
    in
    Alcotest.(check (result b_ok e) "lookup for NS bar.foo.com is good"
                (Ok (Umap.B (Umap.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookupb (n_of_s "bar.foo.com") Udns_enum.NS t))) ;
    Alcotest.(check (result b_ok e) "lookup for NS foo.com is good"
                (Ok (Umap.B (Umap.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookupb (n_of_s "foo.com") Udns_enum.NS t))) ;
    let t' = remove_zone (n_of_s "foo.com") t in
    Alcotest.(check (result b_ok e) "lookup for NS bar.foo.com is good (after foo.com is removed)"
                (Ok (Umap.B (Umap.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookupb (n_of_s "bar.foo.com") Udns_enum.NS t'))) ;
    Alcotest.(check (result b_ok e) "lookup for NS foo.com is not authoritative"
                (Error `NotAuthoritative)
                (r_fst (lookupb (n_of_s "foo.com") Udns_enum.NS t'))) ;
    let t' = remove_zone (n_of_s "bar.foo.com") t in
    Alcotest.(check (result b_ok e) "lookup for NS bar.foo.com is not authoritative"
                (Error (`NotFound (n_of_s "foo.com", (4l, soa))))
                (r_fst (lookupb (n_of_s "bar.foo.com") Udns_enum.NS t'))) ;
    Alcotest.(check (result b_ok e) "lookup for NS foo.com is good"
                (Ok (Umap.B (Umap.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookupb (n_of_s "foo.com") Udns_enum.NS t')))


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
