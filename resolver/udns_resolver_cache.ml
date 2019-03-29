(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

open Udns_resolver_entry

module V = struct
  type entry = int64 * rank * res
  type t = All of entry | Entries of entry Udns_enum.RRMap.t

  let weight = function
    | All _ -> 1
    | Entries tm -> Udns_enum.RRMap.cardinal tm

  let pp_entry ppf (crea, rank, res) =
    Fmt.pf ppf "%a %Lu %a" pp_rank rank crea pp_res res

  let pp ppf = function
    | All e -> Fmt.pf ppf "all %a" pp_entry e
    | Entries tm ->
      Fmt.pf ppf "entries: %a"
        Fmt.(list ~sep:(unit ";@,") (pair Udns_enum.pp_rr_typ pp_entry))
        (Udns_enum.RRMap.bindings tm)
end

module LRU = Lru.F.Make(Domain_name)(V)

type t = LRU.t

type stats = {
  hit : int ;
  miss : int ;
  drop : int ;
  insert : int ;
}

let s = ref { hit = 0 ; miss = 0 ; drop = 0 ; insert = 0 }

let pp_stats pf s =
  Fmt.pf pf "cache: %d hits %d misses %d drops %d inserts" s.hit s.miss s.drop s.insert

let stats () = !s

(* this could be improved:
   lookup : t -> Domain_name.t -> Udns_enum.rr_typ -> int64 ->
            (Dns_map.B, [ `NoErr | `NoDom | `ServFail | `Timeout ]) result

   a bit more types for Dns_map (by providing some more type parameters)

   or ask someone who knows more about GADT to help me fixing that data
   structure properly. *)

let empty = LRU.empty

let items = LRU.items

let capacity = LRU.capacity

let pp = LRU.pp Fmt.(pair ~sep:(unit ": ") Domain_name.pp V.pp)

module N = Domain_name.Set

let update_res created ts res =
  let used = Int32.of_int (Duration.to_sec (Int64.sub ts created)) in
  decrease_ttl used res

let cached t ts typ nam =
  match LRU.find nam t with
  | None ->
    s := { !s with miss = succ !s.miss } ;
    Error `Cache_miss
  | Some (V.All (created, _, res), t) ->
    begin match update_res created ts res with
      | None ->
        s := { !s with drop = succ !s.drop } ;
        Error `Cache_drop
      | Some r ->
        s := { !s with hit = succ !s.hit } ;
        Ok (r, t)
    end
  | Some (V.Entries tm, t) ->
    match Udns_enum.RRMap.find typ tm with
    | exception Not_found ->
      s := { !s with miss = succ !s.miss } ;
      Error `Cache_miss
    | (created, _, res) ->
      match update_res created ts res with
      | None ->
        s := { !s with drop = succ !s.drop } ;
        Error `Cache_drop
      | Some r ->
        s := { !s with hit = succ !s.hit } ;
        Ok (r, t)

(* according to RFC1035, section 7.3, a TTL of a week is a good maximum value! *)
(* XXX: we may want to define a minimum as well (5 minutes? 30 minutes?
   use SOA expiry?) MS used to use 24 hours in internet explorer

from RFC1034 on this topic:
The idea is that if cached data is known to come from a particular zone,
and if an authoritative copy of the zone's SOA is obtained, and if the
zone's SERIAL has not changed since the data was cached, then the TTL of
the cached data can be reset to the zone MINIMUM value if it is smaller.
This usage is mentioned for planning purposes only, and is not
recommended as yet.

and 2308, Sec 4:
   Despite being the original defined meaning, the first of these, the
   minimum TTL value of all RRs in a zone, has never in practice been
   used and is hereby deprecated.

and 1035 6.2:
   The MINIMUM value in the SOA should be used to set a floor on the TTL of data
   distributed from a zone.  This floor function should be done when the data is
   copied into a response.  This will allow future dynamic update protocols to
   change the SOA MINIMUM field without ambiguous semantics.
*)
let week = Int32.of_int Duration.(to_sec (of_day 7))

let smooth_ttl = smooth_ttl week

let maybe_insert typ nam ts rank res t =
  let add_entry tm t =
    let full = (ts, rank, smooth_ttl res) in
    let v = match typ, res with
      | Udns_enum.CNAME, _ -> V.All full
      | _, NoDom _ -> V.All full
      | _, _ -> V.Entries (Udns_enum.RRMap.add typ full tm)
    in
    s := { !s with insert = succ !s.insert } ;
    LRU.add nam v t
  in
  let add_if_ranked_higher (ts', rank', res') tm t =
    match update_res ts' ts res', compare_rank rank' rank with
    | Some _, `Bigger -> t
    | _ -> add_entry tm t
  in
  match LRU.find ~promote:false nam t with
  | None -> add_entry Udns_enum.RRMap.empty t
  | Some (V.All triple, t) -> add_if_ranked_higher triple Udns_enum.RRMap.empty t
  | Some (V.Entries tm, t) -> match Udns_enum.RRMap.find typ tm with
    | exception Not_found -> add_entry tm t
    | triple -> add_if_ranked_higher triple tm t

let resolve_ns t ts name =
  match cached t ts Udns_enum.A name with
  | Error _ -> `NeedA name, t
  | Ok (NoErr Umap.(B (k, v) as b), t) ->
    begin
      match k, v with
      | Umap.A, (_, ips) -> `HaveIPS ips, t
      | Umap.Cname, (_, alias) ->
        Logs.warn
          (fun m -> m "resolve_ns: asked for A record of NS %a, got cname %a"
              Domain_name.pp name Domain_name.pp alias) ;
        `NeedCname alias, t
      | _ ->
        Logs.warn (fun m -> m "resolve_ns: ignoring %a (looked A %a)"
                      Umap.pp_b b Domain_name.pp name) ;
        `NeedA name, t
    end
  | Ok (NoDom _, t) ->
    Logs.warn (fun m -> m "resolve_ns: NoDom, cache lookup for %a"
                  Domain_name.pp name) ;
    `NoDom, t
  | Ok (r, t) ->
    Logs.warn (fun m -> m "resolve_ns: No, cache lookup for %a is %a"
                  Domain_name.pp name pp_res r) ;
    `No, t

let find_ns t rng ts stash name =
  let pick = function
    | [] -> None
    | [ x ] -> Some x
    | xs -> Some (List.nth xs (Randomconv.int ~bound:(List.length xs) rng))
  in
  match cached t ts Udns_enum.NS name with
  | Error _ -> `NeedNS, t
  | Ok (NoErr Umap.(B (k, v) as b), t) ->
    (* TODO test case -- we can't pick right now, unfortunately
       the following setup is there in the wild:
       berliner-zeitung.de NS 1.ns.berlinonline.de, 2.ns.berlinonline.de, x.ns.berlinonline.de
       berlinonline.de NS 1.ns.berlinonline.net, 2.ns.berlinonline.net, dns-berlinonline-de.unbelievable-machine.net
       berlinonline.net NS 2.ns.berlinonline.de, x.ns.berlinonline.de, 1.ns.berlinonline.de.
       --> all delivered without glue *)
    begin match k, v with
      | Umap.Ns, (_, ns) ->
        begin
          let actual = Domain_name.Set.diff ns stash in
          match pick (Domain_name.Set.elements actual) with
          | None ->
            Logs.warn (fun m -> m "find_ns: couldn't take any name from %a (stash: %a), returning loop"
                          Fmt.(list ~sep:(unit ",@ ") Domain_name.pp) (Domain_name.Set.elements ns)
                          Fmt.(list ~sep:(unit ",@ ") Domain_name.pp) (Domain_name.Set.elements stash)) ;
            `Loop, t
          | Some nsname ->
            (* tricky conditional:
               foo.com NS ns1.foo.com ; ns1.foo.com CNAME ns1.bar.com (well, may not happen ;)
               foo.com NS ns1.foo.com -> NeedGlue foo.com *)
            match resolve_ns t ts nsname with
            | `NeedA aname, t when Domain_name.sub ~subdomain:aname ~domain:name -> `NeedGlue name, t
            | `NeedCname cname, t -> `NeedA cname, t
            | `HaveIPS ips, t ->
              (* TODO should use a non-empty list of ips here *)
              begin match pick (Umap.Ipv4_set.elements ips) with
                | None -> `NeedA nsname, t
                | Some ip -> `HaveIP ip, t
              end
            | `NeedA aname, t -> `NeedA aname, t
            | `No, t -> `No, t
            | `NoDom, t -> `NoDom, t
        end
      | Umap.Cname, (_, alias) -> `Cname alias, t (* foo.com CNAME bar.com case *)
      | _ ->
        Logs.err (fun m -> m "find_ns: looked for NS %a, but got %a"
                     Domain_name.pp name Umap.pp_b b) ;
        `No, t
    end
  | Ok (_, t) -> `No, t


let find_nearest_ns rng ts t name =
  let pick = function
    | [] -> None
    | [ x ] -> Some x
    | xs -> Some (List.nth xs (Randomconv.int ~bound:(List.length xs) rng))
  in
  let root =
    match pick (snd (List.split Udns_resolver_root.root_servers)) with
    | None -> invalid_arg "not possible"
    | Some ip -> ip
  in
  let find_ns name = match cached t ts Udns_enum.NS name with
    | Ok (NoErr Umap.(B (Ns, (_, names))), _) -> Domain_name.Set.elements names
    | _ -> []
  and find_a name = match cached t ts Udns_enum.A name with
    | Ok (NoErr Umap.(B (A, (_, ips))), _) -> Umap.Ipv4_set.elements ips
    | _ -> []
  in
  let rec go nam =
    if Domain_name.equal nam Domain_name.root then
      `HaveIP (Domain_name.root, root)
    else match pick (find_ns nam) with
      | None -> go (Domain_name.drop_labels_exn nam)
      | Some ns -> match pick (find_a ns) with
        | None ->
          if Domain_name.sub ~subdomain:ns ~domain:nam then
            (* we actually need glue *)
            go (Domain_name.drop_labels_exn nam)
          else
            `NeedA ns
        | Some ip -> `HaveIP (nam, ip)
  in
  go name

(* below fails for cafe-blaumond.de, somewhere stuck in an zone hop:
    querying a.b.c.d.e.f, getting NS for d.e.f + A
     still no entry for e.f -> retrying same question all the time
  let rec go cur rest zone ip =
    (* if we find a NS, and an A record, go down *)
    (* if we find a NS, and no A record, needa *)
    (* if we get error, finish with what we have *)
    (* if we find nodom, nodata -> finish with what we have *)
    (* servfail returns an error *)
    Logs.debug (fun m -> m "nearest ns cur %a rest %a zone %a ip %a"
                   Domain_name.pp cur
                   Fmt.(list ~sep:(unit ".") string) rest
                   Domain_name.pp zone
                   Ipaddr.V4.pp_hum ip) ;
    match pick find_ns cur with
    | None -> `HaveIP (zone, ip)
    | Some ns -> begin match pick find_a ns with
      | None -> `NeedA ns
      | Some ip -> match rest with
        | [] -> `HaveIP (cur, ip)
        | hd::tl -> go (Domain_name.prepend_Exn cur hd) tl cur ip
        end
  in
  go Domain_name.root (List.rev (Domain_name.to_strings name)) Domain_name.root root
*)

let resolve t ~rng ts name typ =
  (* the standard recursive algorithm *)
  let rec go t typ name =
    Logs.debug (fun m -> m "go %a" Domain_name.pp name) ;
    match find_nearest_ns rng ts t name with
    | `NeedA ns -> go t Udns_enum.A ns
    | `HaveIP (zone, ip) -> Ok (zone, name, typ, ip, t)
  in
  go t typ name

let _resolve t ~rng ts name typ =
  (* TODO return the bailiwick (zone the NS is responsible for) as well *)
  (* TODO this is the query name minimisation approach, reimplement the
          original recursive algorithm as well *)
  (* the top-to-bottom approach, for TYP a.b.c, lookup:
     @root NS, . -> A1
     @A1 NS, c -> A2
     @A2 NS, b.c -> A3
     @A3 NS. a.b.c -> NoData
     @A3 TYP, a.b.c -> A4

     where A{1-3} are all domain names, where we try to find A records (or hope
     to get them as glue)

     now, we have the issue of glue records: NS c (A2) will return names x.c
     and y.c, but also address records for them (otherwise there's no way to
     find out their addresses without knowing their addresses)

     A2 may as well contain a.c, b.c, and c.d - if delivered without glue, c.d
     is the only option to proceed (well, or ServFail or asking someone else for
     NS c) *)
  (* goal is to find the query to send out.
     we're applying qname minimisation on the way down

     it's a bit complicated, OTOH we're doing qname minimisation, but also may
     have to jump to other names (of NS or CNAME) - which is slightly intricate *)
  (* TODO this is misplaced, this should be properly handled by find_ns! *)
  let root =
    let roots = snd (List.split Udns_resolver_root.root_servers) in
    List.nth roots (Randomconv.int ~bound:(List.length roots) rng)
  in
  let rec go t stash typ cur rest zone ip =
    Logs.debug (fun m -> m "resolve entry: stash %a typ %a cur %a rest %a zone %a ip %a"
                   Fmt.(list ~sep:(unit ", ") Domain_name.pp) (N.elements stash)
                   Udns_enum.pp_rr_typ typ Domain_name.pp cur
                   Domain_name.pp (Domain_name.of_strings_exn ~hostname:false rest)
                   Domain_name.pp zone
                   Ipaddr.V4.pp ip) ;
    match find_ns t rng ts stash cur with
    | `NeedNS, t when Domain_name.equal cur Domain_name.root ->
      (* we don't have any root servers *)
      Ok (Domain_name.root, Domain_name.root, Udns_enum.NS, root, t)
    | `HaveIP ip, t ->
      Logs.debug (fun m -> m "resolve: have ip %a" Ipaddr.V4.pp ip) ;
      begin match rest with
        | [] -> Ok (zone, cur, typ, ip, t)
        | hd::tl -> go t stash typ (Domain_name.prepend_exn cur hd) tl zone ip
      end
    | `NeedNS, t ->
      Logs.debug (fun m -> m "resolve: needns") ;
      Ok (zone, cur, Udns_enum.NS, ip, t)
    | `Cname name, t ->
      (* NS name -> CNAME foo, only use foo if rest is empty *)
      Logs.debug (fun m -> m "resolve: cname %a" Domain_name.pp name) ;
      begin match rest with
        | [] ->
          let rest = List.rev (Domain_name.to_strings name) in
          go t (N.add name stash) typ Domain_name.root rest Domain_name.root root
        | hd::tl ->
          go t stash typ (Domain_name.prepend_exn cur hd) tl zone ip
      end
    | `NoDom, _ ->
      (* this is wrong for NS which NoDom for too much (even if its a ENT) *)
      Logs.debug (fun m -> m "resolve: nodom to %a!" Domain_name.pp cur) ;
      Error "can't resolve"
    | `No, _ ->
      Logs.debug (fun m -> m "resolve: no to %a!" Domain_name.pp cur) ;
      (* we tried to locate the NS for cur, but failed to find it *)
      (* it was ServFail/NoData in our cache.  how can we proceed? *)
      (* - ask the very same question to ips (NS / cur) - but we need to stop at some point *)
      (* - if rest = [], we just ask for cur+typ the ips --- this is common, e.g.
            ns1.foo.com NS @(foo.com authoritative)? - NoData, ns1.foo.com A @(foo.com authoritative) yay *)
      (* - if rest != [], (i.e. detectportal.firefox.com.edgesuite.net ->
               edgesuite.net -> NoData *)
      (* - give up!? *)
      (* this opens the door to amplification attacks :/ -- i.e. asking for
         a.b.c.d.e.f results in 6 requests (for f, e.f, d.e.f, c.d.e.f, b.c.d.e.f, a.b.c.d.e.f)  *)
      begin match rest with
        | [] -> Ok (zone, cur, typ, ip, t)
        | hd::tl -> go t stash typ (Domain_name.prepend_exn cur hd) tl zone ip
      end
    | `NeedGlue name, t ->
      Logs.debug (fun m -> m "resolve: needGlue %a" Domain_name.pp name) ;
      Ok (zone, name, Udns_enum.NS, ip, t)
    | `Loop, _ -> Error "resolve: cycle detected in find_ns"
    | `NeedA name, t ->
      Logs.debug (fun m -> m "resolve: needA %a" Domain_name.pp name) ;
      (* TODO: unclear whether this conditional is needed *)
      if N.mem name stash then begin
        Error "resolve: cycle detected during NeedA"
      end else
        let n = List.rev (Domain_name.to_strings name) in
        go t (N.add name stash) Udns_enum.A Domain_name.root n Domain_name.root root
  in
  go t (N.singleton name) typ Domain_name.root (List.rev (Domain_name.to_strings name)) Domain_name.root root

let follow_cname t ts typ name b =
  let rec follow t acc name Umap.(B (k, v) as b) =
    match k, v with
    | Umap.Cname, (_, alias) ->
      if Domain_name.Map.mem alias acc then begin
        Logs.debug (fun m -> m "follow_cname: cycle detected") ;
        `Cycle (acc, t)
      end else begin
        match cached t ts typ alias with
        | Error _ ->
          Logs.debug (fun m -> m "follow_cname: cache miss, need to query %a" Domain_name.pp alias) ;
          `Query (alias, t)
        | Ok (NoErr ans, t) ->
          Logs.debug (fun m -> m "follow_cname: noerr, follow again") ;
          follow t (Umap.add_entry alias ans acc) alias ans
        | Ok (NoDom (ttl, soa) as res, t) ->
          Logs.debug (fun m -> m "follow_cname: nodom") ;
          `NoDom ((acc, to_map res), t)
        | Ok (NoData (ttl, soa) as res, t) ->
          Logs.debug (fun m -> m "follow_cname: nodata") ;
          `NoData ((acc, to_map res), t)
        (* XXX: the last case here is not symmetric... the acc is dropped
           TODO: write tests and evaluate what we need (what clients expect) *)
        | Ok (ServFail (ttl, soa) as res, t) ->
          Logs.debug (fun m -> m "follow_cname: servfail") ;
          `ServFail (to_map res, t)
      end
    | _ -> `NoError (Umap.add_entry name b acc, t)
  in
  let initial = Umap.add_entry name b Domain_name.Map.empty in
  follow t initial name b

(*
let additionals t ts rrs =
  (* TODO: also AAAA *)
  N.fold (fun nam (acc, t) ->
      match cached t ts Udns_enum.A nam with
      | Ok (NoErr answers, t) -> answers @ acc, t
      | _ -> acc, t)
    (Udns_packet.rr_names rrs)
    ([], t)
*)

let answer t ts (name, typ) id =
  let packet t add rcode answer authority =
    (* TODO why is this RA + RD in here? should not be for recursive algorithm
         also, there should be authoritative... *)
    let flags = Packet.Header.FS.(add `Recursion_desired (singleton `Recursion_available)) in
    let header = { Packet.Header.id ; query = false ; operation = Udns_enum.Query ;
                   rcode ; flags }
    (* XXX: we should look for a fixpoint here ;) *)
    (*    and additional, t = if add then additionals t ts answer else [], t *)
    and query = Packet.Query.create ~answer ~authority (* ~additional *) (name, typ) in
    (header, `Query query, t)
  in
  match cached t ts typ name with
  | Error _ -> `Query (name, t)
  | Ok (NoDom (ttl, authority) as res, t) ->
    `Packet (packet t false Udns_enum.NXDomain Domain_name.Map.empty (to_map res))
  | Ok (NoData (ttl, authority) as res, t) ->
    `Packet (packet t false Udns_enum.NoError Domain_name.Map.empty (to_map res))
  | Ok (ServFail (ttl, authority) as res, t) ->
    `Packet (packet t false Udns_enum.ServFail Domain_name.Map.empty (to_map res))
  | Ok (NoErr answer as res, t) -> match typ with
    | Udns_enum.CNAME -> `Packet (packet t false Udns_enum.NoError (to_map res) Domain_name.Map.empty)
    | _ ->
      match follow_cname t ts typ name answer with
      | `NoError (answer, t) -> `Packet (packet t true Udns_enum.NoError answer Domain_name.Map.empty)
      | `Cycle (answer, t) -> `Packet (packet t true Udns_enum.NoError answer Domain_name.Map.empty)
      | `Query (n, t) -> `Query (n, t)
      | `NoDom ((answer, soa), t) -> `Packet (packet t true Udns_enum.NXDomain answer soa)
      | `NoData ((answer, soa), t) -> `Packet (packet t true Udns_enum.NoError answer soa)
      | `ServFail (soa, t) -> `Packet (packet t true Udns_enum.ServFail Domain_name.Map.empty soa)

let handle_query t ~rng ts q qid =
  match answer t ts q qid with
  | `Packet (hdr, pkt, t) -> `Answer (hdr, pkt), t
  | `Query (name, t) ->
    let r =
      match snd q with
      (* similar for TLSA, which uses _443._tcp.<name> (not a service name!) *)
      | Udns_enum.SRV when Domain_name.is_service name ->
        Ok (Domain_name.drop_labels_exn ~amount:2 name, Udns_enum.NS)
      | Udns_enum.SRV ->
        Logs.err (fun m -> m "requested SRV record %a, but not a service name"
                     Domain_name.pp name) ;
        Error ()
      | x -> Ok (name, x)
    in
    match r with
    | Error () -> `Nothing, t
    | Ok (qname, typ) ->
      match resolve t ~rng ts qname typ with
      | Error e ->
        Logs.err (fun m -> m "resolve returned error %s" e) ;
        `Nothing, t
      | Ok (zone, name', typ, ip, t) ->
        let name, typ =
          match Domain_name.equal name' qname, snd q with
          | true, Udns_enum.SRV -> name, Udns_enum.SRV
          | _ -> name', typ
        in
        Logs.debug (fun m -> m "resolve returned zone %a name %a typ %a, ip %a"
                       Domain_name.pp zone
                       Domain_name.pp name
                       Udns_enum.pp_rr_typ typ
                       Ipaddr.V4.pp ip) ;
        `Query (zone, name, typ, ip), t
