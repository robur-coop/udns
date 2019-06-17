(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Rresult
open R.Infix
open Dns

let src = Logs.Src.create "dns_server" ~doc:"DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

module IPM = Map.Make(Ipaddr.V4)

let guard p err = if p then Ok () else Error err

let guardf p err = if p then Ok () else Error (err ())

type proto = [ `Tcp | `Udp ]

module Authentication = struct

  type operation = [
    | `Update
    | `Transfer
  ]

  type a = Dns_trie.t -> proto -> ?key:[ `domain ] Domain_name.t -> operation -> zone:[ `domain ] Domain_name.t -> bool

  type t = Dns_trie.t * a list

  let operation_to_string = function
    | `Update -> "_update"
    | `Transfer -> "_transfer"

  let is_op op name =
    (* TODO should check that op is at the beginning? *)
    let arr = Domain_name.to_array name in
    Array.exists (String.equal (operation_to_string op)) arr

  let find_zone_ips name =
    (* the name of a key is primaryip.secondaryip._transfer.zone
       e.g. 192.168.42.2.192.168.42.1._transfer.mirage
       alternative: <whatever>.primaryip._transfer.zone *)
    let arr = Domain_name.to_array name in
    let transfer = operation_to_string `Transfer in
    try
      let rec go idx = if Array.get arr idx = transfer then idx else go (succ idx) in
      let zone_idx = go 0 in
      let zone = Domain_name.of_array (Array.sub arr 0 zone_idx) in
      let start = succ zone_idx in
      let ip start =
        try
          let subarr = Array.sub arr start 4 in
          let host = Domain_name.of_array subarr in
          match Ipaddr.V4.of_string (Domain_name.to_string host) with
          | Error _ -> None
          | Ok ip -> Some ip
        with Invalid_argument _ -> None
      in
      match ip (start + 4), ip start with
      | _, None -> None
      | None, Some ip -> Some (zone, ip, None)
      | Some primary, Some secondary -> Some (zone, primary, Some secondary)
    with Invalid_argument _ -> None

  let find_ns s (trie, _) zone =
    let accumulate name _ acc =
      let matches_zone z = Domain_name.(equal z root || equal z zone) in
      match find_zone_ips name, s with
      | None, _ -> acc
      | Some (z, prim, _), `P when matches_zone z-> (name, prim) :: acc
      | Some (z, _, Some sec), `S when matches_zone z -> (name, sec) :: acc
      | Some _, _ -> acc
    in
    Dns_trie.fold Rr_map.Dnskey trie accumulate []

  let secondaries t zone = find_ns `S t zone

  let primaries t zone = find_ns `P t zone

  let all_operations =
    List.map operation_to_string [ `Update ; `Transfer ]

  let zone name =
    let arr = Domain_name.to_array name in
    let len = Array.length arr in
    let rec go idx =
      if idx = len then
        len
      else if List.exists (String.equal (Array.get arr idx)) all_operations then
        idx
      else
        go (succ idx)
    in
    let zidx = go 0 in
    Domain_name.(host_exn (of_array (Array.sub arr 0 zidx)))

  let soa name =
    let nameserver = Domain_name.(host_exn (prepend_label_exn name "ns"))
    and hostmaster = Domain_name.prepend_label_exn name "hostmaster"
    in
    { Soa.nameserver ; hostmaster ; serial = 0l ; refresh = 16384l ;
      retry = 2048l ; expiry = 1048576l ; minimum = 300l }

  let add_keys trie name keys =
    let zone = zone name in
    let soa =
      match Dns_trie.lookup zone Rr_map.Soa trie with
      | Ok soa -> { soa with Soa.serial = Int32.succ soa.Soa.serial }
      | Error _ -> soa zone
    in
    let keys' = match Dns_trie.lookup name Rr_map.Dnskey trie with
      | Error _ -> keys
      | Ok (_, dnskeys) ->
        Log.warn (fun m -> m "replacing Dnskeys (name %a, present %a, add %a)"
                     Domain_name.pp name
                     Fmt.(list ~sep:(unit ",") Dnskey.pp)
                     (Rr_map.Dnskey_set.elements dnskeys)
                     Fmt.(list ~sep:(unit ";") Dnskey.pp)
                     (Rr_map.Dnskey_set.elements keys) ) ;
        keys
    in
    let trie' = Dns_trie.insert zone Rr_map.Soa soa trie in
    Dns_trie.insert name Rr_map.Dnskey (0l, keys') trie'

  let of_keys keys =
    List.fold_left (fun trie (name, key) ->
        add_keys trie name (Rr_map.Dnskey_set.singleton key))
      Dns_trie.empty keys

  let find_key t name =
    match Dns_trie.lookup name Rr_map.Dnskey (fst t) with
    | Ok (_, keys) ->
      if Rr_map.Dnskey_set.cardinal keys = 1 then
        Some (Rr_map.Dnskey_set.choose keys)
      else begin
        Log.warn (fun m -> m "found multiple (%d) keys for %a"
                     (Rr_map.Dnskey_set.cardinal keys)
                     Domain_name.pp name) ;
        None
      end
    | Error e ->
      Log.warn (fun m -> m "error %a while looking up key %a" Dns_trie.pp_e e
                   Domain_name.pp name) ;
      None

  let tsig_auth _ _ ?key op ~zone =
    match key with
    | None -> false
    | Some subdomain ->
      let op_string = operation_to_string op in
      let root = Domain_name.of_string_exn op_string
      and zone = Domain_name.prepend_label_exn zone op_string
      in
      Domain_name.sub ~subdomain ~domain:zone
      || Domain_name.sub ~subdomain ~domain:root

  let authorise (data, authorised) proto ?key ~zone operation =
    List.exists (fun a -> a data proto ?key operation ~zone) authorised
end

type t = {
  data : Dns_trie.t ;
  auth : Authentication.t ;
  rng : int -> Cstruct.t ;
  tsig_verify : Tsig_op.verify ;
  tsig_sign : Tsig_op.sign ;
}

let text name data =
  match Dns_trie.entries name data with
  | Error e ->
    Error (`Msg (Fmt.strf "text: couldn't find zone %a: %a" Domain_name.pp name Dns_trie.pp_e e))
  | Ok (soa, map) ->
    let buf = Buffer.create 1024 in
    let origin, default_ttl =
      Buffer.add_string buf
        ("$ORIGIN " ^ Domain_name.to_string ~trailing:true name ^ "\n") ;
      let ttl = soa.minimum in
      Buffer.add_string buf
        ("$TTL " ^ Int32.to_string ttl ^ "\n") ;
      name, ttl
    in
    Buffer.add_string buf (Rr_map.text ~origin ~default_ttl name Soa soa) ;
    Buffer.add_char buf '\n' ;
    let out map =
      Domain_name.Map.iter (fun name rrs ->
          Rr_map.iter (fun b ->
              Buffer.add_string buf (Rr_map.text_b ~origin ~default_ttl name b) ;
              Buffer.add_char buf '\n')
            rrs)
        map
    in
    let is_special name _ =
      (* if only domain-name had proper types *)
      let arr = Domain_name.to_array name in
      match Array.get arr (pred (Array.length arr)) with
      | exception Invalid_argument _ -> false
      | lbl -> try String.get lbl 0 = '_' with Not_found -> false
    in
    let service, entries = Domain_name.Map.partition is_special map in
    out entries ;
    Buffer.add_char buf '\n' ;
    out service ;
    Ok (Buffer.contents buf)

let create ?(tsig_verify = Tsig_op.no_verify) ?(tsig_sign = Tsig_op.no_sign) data auth rng =
  { data ; auth ; rng ; tsig_verify ; tsig_sign }

let find_glue trie names =
  Domain_name.Host_set.fold (fun name map ->
      match
        match Dns_trie.lookup_glue name trie with
        | Some v4, Some v6 -> Some Rr_map.(add A v4 (singleton Aaaa v6))
        | Some v4, None -> Some (Rr_map.singleton A v4)
        | None, Some v6 -> Some (Rr_map.singleton Aaaa v6)
        | None, None -> None
      with
      | None -> map
      | Some rrs -> Domain_name.Map.add (Domain_name.domain name) rrs map)
    names Domain_name.Map.empty

let authoritative =
  (* TODO should copy recursion desired *)
  Packet.Flags.singleton `Authoritative

let err_flags = function
  | Rcode.NotAuth -> Packet.Flags.empty
  | _ -> authoritative

let lookup trie (name, typ) =
  (* TODO: should randomize answers + ad? *)
  let r = match typ with
    | `Any -> Dns_trie.lookup_any name trie
    | `K (Rr_map.K k) -> match Dns_trie.lookup_with_cname name k trie with
      | Ok (B (k, v), au) -> Ok (Rr_map.singleton k v, au)
      | Error e -> Error e
  in
  match r with
  | Ok (an, (au, ttl, ns)) ->
    let answer = Domain_name.Map.singleton name an in
    let authority =
      Name_rr_map.remove_sub (Name_rr_map.singleton au Ns (ttl, ns)) answer
    in
    let additional =
      let names =
        Rr_map.(fold (fun (B (k, v)) s -> Domain_name.Host_set.union (names k v) s) an ns)
      in
      Name_rr_map.remove_sub
        (Name_rr_map.remove_sub (find_glue trie names) answer)
        authority
    in
    Ok (authoritative, (answer, authority), Some additional)
  | Error (`Delegation (name, (ttl, ns))) ->
    let authority = Name_rr_map.singleton name Ns (ttl, ns) in
    Ok (Packet.Flags.empty, (Name_rr_map.empty, authority), Some (find_glue trie ns))
  | Error (`EmptyNonTerminal (zname, soa)) ->
    let authority = Name_rr_map.singleton zname Soa soa in
    Ok (authoritative, (Name_rr_map.empty, authority), None)
  | Error (`NotFound (zname, soa)) ->
    let authority = Name_rr_map.singleton zname Soa soa in
    Error (Rcode.NXDomain, Some (Name_rr_map.empty, authority))
  | Error `NotAuthoritative -> Error (Rcode.NotAuth, None)

let authorise_zone_transfer auth proto key zone =
  guardf (proto = `Tcp) (fun () ->
      Log.err (fun m -> m "refusing zone transfer of %a via UDP" Domain_name.pp zone);
      Rcode.Refused) >>= fun () ->
  guardf (Authentication.authorise auth proto ?key ~zone `Transfer) (fun () ->
      Log.err (fun m -> m "refusing unauthorised zone transfer of %a" Domain_name.pp zone) ;
      Rcode.NotAuth)

let axfr t proto key ((zone, _) as question) =
  authorise_zone_transfer t.auth proto key zone >>= fun () ->
  match Dns_trie.entries zone t.data with
  | Ok (soa, entries) ->
    Log.info (fun m -> m "transfer key %a authorised for AXFR %a"
                 Fmt.(option ~none:(unit "none") Domain_name.pp) key
                 Packet.Question.pp question);
    Ok (soa, entries)
  | Error e ->
    Log.err (fun m -> m "AXFR attempted on %a, where we're not authoritative %a"
                Domain_name.pp zone Dns_trie.pp_e e);
    Error Rcode.NotAuth

module IM = Map.Make(Int32)

let find_trie m name serial =
  match Domain_name.Map.find name m with
  | None -> None
  | Some m' -> IM.find_opt serial m'

let ixfr t m proto key ((zone, _) as question) soa =
  authorise_zone_transfer t.auth proto key zone >>= fun () ->
  Log.info (fun m -> m "transfer key %a authorised for IXFR %a"
               Fmt.(option ~none:(unit "none") Domain_name.pp) key
               Packet.Question.pp question);
  let old = match find_trie m zone soa.Soa.serial with
    | None -> Dns_trie.empty
    | Some old -> old
  in
  match Dns_trie.diff zone soa ~old t.data with
  | Ok ixfr -> Ok ixfr
  | Error (`Msg msg) ->
    Log.err (fun m -> m "IXFR attempted on %a, where diff failed with %s"
                Domain_name.pp zone msg);
    Error Rcode.NotAuth

let safe_decode buf =
  match Packet.decode buf with
  | Error e ->
    Logs.err (fun m -> m "error %a while decoding, giving up" Packet.pp_err e);
    Error Rcode.FormErr
(*  | Error `Partial ->
    Log.err (fun m -> m "partial frame (length %d)@.%a" (Cstruct.len buf) Cstruct.hexdump_pp buf) ;
    Packet.create <<no header>> <<no question>> Dns_enum.FormErr
  | Error (`Bad_edns_version i) ->
    Log.err (fun m -> m "bad edns version error %u while decoding@.%a"
                 i Cstruct.hexdump_pp buf) ;
    Error Dns_enum.BadVersOrSig
  | Error (`Not_implemented (off, msg)) ->
    Log.err (fun m -> m "not implemented at %d: %s while decoding@.%a"
                off msg Cstruct.hexdump_pp buf) ;
    Error Dns_enum.NotImp
  | Error e ->
    Log.err (fun m -> m "error %a while decoding@.%a"
                 Packet.pp_err e Cstruct.hexdump_pp buf) ;
    Error Dns_enum.FormErr *)
  | Ok v -> Ok v

let handle_question t (name, typ) =
  (* TODO white/blacklist of allowed qtypes? what about ANY and UDP? *)
  match typ with
  (* this won't happen, decoder constructs `Axfr *)
  | `Axfr | `Ixfr -> Error (Rcode.NotImp, None)
  | (`K _ | `Any) as k -> lookup t.data (name, k)
(*  | r ->
    Log.err (fun m -> m "refusing query type %a" Rr.pp r) ;
    Error (Rcode.Refused, None) *)

(* this implements RFC 2136 Section 2.4 + 3.2 *)
let handle_rr_prereq name trie = function
  | Packet.Update.Name_inuse ->
    begin match Dns_trie.lookup name A trie with
      | Ok _ | Error (`EmptyNonTerminal _) -> Ok ()
      | _ -> Error Rcode.NXDomain
    end
  | Packet.Update.Exists (K typ) ->
    begin match Dns_trie.lookup name typ trie with
      | Ok _ -> Ok ()
      | _ -> Error Rcode.NXRRSet
    end
  | Packet.Update.Not_name_inuse ->
    begin match Dns_trie.lookup name A trie with
      | Error (`NotFound _) -> Ok ()
      | _ -> Error Rcode.YXDomain
    end
  | Packet.Update.Not_exists (K typ) ->
    begin match Dns_trie.lookup name typ trie with
      | Error (`EmptyNonTerminal _ | `NotFound _) -> Ok ()
      | _ -> Error Rcode.YXRRSet
    end
  | Packet.Update.Exists_data Rr_map.(B (k, v)) ->
    match Dns_trie.lookup name k trie with
    | Ok v' when Rr_map.equal_rr k v v' -> Ok ()
    | _ -> Error Rcode.NXRRSet

(* RFC 2136 Section 2.5 + 3.4.2 *)
(* we partially ignore 3.4.2.3 and 3.4.2.4 by not special-handling of NS, SOA *)
let handle_rr_update name trie = function
  | Packet.Update.Remove (K typ) ->
    begin match typ with
      | Soa ->
        (* this does not follow 2136, but we want to be able to remove a zone *)
        Dns_trie.remove_zone name trie
      | _ -> Dns_trie.remove_ty name typ trie
    end
  | Packet.Update.Remove_all -> Dns_trie.remove_all name trie
  | Packet.Update.Remove_single Rr_map.(B (k, v)) -> Dns_trie.remove name k v trie
  | Packet.Update.Add Rr_map.(B (k, add)) ->
    (* turns out, RFC 2136, 3.4.2.2 says "SOA with smaller or equal serial is silently ignored" *)
    (* here we allow arbitrary, even out-of-zone updates.  this is
       crucial for the resolver operation as we have it right now:
       add . 300 NS resolver ; add resolver . 300 A 141.1.1.1 would
       otherwise fail (no SOA for . / delegation for resolver) *)
    Dns_trie.insert name k add trie

let sign_outgoing ~max_size server keyname signed packet buf =
  match Authentication.find_key server.auth keyname with
  | None -> Log.err (fun m -> m "key %a not found (or multiple)" Domain_name.pp keyname) ; None
  | Some key -> match Tsig.dnskey_to_tsig_algo key with
    | Error (`Msg msg) ->
      Log.err (fun m -> m "couldn't convert algorithm: %s" msg) ; None
    | Ok algorithm ->
      let original_id = fst packet.Packet.header in
      match Tsig.tsig ~algorithm ~original_id ~signed () with
      | None -> Log.err (fun m -> m "creation of tsig failed") ; None
      | Some tsig -> match server.tsig_sign ?mac:None ~max_size keyname tsig ~key packet buf with
        | None -> Log.err (fun m -> m "signing failed") ; None
        | Some res -> Some res

module Notification = struct
  (* TODO dnskey authentication of outgoing packets (preserve in connections, name of key should be enough) *)

  (* needed for passive secondaries (behind NAT etc.) such as let's encrypt,
     which initiated a signed! TCP session *)
  type connections = ([ `domain ] Domain_name.t * Ipaddr.V4.t) list Domain_name.Host_map.t

  let secondaries trie zone =
    match Dns_trie.lookup_with_cname zone Rr_map.Soa trie with
    | Ok (B (Soa, soa), (_, _, ns)) ->
      let secondaries = Domain_name.Host_set.remove soa.Soa.nameserver ns in
      (* TODO AAAA records / use lookup_glue? *)
      Domain_name.Host_set.fold (fun ns acc ->
          match Dns_trie.lookup ns Rr_map.A trie with
          | Ok (_, ips) -> Rr_map.Ipv4_set.union ips acc
          | _ ->
            Log.err (fun m -> m "lookup for A %a returned nothing as well"
                        Domain_name.pp ns) ;
            acc)
        secondaries Rr_map.Ipv4_set.empty
    | _ -> Rr_map.Ipv4_set.empty

  let to_notify conn ~data ~auth zone =
    (* for a given zone, compute the "ip -> key option" map of to-be-notiied secondaries
       uses data from 3 sources:
       - secondary NS of the zone as registered in data (ip only)
       - keys of the form YY.secondary-ip._transfer.zone and YY.secondary-ip._transfer
       - active connections (from the zone -> ip, key map above), used for lets encrypt etc. *)
    let secondaries =
      Rr_map.Ipv4_set.fold (fun ip m -> IPM.add ip None m)
        (secondaries data zone)
        IPM.empty
    in
    let of_list = List.fold_left (fun m (key, ip) -> IPM.add ip (Some key) m) in
    let secondaries_and_keys =
      of_list secondaries (Authentication.secondaries auth zone)
    in
    match Domain_name.Host_map.find zone conn with
    | None -> secondaries_and_keys
    | Some xs -> of_list secondaries_and_keys xs

  let insert ~data ~auth cs ~zone ~key ip =
    let cs' =
      let old =
        match Domain_name.Host_map.find zone cs with None -> [] | Some a -> a
      in
      Domain_name.Host_map.add zone ((key, ip) :: old) cs
    in
    match IPM.find_opt ip (to_notify cs ~data ~auth zone) with
    | None ->
      Log.info (fun m -> m "inserting notifications for %a key %a IP %a"
                   Domain_name.pp zone Domain_name.pp key Ipaddr.V4.pp ip);
      cs'
    | Some (Some k) ->
      if Domain_name.equal k key then begin
        Log.warn (fun m -> m "zone %a with key %a and IP %a already registered"
                     Domain_name.pp zone Domain_name.pp key Ipaddr.V4.pp ip);
        cs
      end else begin
        Log.warn (fun m -> m "replacing key zone %a oldkey %a and IP %a, new key %a"
                     Domain_name.pp zone Domain_name.pp k Ipaddr.V4.pp ip
                     Domain_name.pp key);
        cs'
      end
    | Some None ->
      Log.info (fun m -> m "adding zone %a with key %a and IP %a (previously: no key)"
                   Domain_name.pp zone Domain_name.pp key Ipaddr.V4.pp ip);
      cs'

  let remove conn ip =
    let is_not_it name (_, ip') =
      if Ipaddr.V4.compare ip ip' = 0 then begin
        Log.info (fun m -> m "removing notification for %a %a"
                     Domain_name.pp name Ipaddr.V4.pp ip);
        false
      end else true
    in
    Domain_name.Host_map.fold (fun name conns new_map ->
      match List.filter (is_not_it name) conns with
      | [] -> new_map
      | xs -> Domain_name.Host_map.add name xs new_map)
      conn Domain_name.Host_map.empty

  let encode_and_sign key_opt server now packet =
    let buf, max_size = Packet.encode `Tcp packet in
    match key_opt with
    | None -> buf, None
    | Some key ->
      match sign_outgoing ~max_size server key now packet buf with
      | None -> buf, None
      | Some (out, mac) -> out, Some mac

  (* outstanding notifications, with timestamp and retry count
     (at most one per zone per ip) *)
  type outstanding =
    (int64 * int * Cstruct.t option * Packet.t * [ `domain ] Domain_name.t option) Domain_name.Host_map.t IPM.t

  (* operations:
     - timer occured, retransmit outstanding or drop
     - send out notification for a given zone
     - a (signed?) notify response came in, drop it from outstanding
  *)
  (* TODO other timings, and also some in the far future *)
  let retransmit = Array.map Duration.of_sec [| 1 ; 3 ; 7 ; 20 ; 40 ; 60 ; 180 |]

  let retransmit server ns now ts =
    let max = pred (Array.length retransmit) in
    IPM.fold (fun ip map (new_ns, out) ->
        let new_map, out =
          Domain_name.Host_map.fold
            (fun name (oldts, count, mac, packet, key) (new_map, outs) ->
               if Int64.sub ts retransmit.(count) > oldts then
                 let out, mac = encode_and_sign key server now packet in
                 (if count = max then begin
                     Log.warn (fun m -> m "retransmitting notify to %a the last time %a"
                                 Ipaddr.V4.pp ip Packet.pp packet) ;
                    new_map
                   end else
                    (Domain_name.Host_map.add name (oldts, succ count, mac, packet, key) new_map)),
                 (ip, out) :: outs
               else
                 (Domain_name.Host_map.add name (oldts, count, mac, packet, key) new_map, outs))
            map (Domain_name.Host_map.empty, out)
        in
        (if Domain_name.Host_map.is_empty new_map then new_ns else IPM.add ip new_map new_ns),
        out)
      ns (IPM.empty, [])

  let notify_one ns server now ts zone soa ip key =
    let packet =
      let question = Packet.Question.create zone Soa
      and header =
        let id = Randomconv.int ~bound:(1 lsl 16 - 1) server.rng in
        (id, authoritative)
      in
      Packet.create header question (`Notify (Some soa))
    in
    let add_to_ns ns ip key mac =
      let data = (ts, 0, mac, packet, key) in
      let map = match IPM.find_opt ip ns with
        | None -> Domain_name.Host_map.empty
        | Some map -> map
      in
      let map' = Domain_name.Host_map.add zone data map in
      IPM.add ip map' ns
    in
    let out, mac = encode_and_sign key server now packet in
    let ns = add_to_ns ns ip key mac in
    (ns, (ip, out))

  let notify conn ns server now ts zone soa =
    let remotes = to_notify conn ~data:server.data ~auth:server.auth zone in
    Log.debug (fun m -> m "notifying %a: %a" Domain_name.pp zone
                  Fmt.(list ~sep:(unit ",@ ")
                         (pair ~sep:(unit ", key ") Ipaddr.V4.pp
                            (option ~none:(unit "none") Domain_name.pp)))
                  (IPM.bindings remotes));
    IPM.fold (fun ip key (ns, outs) ->
        let ns, out = notify_one ns server now ts zone soa ip key in
        ns, out :: outs)
      remotes (ns, [])

  let received_reply ns ip reply =
    match IPM.find_opt ip ns with
    | None -> ns
    | Some map ->
      match Domain_name.host (fst reply.Packet.question) with
      | Error _ ->
        Log.warn (fun m -> m "received notify reply for a non-hostname zone %a"
                     Domain_name.pp (fst reply.Packet.question));
        ns
      | Ok zone ->
        let map' = match Domain_name.Host_map.find zone map with
          | Some (_, _, _, request, _) ->
            begin match Packet.reply_matches_request ~request reply with
            | Ok r ->
              let map' = Domain_name.Host_map.remove zone map in
              (match r with `Notify_ack -> () | r -> Log.warn (fun m -> m "expected notify_ack, got %a" Packet.pp_reply r));
              map'
            | Error e ->
              Log.warn (fun m -> m "notify reply didn't match our request %a (request %a, reply %a)"
                           Packet.pp_mismatch e Packet.pp request Packet.pp reply);
              map
          end
        | _ -> map
      in
      if Domain_name.Host_map.is_empty map' then
        IPM.remove ip ns
      else
        IPM.add ip map' ns

  let mac ns ip reply =
    match IPM.find_opt ip ns with
    | None -> None
    | Some map ->
      match Domain_name.host (fst reply.Packet.question) with
      | Error _ ->
        Log.warn (fun m -> m "mac for a non-hostname zone %a"
                     Domain_name.pp (fst reply.Packet.question));
        None
      | Ok zone -> match Domain_name.Host_map.find zone map with
        | Some (_, _, mac, _, _) -> mac
        | None -> None
end

let in_zone zone name = Domain_name.sub ~subdomain:name ~domain:zone

let update_data trie zone (prereq, update) =
  let in_zone = in_zone zone in
  Domain_name.Map.fold (fun name prereqs acc ->
      acc >>= fun () ->
      guard (in_zone name) Rcode.NotZone >>= fun () ->
      List.fold_left (fun acc prereq ->
          acc >>= fun () ->
          handle_rr_prereq name trie prereq)
        (Ok ()) prereqs)
    prereq (Ok ()) >>= fun () ->
  Domain_name.Map.fold (fun name updates acc ->
      acc >>= fun trie ->
      guard (in_zone name) Rcode.NotZone >>| fun () ->
      List.fold_left (handle_rr_update name) trie updates)
    update (Ok trie) >>= fun trie' ->
  (match Dns_trie.check trie' with
   | Ok () -> Ok ()
   | Error e ->
     Log.err (fun m -> m "check after update returned %a" Dns_trie.pp_zone_check e) ;
     Error Rcode.YXRRSet) >>= fun () ->
  if Dns_trie.equal trie trie' then
    (* should this error out? - RFC 2136 3.4.2.7 says NoError at the end *)
    Ok (trie, None)
  else match Dns_trie.lookup zone Soa trie, Dns_trie.lookup zone Soa trie' with
    | Ok oldsoa, Ok soa when Soa.newer ~old:oldsoa soa -> Ok (trie', Some (zone, soa))
    | _, Ok soa ->
      let soa = { soa with Soa.serial = Int32.succ soa.Soa.serial } in
      let trie'' = Dns_trie.insert zone Soa soa trie' in
      Ok (trie'', Some (zone, soa))
    | Ok oldsoa, Error _ ->
      (* zone removal!? *)
      Ok (trie', Some (zone, { oldsoa with Soa.serial = Int32.succ oldsoa.Soa.serial }))
    | Error o, Error n ->
      Log.warn (fun m -> m "should not happen: soa lookup for %a failed in old %a and new %a"
                   Domain_name.pp zone Dns_trie.pp_e o Dns_trie.pp_e n);
      Ok (trie', None)

let handle_update t proto key (zone, _) u =
  if Authentication.authorise t.auth proto ?key ~zone `Update then begin
    Log.info (fun m -> m "update key %a authorised for update %a"
                 Fmt.(option ~none:(unit "none") Domain_name.pp) key
                 Packet.Update.pp u) ;
    match Domain_name.host zone with
    | Ok z ->
      update_data t.data z u >>| fun (data', stuff) ->
      data', stuff
    | Error _ ->
      Log.warn (fun m -> m "update on a zone not a hostname %a" Domain_name.pp zone);
      Error Rcode.FormErr
  end else
    Error Rcode.NotAuth

let handle_tsig ?mac t now p buf =
  match p.Packet.tsig with
  | None -> Ok None
  | Some (name, tsig, off) ->
    let algo = tsig.Tsig.algorithm in
    let key =
      match Authentication.find_key t.auth name with
      | None -> None
      | Some key ->
        match Tsig.dnskey_to_tsig_algo key with
        | Ok a when a = algo -> Some key
        | _ -> None
    in
    t.tsig_verify ?mac now p name ?key tsig (Cstruct.sub buf 0 off) >>= fun (tsig, mac, key) ->
    Ok (Some (name, tsig, mac, key))

module Primary = struct

  type s =
    t * Dns_trie.t IM.t Domain_name.Map.t * Notification.connections * Notification.outstanding

  let server (t, _, _, _) = t

  let data (t, _, _, _) = t.data

  (* TODO: not entirely sure how many old ones to keep. This keeps for each
     zone the most recent 5 serials. It does _not_ remove removed zones.
     since it updates all zones with the new trie, there should be at most
     5 (well, 6) tries alive in memory *)
  (* TODO use LRU here! *)
  let update_trie_cache m trie =
    Dns_trie.fold Soa trie (fun name soa acc ->
        let recorded = match Domain_name.Map.find name m with
          | None -> IM.empty
          | Some xs ->
            (* keep last 5 references around *)
            if IM.cardinal xs >= 5 then
              IM.remove (fst (IM.min_binding xs)) xs
            else
              xs
        in
        let m' = IM.add soa.Soa.serial trie recorded in
        Domain_name.Map.add name m' acc)
        Domain_name.Map.empty

  let with_data (t, m, l, n) now ts data =
    (* we're the primary and need to notify our friends! *)
    let n', out =
      Dns_trie.fold Soa data
        (fun name soa (n, outs) ->
           match Domain_name.host name with
           | Error _ ->
             Log.warn (fun m -> m "zone not a hostname %a" Domain_name.pp name);
             (n, outs)
           | Ok zone ->
             match Dns_trie.lookup name Soa t.data with
             | Error _ ->
               let n', outs' = Notification.notify l n t now ts zone soa in
               (n', outs @ outs')
             | Ok old when Soa.newer ~old soa ->
               let n', outs' = Notification.notify l n t now ts zone soa in
               (n', outs @ outs')
             | Ok _ -> (n, outs))
        (n, [])
    in
    let n'', out' =
      Dns_trie.fold Soa t.data (fun name soa (n, outs) ->
          match Domain_name.host name with
          | Error _ ->
            Log.warn (fun m -> m "zone not a hostname %a" Domain_name.pp name);
            (n, outs)
          | Ok zone ->
            match Dns_trie.lookup name Soa data with
            | Error _ ->
              let soa' = { soa with Soa.serial = Int32.succ soa.Soa.serial } in
              let n', outs' = Notification.notify l n t now ts zone soa' in
              (n', outs @ outs')
            | Ok _ -> (n, outs))
        (n', [])
    in
    let m' = update_trie_cache m t.data in
    ({ t with data }, m', l, n''), out @ out'

  let with_keys (t, m, l, n) now ts keys =
    let auth = Authentication.of_keys keys in
    let old, au = t.auth in
    (* need to diff the old and new keys *)
    let added =
      Dns_trie.fold Rr_map.Dnskey auth (fun name _ acc ->
          match Dns_trie.lookup name Rr_map.Dnskey old with
          | Ok _ -> acc
          | Error _ -> Domain_name.Set.add name acc) Domain_name.Set.empty
    and removed =
      Dns_trie.fold Rr_map.Dnskey old (fun name _ acc ->
          match Dns_trie.lookup name Rr_map.Dnskey auth with
          | Ok _ -> acc
          | Error _ -> Domain_name.Set.add name acc) Domain_name.Set.empty
    in
    (* drop all removed keys from connections & notifications *)
    let l' = Domain_name.Host_map.fold (fun name v acc ->
        match List.filter (fun (n, _) -> not (Domain_name.Set.mem n removed)) v with
        | [] -> acc
        | v' -> Domain_name.Host_map.add name v' acc)
        l Domain_name.Host_map.empty
    and n' = IPM.fold (fun ip m acc ->
        let m' = Domain_name.Host_map.fold (fun name v acc ->
            match v with
            | _, _, _, _, Some key when Domain_name.Set.mem key removed -> acc
            | _ -> Domain_name.Host_map.add name v acc)
            m Domain_name.Host_map.empty
        in
        if Domain_name.Host_map.is_empty m' then acc else IPM.add ip m' acc)
        n IPM.empty
    in
    let t' = { t with auth = (auth, au) } in
    (* for new transfer keys, send notifies out (with respective zone) *)
    let n'', outs =
      Domain_name.Set.fold (fun key (ns, out) ->
          match Authentication.find_zone_ips key with
          | Some (zone, _, Some secondary) ->
            let notify =
              if Domain_name.(equal zone root) then
                Dns_trie.fold Soa t'.data (fun name soa n -> (name, soa)::n) []
              else
                match Dns_trie.lookup zone Rr_map.Soa t'.data with
                | Error _ -> []
                | Ok soa -> [zone, soa]
            in
            List.fold_left (fun (ns, outs) (name, soa) ->
                let zone = Domain_name.host_exn name in
                let ns, out = Notification.notify_one ns t' now ts zone soa secondary (Some key) in
                ns, out :: outs)
              (ns, out) notify
          | _ -> ns, out)
        added (n', [])
    in
    (t', m, l', n''), outs

  let create ?(keys = []) ?(a = []) ?tsig_verify ?tsig_sign ~rng data =
    let keys = Authentication.of_keys keys in
    let t = create ?tsig_verify ?tsig_sign data (keys, a) rng in
    let notifications =
      let f name soa ns =
        Log.debug (fun m -> m "soa found for %a" Domain_name.pp name) ;
        match Domain_name.host name with
        | Error _ ->
          Log.warn (fun m -> m "zone is not a valid hostname %a" Domain_name.pp name);
          ns
        | Ok zone ->
          (* we drop notifications, the first call to timer will solve this :) *)
          fst (Notification.notify Domain_name.Host_map.empty ns t Ptime.epoch 0L zone soa)
      in
      Dns_trie.fold Rr_map.Soa data f IPM.empty
    in
    t, update_trie_cache Domain_name.Map.empty data, Domain_name.Host_map.empty, notifications

  let tcp_soa_query proto (name, typ) =
    match proto, typ with
    | `Tcp, `K (Rr_map.K Soa) ->
      begin match Domain_name.host name with
        | Ok h -> Ok h
        | Error _ -> Error ()
      end
    | _ -> Error ()

  let handle_packet (t, m, l, ns) now ts proto ip _port p key =
    let key = match key with None -> None | Some k -> Some (Domain_name.domain k) in
    match p.Packet.data with
    | `Query ->
      (* if there was a (transfer-key) signed SOA, and tcp, we add to notification list! *)
      let l', ns', outs, keep = match tcp_soa_query proto p.question, key with
        | Ok zone, Some key when Authentication.is_op `Transfer key ->
          let zones, notify =
            if Domain_name.(equal root zone) then
              Dns_trie.fold Soa t.data (fun name soa (zs, n) ->
                  let zone = Domain_name.host_exn name in
                  Domain_name.Host_set.add zone zs, (zone, soa)::n)
                (Domain_name.Host_set.empty, [])
            else
              Domain_name.Host_set.singleton zone, []
          in
          let l' = Domain_name.Host_set.fold (fun zone l ->
              Notification.insert ~data:t.data ~auth:t.auth l ~zone ~key ip)
              zones l
          in
          let ns, outs =
            List.fold_left (fun (ns, outs) (name, soa) ->
                let ns, out = Notification.notify_one ns t now ts name soa ip (Some key) in
                ns, out :: outs)
              (ns, []) notify
          in
          l', ns, outs, Some `Keep
        | _ -> l, ns, [], None
      in
      let answer =
        let flags, data, additional = match handle_question t p.question with
          | Ok (flags, data, additional) -> flags, `Answer data, additional
          | Error (rcode, data) -> err_flags rcode, `Rcode_error (rcode, Opcode.Query, data), None
        in
        Packet.create ?additional (fst p.header, flags) p.question data
      in
      (t, m, l', ns'), Some answer, outs, keep
    | `Update u ->
      let data, (flags, answer), stuff =
        match handle_update t proto key p.question u with
        | Ok (data, stuff) -> data, (authoritative, `Update_ack), stuff
        | Error rcode -> t.data, (err_flags rcode, `Rcode_error (rcode, Opcode.Update, None)), None
      in
      let t' = { t with data }
      and m' = update_trie_cache m data
      in
      let ns, out = match stuff with
        | None -> ns, []
        | Some (zone, soa) -> Notification.notify l ns t' now ts zone soa
      in
      let answer' = Packet.create (fst p.header, flags) p.question answer in
      (t', m', l, ns), Some answer', out, None
    | `Axfr_request ->
      let flags, answer = match axfr t proto key p.question with
        | Ok data -> authoritative, `Axfr_reply data
        | Error rcode -> err_flags rcode, `Rcode_error (rcode, Opcode.Query, None)
      in
      let answer = Packet.create (fst p.header, flags) p.question answer in
      (t, m, l, ns), Some answer, [], None
    | `Ixfr_request soa ->
      let flags, answer = match ixfr t m proto key p.question soa with
        | Ok data -> authoritative, `Ixfr_reply data
        | Error rcode -> err_flags rcode, `Rcode_error (rcode, Opcode.Query, None)
      in
      let answer = Packet.create (fst p.header, flags) p.question answer in
      (t, m, l, ns), Some answer, [], None
    | `Notify_ack | `Rcode_error (_, Opcode.Notify, _) ->
      let ns' = Notification.received_reply ns ip p in
      (t, m, l, ns'), None, [], None
    | `Notify soa ->
      Log.warn (fun m -> m "unsolicited notify request %a (replying anyways)"
                   Fmt.(option ~none:(unit "no") Soa.pp) soa) ;
      let reply = Packet.create (fst p.header, authoritative) p.question `Notify_ack in
      (t, m, l, ns), Some reply, [], Some (`Notify soa)
    | p ->
      Log.err (fun m -> m "ignoring unsolicited %a" Packet.pp_data p) ;
      (t, m, l, ns), None, [], None

  let handle_buf t now ts proto ip port buf =
    match
      safe_decode buf >>| fun res ->
      Log.debug (fun m -> m "from %a received:@[%a@]" Ipaddr.V4.pp ip Packet.pp res) ;
      res
    with
    | Error rcode ->
      let answer = Packet.raw_error buf rcode in
      Log.warn (fun m -> m "error %a while %a sent %a, answering with %a"
                   Rcode.pp rcode Ipaddr.V4.pp ip Cstruct.hexdump_pp buf
                   Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) answer) ;
      t, answer, [], None
    | Ok p ->
      let handle_inner keyname =
        let t, answer, out, notify =
          handle_packet t now ts proto ip port p keyname
        in
        let answer = match answer with
          | Some answer ->
            let max_size, edns = Edns.reply p.edns in
            let answer = Packet.with_edns answer edns in
            (* be aware, this may be truncated... here's where AXFR is assembled! *)
            let r = Packet.encode ?max_size proto answer in
            Some (answer, r)
          | None -> None
        in
        t, answer, out, notify
      in
      let server, _, _, ns = t in
      let mac = match p.Packet.data with
        | `Notify_ack | `Rcode_error _ -> Notification.mac ns ip p
        | _ -> None
      in
      match handle_tsig ?mac server now p buf with
      | Error (e, data) ->
        Log.err (fun m -> m "error %a while handling tsig" Tsig_op.pp_e e) ;
        t, data, [], None
      | Ok None ->
        let t, answer, out, notify = handle_inner None in
        let answer' = match answer with
          | None -> None
          | Some (_, (cs, _)) -> Some cs
        in
        (t, answer', out, notify)
      | Ok (Some (name, tsig, mac, key)) ->
        let n = function Some (`Notify n) -> Some (`Signed_notify n) | Some `Keep -> Some `Keep | None -> None in
        let t', answer, out, notify = handle_inner (Some name) in
        let answer' = match answer with
          | None -> None
          | Some (answer, (buf, max_size)) ->
            match server.tsig_sign ~max_size ~mac name tsig ~key answer buf with
            | None ->
              Log.warn (fun m -> m "couldn't use %a to tsig sign" Domain_name.pp name);
              (* TODO - better send back unsigned answer? or an error? *)
              None
            | Some (buf, _) -> Some buf
        in
        (t', answer', out, n notify)

  let closed (t, m, l, ns) ip =
    let l' = Notification.remove l ip in
    (t, m, l', ns)

  let timer (t, m, l, ns) now ts =
    let ns', out = Notification.retransmit t ns now ts in
    (t, m, l, ns'), out

  let to_be_notified (t, _, l, _) zone =
    IPM.bindings (Notification.to_notify l ~data:t.data ~auth:t.auth zone)
end

module Secondary = struct

  type state =
    | Transferred of int64
    | Requested_soa of int64 * int * int * Cstruct.t
    | Requested_axfr of int64 * int * Cstruct.t
    | Requested_ixfr of int64 * int * Soa.t * Cstruct.t

  let id = function
    | Transferred _ -> None
    | Requested_soa (_, id, _, _) -> Some id
    | Requested_axfr (_, id, _) -> Some id
    | Requested_ixfr (_, id, _, _) -> Some id

  (* TODO undefined what happens if there are multiple transfer keys for zone x *)
  type s = t * (state * Ipaddr.V4.t * [ `domain ] Domain_name.t) Domain_name.Host_map.t

  let data (t, _) = t.data

  let with_data (t, zones) data = ({ t with data }, zones)

  let create ?(a = []) ?primary ~tsig_verify ~tsig_sign ~rng keylist =
    (* two kinds of keys: aaa._key-management and ip1.ip2._transfer.zone *)
    let keys = Authentication.of_keys keylist in
    let zones =
      let f name _ zones =
        Log.debug (fun m -> m "soa found for %a" Domain_name.pp name) ;
        match Domain_name.host name with
        | Error _ ->
          Log.warn (fun m -> m "zone %a not a hostname" Domain_name.pp name);
          zones
        | Ok zone ->
          match Authentication.primaries (keys, []) name with
          | [] -> begin match primary with
              | None ->
                Log.warn (fun m -> m "no nameserver found for %a" Domain_name.pp name) ;
                zones
              | Some ip ->
                List.fold_left (fun zones (keyname, _) ->
                    let keyname = Domain_name.domain keyname in
                    if
                      Authentication.is_op `Transfer keyname &&
                      Domain_name.sub ~domain:name ~subdomain:keyname
                    then begin
                      Log.app (fun m -> m "adding zone %a with key %a and ip %a"
                                  Domain_name.pp name Domain_name.pp keyname
                                  Ipaddr.V4.pp ip) ;
                      let v = Requested_soa (0L, 0, 0, Cstruct.empty), ip, keyname in
                      Domain_name.Host_map.add zone v zones
                    end else begin
                      Log.warn (fun m -> m "no transfer key found for %a" Domain_name.pp name) ;
                      zones
                    end) zones keylist
            end
          | primaries ->
            List.fold_left (fun zones (keyname, ip) ->
                Log.app (fun m -> m "adding transfer key %a for zone %a"
                            Domain_name.pp keyname Domain_name.pp name) ;
                let v = Requested_soa (0L, 0, 0, Cstruct.empty), ip, keyname in
                Domain_name.Host_map.add zone v zones)
              zones primaries
      in
      Dns_trie.fold Rr_map.Soa keys f Domain_name.Host_map.empty
    in
    (create ~tsig_verify ~tsig_sign Dns_trie.empty (keys, a) rng, zones)

  let header rng () =
    let id = Randomconv.int ~bound:(1 lsl 16 - 1) rng in
    id, Packet.Flags.empty

  let axfr t proto now ts q_name name =
    let header = header t.rng ()
    and question = (Domain_name.domain q_name, `Axfr)
    in
    let p = Packet.create header question `Axfr_request in
    let buf, max_size = Packet.encode proto p in
    match sign_outgoing ~max_size t name now p buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_axfr (ts, fst header, mac), buf)

  let ixfr t proto now ts q_name soa name =
    let header = header t.rng ()
    and question = (Domain_name.domain q_name, `Ixfr)
    in
    let p = Packet.create header question (`Ixfr_request soa) in
    let buf, max_size = Packet.encode proto p in
    match sign_outgoing ~max_size t name now p buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_ixfr (ts, fst header, soa, mac), buf)

  let query_soa ?(retry = 0) t proto now ts q_name name =
    let header = header t.rng ()
    and question = Packet.Question.create q_name Soa
    in
    let p = Packet.create header question `Query in
    let buf, max_size = Packet.encode proto p in
    match sign_outgoing ~max_size t name now p buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_soa (ts, fst header, retry, mac), buf)

  let timer (t, zones) p_now now =
    (* what is there to be done?
       - request SOA on every soa.refresh interval
       - if the primary server is not reachable, try every time after soa.retry
       - once soa.expiry is over (from the initial SOA request), don't serve the zone anymore

       - axfr (once soa is through and we know we have stale data) is retried every 5 seconds
       - if we don't have a soa yet for the zone, retry every 5 seconds as well
    *)
    Log.debug (fun m -> m "secondary timer");
    let t, out =
      Domain_name.Host_map.fold (fun zone (st, ip, name) ((t, zones), acc) ->
          Log.debug (fun m -> m "secondary timer zone %a ip %a name %a"
                        Domain_name.pp zone Ipaddr.V4.pp ip Domain_name.pp name);
          let maybe_out data =
            let st, out = match data with
              | None -> st, acc
              | Some (st, out) -> st, (`Tcp, ip, out) :: acc
            in
            ((t, Domain_name.Host_map.add zone (st, ip, name) zones), out)
          in
          match Dns_trie.lookup zone Rr_map.Soa t.data, st with
          | Ok soa, Transferred ts ->
            (* TODO: integer overflows (Int64.add) *)
            let r = Duration.of_sec (Int32.to_int soa.Soa.refresh) in
            maybe_out
              (if Int64.add ts r < now then
                 query_soa t `Tcp p_now now zone name
               else
                 None)
          | Ok soa, Requested_soa (ts, _, retry, _) ->
            let expiry = Duration.of_sec (Int32.to_int soa.Soa.expiry) in
            if Int64.add ts expiry < now then begin
              Log.warn (fun m -> m "expiry expired, dropping zone %a"
                           Domain_name.pp zone) ;
              let data = Dns_trie.remove_zone zone t.data in
              (({ t with data }, zones), acc)
            end else
              let retry = succ retry in
              let e = Duration.of_sec (retry * Int32.to_int soa.Soa.retry) in
              maybe_out
                (if Int64.add ts e < now then
                   query_soa ~retry t `Tcp p_now ts zone name
                 else
                   None)
          | Error _, Requested_soa (ts, _, retry, _) ->
            let e = Duration.of_sec 5 in
            maybe_out
              (if Int64.add ts e < now || ts = 0L then
                 let retry = succ retry in
                 query_soa ~retry t `Tcp p_now ts zone name
               else
                 None)
          | _, Requested_axfr (ts, _, _) ->
            let e = Duration.of_sec 5 in
            maybe_out
              (if Int64.add ts e < now then
                 axfr t `Tcp p_now ts zone name
               else
                 None)
          | _, Requested_ixfr (ts, _, soa, _) ->
            let e = Duration.of_sec 5 in
            maybe_out
              (if Int64.add ts e < now then
                 ixfr t `Tcp p_now ts zone soa name
               else
                 None)
          | Error e, _ ->
            Log.err (fun m -> m "unclear how we ended up here zone %a, error %a while looking for soa"
                        Domain_name.pp zone Dns_trie.pp_e e) ;
            maybe_out None)
        zones ((t, Domain_name.Host_map.empty), [])
    in
    t, out

  let handle_notify t zones now ts ip zone typ notify keyname =
    match typ with
    | `K (Rr_map.K Soa) ->
      let kzone = match keyname with
        | None -> None
        | Some key -> Some (key, Authentication.zone key)
      in
      begin match Domain_name.Host_map.find zone zones, kzone with
        | None, None ->
          (* we don't know anything about the notified zone *)
          Log.warn (fun m -> m "ignoring notify for %a, no such zone"
                       Domain_name.pp zone);
          Error Rcode.Refused
        | None, Some (kname, kzone) ->
          if Domain_name.(equal root kzone || equal zone kzone) then
            (* new zone, let's AXFR directly! *)
            (* or old (forgotten) zone, but key zone matches *)
            let r = match axfr t `Tcp now ts zone kname with
              | None ->
                Log.warn (fun m -> m "new zone %a, couldn't AXFR" Domain_name.pp zone);
                zones, []
              | Some (st, buf) ->
                Domain_name.Host_map.add zone (st, ip, kname) zones,
                [ `Tcp, ip, buf ]
            in
            Ok r
          else begin
            Log.warn (fun m -> m "ignoring notify for %a, (key %a, kzone %a): no such zone"
                         Domain_name.pp zone Domain_name.pp kname Domain_name.pp kzone);
            Error Rcode.Refused
          end
        | Some (Transferred _, ip', name), None ->
          if Ipaddr.V4.compare ip ip' = 0 then begin
            Log.debug (fun m -> m "received notify for %a, replying and requesting SOA"
                          Domain_name.pp zone) ;
            let zones, out =
              match query_soa t `Tcp now ts zone name with
              | None -> zones, []
              | Some (st, buf) ->
                Domain_name.Host_map.add zone (st, ip, name) zones,
                [ `Tcp, ip, buf ]
            in
            Ok (zones, out)
          end else begin
            Log.warn (fun m -> m "ignoring notify for %a from %a (%a is primary)"
                         Domain_name.pp zone Ipaddr.V4.pp ip Ipaddr.V4.pp ip');
            Error Rcode.Refused
          end
        | Some _, None ->
          Log.warn (fun m -> m "received unsigned notify, but %a already in progress"
                       Domain_name.pp zone);
          Ok (zones, [])
        | Some (st, ip', name), Some _ ->
          if Ipaddr.V4.compare ip ip' = 0 then begin
            (* we received a signed notify! let's check SOA if present, and act *)
            match st, notify, Dns_trie.lookup zone Rr_map.Soa t.data with
            | Transferred _, None, _ ->
              begin match query_soa t `Tcp now ts zone name with
                | None ->
                  Log.warn (fun m -> m "received signed notify for %a, but couldn't sign soa?" Domain_name.pp zone);
                  Ok (zones, [])
                | Some (st, buf) ->
                  Ok (Domain_name.Host_map.add zone (st, ip, name) zones,
                      [ `Tcp, ip, buf ])
              end
            | _, None, _ ->
              Log.warn (fun m -> m "received signed notify for %a, but no SOA (already in progress)"
                           Domain_name.pp zone);
              Ok (zones, [])
            | _, Some soa, Error _ ->
              Log.info (fun m -> m "received signed notify for %a, soa %a couldn't find a local SOA"
                           Domain_name.pp zone Soa.pp soa);
              begin match axfr t `Tcp now ts zone name with
                | None ->
                  Log.warn (fun m -> m "received signed notify for %a, but couldn't sign axfr" Domain_name.pp zone);
                  Ok (zones, [])
                | Some (st, buf) ->
                  Ok (Domain_name.Host_map.add zone (st, ip, name) zones,
                      [ `Tcp, ip, buf ])
              end
            | _, Some soa, Ok old ->
              if Soa.newer ~old soa then
                match ixfr t `Tcp now ts zone old name with
                  | None ->
                    Log.warn (fun m -> m "received signed notify for %a, but couldn't sign ixfr" Domain_name.pp zone);
                    Ok (zones, [])
                  | Some (st, buf) ->
                    Log.info (fun m -> m "received signed notify for %a, ixfr" Domain_name.pp zone);
                    Ok (Domain_name.Host_map.add zone (st, ip, name) zones,
                        [ `Tcp, ip, buf ])
              else begin
                Log.warn (fun m -> m "received signed notify for %a with SOA %a not newer %a" Domain_name.pp zone Soa.pp soa Soa.pp old);
                Ok (Domain_name.Host_map.add zone (Transferred ts, ip, name) zones, [])
              end
          end else begin
            Log.warn (fun m -> m "ignoring notify for %a from %a (%a is primary)"
                         Domain_name.pp zone Ipaddr.V4.pp ip Ipaddr.V4.pp ip');
            Error Rcode.Refused
          end
      end
    | _ ->
      Log.warn (fun m -> m "ignoring notify %a"
                   Packet.Question.pp (Domain_name.domain zone, typ));
      Error Rcode.FormErr

  let authorise should is =
    let r = match is with
      | None -> false
      | Some x -> Domain_name.equal x should
    in
    if not r then
      Log.warn (fun m -> m "%a is not authorised (should %a)"
                   Fmt.(option ~none:(unit "no key") Domain_name.pp) is
                   Domain_name.pp should) ;
    r

  let authorise_zone zones keyname header zone =
    match Domain_name.Host_map.find zone zones with
    | None ->
      Log.warn (fun m -> m "ignoring %a, unknown zone" Domain_name.pp zone) ;
      Error Rcode.Refused
    | Some (st, ip, name) ->
      (* TODO use NotAuth instead of Refused here? *)
      guard (match id st with None -> true | Some id' -> fst header = id')
        Rcode.Refused >>= fun () ->
      guard (authorise name keyname) Rcode.Refused >>| fun () ->
      Log.debug (fun m -> m "authorized access to zone %a (with key %a)"
                    Domain_name.pp zone Domain_name.pp name) ;
      (st, ip, name)

  let rrs_in_zone zone rr_map =
    Domain_name.Map.filter
      (fun name _ -> Domain_name.sub ~subdomain:name ~domain:zone)
      rr_map

  let handle_axfr t zones ts keyname header zone ((fresh_soa, fresh_zone) as axfr) =
    authorise_zone zones keyname header zone >>= fun (st, ip, name) ->
    match st with
    | Requested_axfr (_, _, _) ->
      (* TODO partial AXFR, but decoder already rejects them *)
      Log.info (fun m -> m "received authorised AXFR for %a: %a"
                   Domain_name.pp zone Packet.Axfr.pp axfr) ;
      (* SOA should be higher than ours! *)
      (match Dns_trie.lookup zone Soa t.data with
       | Error _ ->
         Log.info (fun m -> m "no soa for %a, maybe first axfr" Domain_name.pp zone) ;
         Ok ()
       | Ok soa ->
         if Soa.newer ~old:soa fresh_soa then
           Ok ()
         else begin
           Log.warn (fun m -> m "AXFR for %a (%a) is not newer than ours (%a)"
                        Domain_name.pp zone Soa.pp fresh_soa Soa.pp soa) ;
           (* TODO what is the right error here? *)
           Error Rcode.ServFail
         end) >>= fun () ->
      (* filter map to ensure that all entries are in the zone! *)
      let fresh_zone = rrs_in_zone zone fresh_zone in
      let trie' =
        let trie = Dns_trie.remove_zone zone t.data in
        (* insert SOA explicitly - it's not part of entries (should it be?) *)
        let trie = Dns_trie.insert zone Rr_map.Soa fresh_soa trie in
        Dns_trie.insert_map fresh_zone trie
      in
      (* check new trie *)
      (match Dns_trie.check trie' with
        | Ok () ->
          Log.info (fun m -> m "zone %a transferred, and life %a"
                       Domain_name.pp zone Soa.pp fresh_soa)
        | Error err ->
          Log.warn (fun m -> m "check on transferred zone %a failed: %a"
                       Domain_name.pp zone Dns_trie.pp_zone_check err)) ;
      let zones = Domain_name.Host_map.add zone (Transferred ts, ip, name) zones in
      Ok ({ t with data = trie' }, zones, [])
    | _ ->
      Log.warn (fun m -> m "ignoring AXFR %a unmatched state" Domain_name.pp zone) ;
      Error Rcode.Refused

  let handle_ixfr t zones ts keyname header zone (fresh_soa, data) =
    authorise_zone zones keyname header zone >>= fun (st, ip, name) ->
    match st with
    | Requested_ixfr (_, _, soa, _) ->
      if Soa.newer ~old:soa fresh_soa then
        let trie' = match data with
          | `Empty -> t.data
          | `Full entries ->
            let fresh_zone = rrs_in_zone zone entries in
            let trie = Dns_trie.remove_zone zone t.data in
            Dns_trie.insert_map fresh_zone trie
          | `Difference (_, del, add) ->
            let del = rrs_in_zone zone del
            and add = rrs_in_zone zone add
            in
            Dns_trie.insert_map add (Dns_trie.remove_map del t.data)
        in
        let trie' = Dns_trie.insert zone Rr_map.Soa fresh_soa trie' in
        (match Dns_trie.check trie' with
         | Ok () ->
           Log.info (fun m -> m "zone %a transferred, and life %a"
                        Domain_name.pp zone Soa.pp fresh_soa)
         | Error err ->
           Log.warn (fun m -> m "check on incrementally transferred zone %a failed: %a"
                        Domain_name.pp zone Dns_trie.pp_zone_check err)) ;
        let zones = Domain_name.Host_map.add zone (Transferred ts, ip, name) zones in
        Ok ({ t with data = trie' }, zones, [])
      else begin
        Log.warn (fun m -> m "requested zone %a soa %a, got %a as fresh soa"
                     Domain_name.pp zone Soa.pp soa Soa.pp fresh_soa);
        Error Rcode.ServFail
      end
    | _ ->
      Log.warn (fun m -> m "ignoring IXFR %a unmatched state" Domain_name.pp zone) ;
      Error Rcode.Refused

  let handle_answer t zones now ts keyname header zone typ (answer, _) =
    authorise_zone zones keyname header zone >>= fun (st, ip, name) ->
    match st with
    | Requested_soa (_, _, retry, _) ->
      Log.debug (fun m -> m "received SOA after %d retries" retry) ;
      (* request AXFR now in case of serial is higher! *)
      begin match Dns_trie.lookup zone Rr_map.Soa t.data, Name_rr_map.find (Domain_name.domain zone) Soa answer with
        | _, None ->
          Log.err (fun m -> m "didn't receive SOA for %a from %a (answer %a)"
                      Domain_name.pp zone Ipaddr.V4.pp ip Name_rr_map.pp answer) ;
          Error Rcode.FormErr
        | Ok cached_soa, Some fresh ->
          (* TODO: > with wraparound in mind *)
          if Soa.newer ~old:cached_soa fresh then
            match ixfr t `Tcp now ts zone cached_soa name with
            | None ->
              Log.warn (fun m -> m "trouble creating ixfr for %a (using %a)"
                           Domain_name.pp zone Domain_name.pp name) ;
              (* TODO: reset state? *)
              Ok (t, zones, [])
            | Some (st, buf) ->
              Log.debug (fun m -> m "requesting IXFR for %a now!" Domain_name.pp zone) ;
              let zones = Domain_name.Host_map.add zone (st, ip, name) zones in
              Ok (t, zones, [ (`Tcp, ip, buf) ])
          else begin
            Log.info (fun m -> m "received soa (%a) for %a is not newer than cached (%a), moving on"
                         Soa.pp fresh Domain_name.pp zone Soa.pp cached_soa) ;
            let zones = Domain_name.Host_map.add zone (Transferred ts, ip, name) zones in
            Ok (t, zones, [])
          end
        | Error _, _ ->
          Log.info (fun m -> m "couldn't find soa, requesting AXFR") ;
          begin match axfr t `Tcp now ts zone name with
            | None -> Log.warn (fun m -> m "trouble building axfr") ; Ok (t, zones, [])
            | Some (st, buf) ->
              Log.debug (fun m -> m "requesting AXFR for %a now!" Domain_name.pp zone) ;
              let zones = Domain_name.Host_map.add zone (st, ip, name) zones in
              Ok (t, zones, [ (`Tcp, ip, buf) ])
          end
      end
    | _ ->
      Log.warn (fun m -> m "ignoring question %a unmatched state"
                   Packet.Question.pp (Domain_name.domain zone, typ));
      Error Rcode.Refused

  let handle_packet (t, zones) now ts ip p keyname =
    let keyname = match keyname with None -> None | Some k -> Some (Domain_name.domain k) in
    match p.Packet.data with
    | `Query ->
      let flags, data, additional = match handle_question t p.question with
        | Ok (flags, data, additional) -> flags, `Answer data, additional
        | Error (rcode, data) -> err_flags rcode, `Rcode_error (rcode, Opcode.Query, data), None
      in
      let answer = Packet.create ?additional (fst p.header, flags) p.question data in
      (t, zones), Some answer, []
    | `Answer a ->
      begin match Domain_name.host (fst p.question) with
        | Error _ ->
          Log.warn (fun m -> m "answer for a non-hostname zone %a"
                       Domain_name.pp (fst p.question));
          (t, zones), None, []
        | Ok zone ->
          let t, out =
            match handle_answer t zones now ts keyname p.header zone (snd p.question) a with
            | Ok (t, zones, out) -> (t, zones), out
            | Error rcode ->
              Log.warn (fun m -> m "error %a while processing answer %a" Rcode.pp rcode Packet.pp p);
              (t, zones), []
          in
          t, None, out
      end
    | `Update _ ->
      (* we don't deal with updates *)
      let answer = Packet.create p.header p.question (`Rcode_error (Rcode.Refused, Opcode.Update, None)) in
      (t, zones), Some answer, []
    | `Axfr_request | `Ixfr_request _ ->
      (* we don't reply to axfr/ixfr requests *)
      let answer = Packet.create p.header p.question (`Rcode_error (Rcode.Refused, Opcode.Query, None)) in
      (t, zones), Some answer, []
    | `Rcode_error (Rcode.NotAuth, Opcode.Query, _) ->
      (* notauth axfr and SOA replies (and drop the resp. zone) *)
      begin match Domain_name.host (fst p.Packet.question) with
        | Error _ ->
          Log.warn (fun m -> m "rcode error with a non-hostname zone %a"
                       Domain_name.pp (fst p.Packet.question));
          (t, zones), None, []
        | Ok zone ->
          match authorise_zone zones keyname p.Packet.header zone with
          | Ok (Requested_axfr (_, _, _), _, _ | Requested_ixfr (_, _, _, _), _, _ | Requested_soa (_, _, _, _), _, _) ->
            Log.warn (fun m -> m "received notauth reply, requested axfr, ixfr or soa, dropping zone %a"
                         Domain_name.pp zone);
            let trie = Dns_trie.remove_zone zone t.data in
            let zones' = Domain_name.Host_map.remove zone zones in
            ({ t with data = trie }, zones'), None, []
          | _ ->
            Log.warn (fun m -> m "ignoring unsolicited notauth error");
            (t, zones), None, []
      end
    | `Rcode_error (rc, Opcode.Query, _) ->
      (* errors with IXFR: try AXFR *)
      begin match Domain_name.host (fst p.Packet.question) with
        | Error _ ->
          Log.warn (fun m -> m "rcode error with non-hostname zone %a"
                       Domain_name.pp (fst p.Packet.question));
          (t, zones), None, []
        | Ok zone ->
          match authorise_zone zones keyname p.Packet.header zone with
          | Ok (Requested_ixfr (_, _, _, _), _, name) ->
            Log.warn (fun m -> m "received %a reply for %a, requested ixfr, trying with AXFR"
                         Rcode.pp rc Domain_name.pp zone);
            begin match axfr t `Tcp now ts zone name with
              | None -> Log.err (fun m -> m "failed to construct AXFR"); (t, zones), None, []
              | Some (st, buf) ->
                Log.debug (fun m -> m "requesting AXFR for %a now!" Domain_name.pp zone);
                let zones' = Domain_name.Host_map.add zone (st, ip, name) zones in
                (t, zones'), None, [ `Tcp, ip, buf ]
            end
          | _ ->
            Log.warn (fun m -> m "ignoring unsolicited notauth error");
            (t, zones), None, []
      end
    | `Axfr_reply data ->
      begin match Domain_name.host (fst p.question) with
        | Error _ ->
          Log.warn (fun m -> m "axfr reply with non-hostname zone %a"
                       Domain_name.pp (fst p.question));
          (t, zones), None, []
        | Ok zone ->
          let r, out = match handle_axfr t zones ts keyname p.header zone data with
            | Ok (t, zones, out) -> (t, zones), out
            | Error rcode ->
              Log.warn (fun m -> m "error %a while processing axfr %a" Rcode.pp rcode Packet.pp p);
              (t, zones), []
          in
          r, None, out
      end
    | `Ixfr_reply data ->
      begin match Domain_name.host (fst p.question) with
        | Error _ -> Log.warn (fun m -> m "ixfr where zone is not a hostname %a" Domain_name.pp (fst p.question));
          (t, zones), None, []
        | Ok zone ->
          let r, out = match handle_ixfr t zones ts keyname p.header zone data with
            | Ok (t, zones, out) -> (t, zones), out
            | Error rcode ->
              Log.warn (fun m -> m "error %a while processing axfr %a" Rcode.pp rcode Packet.pp p);
              (t, zones), []
          in
          r, None, out
      end
    | `Update_ack ->
      Log.warn (fun m -> m "ignoring update reply (we'll never send updates out)");
      (t, zones), None, []
    | `Notify n ->
      begin match Domain_name.host (fst p.question) with
        | Error _ ->
          Log.warn (fun m -> m "notify for non-hostname zone %a" Domain_name.pp
                       (fst p.question));
          (t, zones), None, []
        | Ok zone ->
          let zones, flags, answer, out = match handle_notify t zones now ts ip zone (snd p.question) n keyname with
            | Ok (zones, out) -> zones, authoritative, `Notify_ack, out
            | Error rcode -> zones, err_flags rcode, `Rcode_error (rcode, Opcode.Notify, None), []
          in
          let answer = Packet.create (fst p.header, flags) p.question answer in
          (t, zones), Some answer, out
      end
    | `Notify_ack ->
      Log.err (fun m -> m "ignoring notify response (we don't send notifications)") ;
      (t, zones), None, []
    | `Rcode_error (rc, op, data) ->
      Log.err (fun m -> m "ignoring rcode error %a for op %a data %a" Rcode.pp rc Opcode.pp op
                  Fmt.(option ~none:(unit "no") Packet.Answer.pp) data);
      (t, zones), None, []

  let find_mac zones p =
    match p.Packet.data with
    | #Packet.request -> None
    | #Packet.reply ->
      match Domain_name.host (fst p.question) with
      | Error _ -> None
      | Ok zone ->
        match Domain_name.Host_map.find zone zones with
        | None -> None
        | Some (Requested_axfr (_, _, mac), _, _) -> Some mac
        | Some (Requested_ixfr (_, _, _, mac), _, _) -> Some mac
        | Some (Requested_soa (_, _, _, mac), _, _) -> Some mac
        | _ -> None

  let handle_buf t now ts proto ip buf =
    match
      safe_decode buf >>| fun res ->
      Log.debug (fun m -> m "received a packet from %a: %a" Ipaddr.V4.pp ip Packet.pp res) ;
      res
    with
    | Error rcode -> t, Packet.raw_error buf rcode, []
    | Ok p ->
      let handle_inner keyname =
        let t, answer, out = handle_packet t now ts ip p keyname in
        let answer = match answer with
          | Some answer ->
            let max_size, edns = Edns.reply p.edns in
            let answer = Packet.with_edns answer edns in
            let r = Packet.encode ?max_size proto answer in
            Some (answer, r)
          | None -> None
        in
        t, answer, out
      in
      let server, zones = t in
      let mac = find_mac zones p in
      match handle_tsig ?mac server now p buf with
      | Error (e, data) ->
        Logs.err (fun m -> m "error %a while handling tsig" Tsig_op.pp_e e) ;
        t, data, []
      | Ok None ->
        let t, answer, out = handle_inner None in
        let answer' = match answer with
          | None -> None
          | Some (_, (buf, _)) -> Some buf
        in
        t, answer', out
      | Ok (Some (name, tsig, mac, key)) ->
        let t, answer, out = handle_inner (Some name) in
        let answer' = match answer with
        | Some (p, (buf, max_size)) ->
          begin match server.tsig_sign ~max_size ~mac name tsig ~key p buf with
            | None ->
              (* TODO: output buf? *)
              Log.warn (fun m -> m "couldn't use %a to tsig sign"
                           Domain_name.pp name) ;
              None
            | Some (buf, _) -> Some buf
          end
        | None -> None
        in
        t, answer', out

  let closed (t, zones) now ts ip' =
    (* if this ip and port was registered for zone(s), we re-open connections to the remote servers*)
    let xs =
      Domain_name.Host_map.fold (fun zone (_, ip, keyname) acc ->
          if Ipaddr.V4.compare ip ip' = 0 then
            match Authentication.find_zone_ips keyname with
            (* returns zone primary_ip secondary_ip -- for the hidden secondary the latter is None *)
            | Some (_, _, None) ->
              begin match query_soa t `Tcp now ts zone keyname with
                | None -> acc
                | Some (st, data) ->
                  ((zone, (st, ip, keyname)), (`Tcp, ip, data)) :: acc
              end
            | _ -> acc
          else acc)
        zones []
    in
    let zones', out = List.split xs in
    let zones'' = List.fold_left (fun z (zone, v) -> Domain_name.Host_map.add zone v z) zones zones' in
    (t, zones''), out
end
