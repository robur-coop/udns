(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

(* The cache (a Map!?) for answers: once a specific type/name comes in, we know
   which questions can progress now *)
module K = struct
  type t = Udns_enum.rr_typ * Domain_name.t

  let compare (t, n) (t', n') = match Domain_name.compare n n' with
    | 0 -> compare (Udns_enum.rr_typ_to_int t) (Udns_enum.rr_typ_to_int t')
    | x -> x
end

module QM = Map.Make(K)

type awaiting =
  int64 * int * Udns_types.proto * Domain_name.t * Udns_packet.opt option
                * Ipaddr.V4.t * int * Udns_types.question * int

open Rresult.R.Infix

let retry_interval = Duration.of_ms 500

type stats = {
  questions : int ;
  responses : int ;
  answers : int ;
  authoritative : int ;
  delegation : int ;
  errors : int ;
  drops : int ;
  retransmits : int ;
  total_out : int ;
  max_out : int ;
  total_time : int64 ;
  max_time : int64 ;
  drop_timeout : int ;
  drop_send : int ;
  retry_edns : int ;
  tcp_upgrade : int ;
}

let empty_stats () = {
  questions = 0 ; responses = 0 ; answers = 0 ;
  authoritative = 0 ; delegation = 0 ;
  errors = 0 ; drops = 0 ; retransmits = 0 ;
  total_out = 0 ; max_out = 0 ; drop_timeout = 0 ; drop_send = 0 ;
  retry_edns = 0 ; total_time = 0L ; max_time = 0L ; tcp_upgrade = 0 ;
}

let s = ref (empty_stats ())

let pp_stats pf s =
  let avg = if s.answers = 0 then 0L else Int64.div s.total_time (Int64.of_int s.answers) in
  let avg_out = if s.answers = 0 then 0. else float_of_int s.total_out /. float_of_int s.answers in
  Fmt.pf pf "%d questions, %d answers max %a (avg %a)@.%d received responses, %d authoritative, %d delegations, %d errors, %d dropped replies, %d retransmits, %d noedns retries, %d tcp upgrade@.%f average out (%d max), %d timeout drops %d max_out drops"
    s.questions s.answers Duration.pp s.max_time Duration.pp avg s.responses s.authoritative s.delegation s.errors s.drops s.retransmits s.retry_edns s.tcp_upgrade avg_out s.max_out s.drop_timeout s.drop_send

type t = {
  rng : int -> Cstruct.t ;
  primary : Udns_server.Primary.s ;
  cache : Udns_resolver_cache.t ;
  transit : awaiting QM.t ;
  queried : awaiting list QM.t ;
  mode : [ `Stub | `Recursive ] ;
}

let create ?(size = 10000) ?(mode = `Recursive) now rng primary =
  let cache = Udns_resolver_cache.empty size in
  let cache =
    List.fold_left (fun cache (name, rr) ->
        Udns_resolver_cache.maybe_insert
          Udns_enum.A name now Udns_resolver_entry.Additional
          (Udns_resolver_entry.NoErr [ rr ]) cache)
      cache Udns_resolver_root.a_records
  in
  let cache =
    Udns_resolver_cache.maybe_insert
      Udns_enum.NS Domain_name.root now Udns_resolver_entry.Additional
      (Udns_resolver_entry.NoErr Udns_resolver_root.ns_records) cache
  in
  { rng ; cache ; primary ; transit = QM.empty ; queried = QM.empty ; mode }

let header id = { Udns_packet.id ; query = true ; operation = Udns_enum.Query ;
                  authoritative = false ; truncation = false ; recursion_desired = false ;
                  recursion_available = false ; authentic_data = false ;
                  checking_disabled = false ; rcode = Udns_enum.NoError }

let build_query ?id ?(recursion_desired = false) t ts proto q retry zone edns ip =
  let id = match id with Some id -> id | None -> Randomconv.int16 t.rng in
  let header =
    let hdr = header id in
    (* TODO not clear about this.. *)
    { hdr with Udns_packet.recursion_desired }
  in
  let query = `Query { Udns_packet.question = [q] ; answer = [] ; authority = [] ; additional = [] } in
  let el = (ts, retry, proto, zone, edns, ip, 53, q, id) in
  let k = (q.Udns_types.q_type, q.Udns_types.q_name) in
  let transit =
    if QM.mem k t.transit then
      Logs.warn (fun m -> m "overwriting transit of %a (%a)" Domain_name.pp (snd k) Udns_enum.pp_rr_typ (fst k)) ;
    QM.add k el t.transit
  in
  transit, header, query

let maybe_query ?recursion_desired t ts retry out ip typ name (proto, zone, edns, orig_s, orig_p, orig_q, orig_id) =
  let k = (typ, name) in
  let await = (ts, succ out, proto, zone, edns, orig_s, orig_p, orig_q, orig_id) in
  if QM.mem k t.queried then
    let t = { t with queried = QM.add k (await :: QM.find k t.queried) t.queried } in
    `Nothing, t
  else
    let edns = Some (Udns_packet.opt ())
    and proto = `Udp
    in
    let quest = { Udns_types.q_type = typ ; q_name = name } in
    (* TODO: is `Udp good here? *)
    let transit, hdr, packet = build_query ?recursion_desired t ts proto quest retry zone edns ip in
    let t = { t with transit ; queried = QM.add k [await] t.queried } in
    Logs.debug (fun m -> m "maybe_query: query %a %a %a" Ipaddr.V4.pp ip
                   Udns_packet.pp_header hdr Udns_packet.pp_v packet) ;
    let packet, _ = Udns_packet.encode ?edns proto hdr packet in
    `Query (packet, ip), t

let was_in_transit t typ name id sender =
  let key = (typ, name) in
  match QM.find key t with
  | exception Not_found ->
    s := { !s with drops = succ !s.drops } ;
    Logs.warn (fun m -> m "key %a (%a) not present in set (likely retransmitted)"
                  Domain_name.pp name Udns_enum.pp_rr_typ typ) ;
    None, t
  | (_ts, _retry, _proto, zone, edns, o_sender, _o_port, _o_q, o_id) ->
    if Ipaddr.V4.compare sender o_sender = 0 && id = o_id then
      Some (zone, edns), QM.remove key t
    else
      (Logs.warn (fun m -> m "unsolicited reply for %a (%a) (id %d vs o_id %d, sender %a vs o_sender %a)"
                    Domain_name.pp name Udns_enum.pp_rr_typ typ
                    id o_id Ipaddr.V4.pp sender Ipaddr.V4.pp o_sender) ;
       None, t)

let find_queries t k =
  match QM.find k t with
  | exception Not_found ->
    Logs.warn (fun m -> m "couldn't find entry %a (%a) in map"
                  Domain_name.pp (snd k) Udns_enum.pp_rr_typ (fst k)) ;
    s := { !s with drops = succ !s.drops } ;
    t, []
  | vals ->
    QM.remove k t, vals

let stats t =
  Logs.info (fun m -> m "stats: %a@.%a@.%d cached resource records (capacity: %d)"
                pp_stats !s
                Udns_resolver_cache.pp_stats (Udns_resolver_cache.stats ())
                (Udns_resolver_cache.items t.cache) (Udns_resolver_cache.capacity t.cache)) ;
  let names = List.map (fun (t, n) -> (n, t)) (fst (List.split (QM.bindings t.transit))) in
  Logs.info (fun m -> m "%d queries in transit %a" (QM.cardinal t.transit)
                Fmt.(list ~sep:(unit "; ")
                       (pair ~sep:(unit ", ") Domain_name.pp Udns_enum.pp_rr_typ))
                       names) ;
  let qs = List.map (fun ((t, n), v) -> (List.length v, (n, t))) (QM.bindings t.queried) in
  Logs.info (fun m -> m "%d queries %a" (QM.cardinal t.queried)
                Fmt.(list ~sep:(unit "; ")
                       (pair ~sep:(unit ": ") int
                          (pair ~sep:(unit ", ") Domain_name.pp Udns_enum.pp_rr_typ)))
                qs)

let handle_query t its out ?(retry = 0) proto edns from port ts q qid =
  if Int64.sub ts its > Int64.shift_left retry_interval 2 then begin
    Logs.warn (fun m -> m "dropping q %a from %a:%d (timed out)"
                  Udns_types.pp_question q Ipaddr.V4.pp from port) ;
    s := { !s with drop_timeout = succ !s.drop_timeout } ;
    `Nothing, t
  end else
    let r, cache = Udns_resolver_cache.handle_query t.cache ~rng:t.rng (* primary *) ts q qid in
    let t = { t with cache } in
    match r with
    | `Query _ when out >= 30 ->
      Logs.warn (fun m -> m "dropping q %a from %a:%d (already sent 30 packets)"
                    Udns_types.pp_question q Ipaddr.V4.pp from port) ;
      s := { !s with drop_send = succ !s.drop_send } ;
      (* TODO reply with error! *)
      `Nothing, t
    | `Query (zone, nam, typ, ip) ->
      Logs.debug (fun m -> m "have to query (zone %a) %a (%a) using ip %a"
                     Domain_name.pp zone
                     Domain_name.pp nam Udns_enum.pp_rr_typ typ Ipaddr.V4.pp ip) ;
      maybe_query t ts retry out ip typ nam (proto, zone, edns, from, port, q, qid)
    | `Answer (hdr, a) ->
      let max_out = if !s.max_out < out then out else !s.max_out in
      let time = Int64.sub ts its in
      let max_time = if !s.max_time < time then time else !s.max_time in
      s := { !s with
             answers = succ !s.answers ;
             max_out ; total_out = !s.total_out + out ;
             max_time ; total_time = Int64.add !s.total_time time ;
           } ;
      Logs.debug (fun m -> m "answering %a (%a) after %a %d out packets: %a %a"
                     Domain_name.pp q.Udns_types.q_name
                     Udns_enum.pp_rr_typ q.Udns_types.q_type
                     Duration.pp time out
                     Udns_packet.pp_header hdr
                     Udns_packet.pp_v a) ;
      let max_size, edns = Udns_packet.reply_opt edns in
      let cs, _ = Udns_packet.encode ?max_size ?edns proto hdr a in
      `Answer cs, t
    | `Nothing -> `Nothing, t

let scrub_it mode t proto zone edns ts q header query =
  match Udns_resolver_utils.scrub ~mode zone q header query, edns with
  | Ok xs, _ ->
    let cache =
      List.fold_left
        (fun t (ty, n, r, e) ->
           Logs.debug (fun m -> m "maybe_insert %a %a %a"
                            Udns_enum.pp_rr_typ ty Domain_name.pp n Udns_resolver_entry.pp_res e) ;
           Udns_resolver_cache.maybe_insert ty n ts r e t)
        t xs
    in
    if header.Udns_packet.truncation && proto = `Udp then
      (Logs.warn (fun m -> m "NS truncated reply, using TCP now") ;
       `Upgrade_to_tcp cache)
    else
      `Cache cache
  | Error Udns_enum.FormErr, Some _ ->
    Logs.warn (fun m -> m "NS sent FormErr, retrying without edns!") ;
    `Query_without_edns
  | Error e, _ ->
    Logs.warn (fun m -> m "NS didn't like us %a" Udns_enum.pp_rcode e) ;
    `Try_another_ns

let guard p err = if p then Ok () else Error (err ())

let handle_primary t now ts proto sender sport header v opt tsig tsig_off buf =
  (* makes only sense to ask primary for query=true since we'll never issue questions from primary *)
  let handle_inner name =
    if not header.Udns_packet.query then
      `No
    else
      match Udns_server.Primary.handle_frame t ts sender sport proto name header v with
      | Ok (_, None, _, _) -> `None (* incoming notifications are never replied to *)
      | Ok (t, Some (header, v'), _, _) ->
          (* delegation if authoritative is not set! *)
          if header.Udns_packet.authoritative then begin
            s := { !s with authoritative = succ !s.authoritative } ;
            let max_size, edns = Udns_packet.reply_opt opt in
            Logs.debug (fun m -> m "authoritative reply %a %a" Udns_packet.pp_header header Udns_packet.pp_v v) ;
            let out = Udns_packet.encode ?max_size ?edns proto header v' in
            `Reply (t, out)
          end else begin
            s := { !s with delegation = succ !s.delegation } ;
            `Delegation v'
          end
      | Error rcode ->
        Logs.debug (fun m -> m "authoritative returned %a" Udns_enum.pp_rcode rcode) ;
        `No
  in
  match Udns_server.handle_tsig (Udns_server.Primary.server t) now header v tsig tsig_off buf with
  | Error (Some data) -> `Reply (t, (data, 0))
  | Error None -> `None
  | Ok None -> handle_inner None
  | Ok (Some (name, tsig, mac, key)) ->
    match handle_inner (Some name) with
    | `Reply (t, (buf, max_size)) ->
      begin match Udns_server.((Primary.server t).tsig_sign) ~max_size ~mac name tsig ~key buf with
        | None ->
          Logs.warn (fun m -> m "couldn't use %a to tsig sign, using unsigned reply" Domain_name.pp name) ;
          `Reply (t, (buf, max_size))
        | Some (buf, _) -> `Reply (t, (buf, 0))
      end
    | x -> x

let supported = [ Udns_enum.A ; Udns_enum.NS ; Udns_enum.CNAME ;
                  Udns_enum.SOA ; Udns_enum.PTR ; Udns_enum.MX ;
                  Udns_enum.TXT ; Udns_enum.AAAA ; Udns_enum.SRV ;
                  Udns_enum.SSHFP ; Udns_enum.TLSA ;
                  Udns_enum.ANY ]

let handle_awaiting_queries ?retry t ts q =
  let queried, values = find_queries t.queried (q.Udns_types.q_type, q.Udns_types.q_name) in
  let t = { t with queried } in
  List.fold_left (fun (t, out_a, out_q) (old_ts, out, proto, _, edns, from, port, q, qid) ->
      Logs.debug (fun m -> m "now querying %a" Udns_types.pp_question q) ;
      match handle_query ?retry t old_ts out proto edns from port ts q qid with
      | `Nothing, t -> t, out_a, out_q
      | `Query (pkt, dst), t -> t, out_a, (`Udp, dst, pkt) :: out_q
      | `Answer pkt, t -> t, (proto, from, port, pkt) :: out_a, out_q)
    (t, [], []) values

let resolve t ts proto sender sport header v opt =
  let id = header.Udns_packet.id
  and error rcode =
    s := { !s with errors = succ !s.errors } ;
    let header = { header with Udns_packet.query = not header.Udns_packet.query } in
    match Udns_packet.error header v rcode with
    | None -> None
    | Some (cs, _) -> Some cs
  in
  match v with
  | `Query query ->
    let q = match query.Udns_packet.question with | [x] -> Some x | _ -> None in
    Logs.info (fun m -> m "resolving %a %a" Udns_packet.pp_header header
                  Fmt.(option ~none:(unit "none") Udns_types.pp_question) q) ;
    begin match query.Udns_packet.question with
      | [ q ] ->
        if not header.Udns_packet.recursion_desired then
          Logs.warn (fun m -> m "recursion not desired") ;
        guard (List.mem q.Udns_types.q_type supported)
          (fun () ->
             Logs.err (fun m -> m "unsupported query type %a"
                          Udns_enum.pp_rr_typ q.Udns_types.q_type) ;
             error Udns_enum.NotImp) >>= fun () ->
        s := { !s with questions = succ !s.questions } ;
        (* ask the cache *)
        begin match handle_query t ts 0 proto opt sender sport ts q id with
          | `Answer pkt, t -> Ok (t, [ (proto, sender, sport, pkt) ], [])
          | `Nothing, t -> Ok (t, [], [])
          | `Query (packet, dst), t -> Ok (t, [], [ `Udp, dst, packet ])
        end
      | question ->
        Logs.warn (fun m -> m "got %d questions %a"
                      (List.length question)
                      Fmt.(list ~sep:(unit ";@ ") Udns_types.pp_question) question) ;
        Error (error Udns_enum.FormErr)
    end (* `Query query *)
  | v ->
    Logs.err (fun m -> m "ignoring %a %a" Udns_packet.pp_header header Udns_packet.pp_v v) ;
    Error (error Udns_enum.FormErr)

let handle_reply t ts proto sender header v =
  let id = header.Udns_packet.id
  and error rcode =
    s := { !s with errors = succ !s.errors } ;
    let header = { header with Udns_packet.query = not header.Udns_packet.query } in
    match Udns_packet.error header v rcode with
    | None -> None
    | Some (cs, _) -> Some cs
  in
  match v with
  | `Query query ->
    let q = match query.Udns_packet.question with | [x] -> Some x | _ -> None in
    Logs.info (fun m -> m "handling reply %a %a" Udns_packet.pp_header header
                  Fmt.(option ~none:(unit "none") Udns_types.pp_question) q) ;
    begin match query.Udns_packet.question with
      | [ q ] ->
        (* (a) first check whether frame was in transit! *)
        let r, transit = was_in_transit t.transit q.Udns_types.q_type q.Udns_types.q_name id sender in
        let t = { t with transit } in
        let r = match r with
          | None -> (t, [], [])
          | Some (zone, edns) ->
            s := { !s with responses = succ !s.responses } ;
            (* (b) now we scrub and either *)
            match scrub_it t.mode t.cache proto zone edns ts q header query with
            | `Query_without_edns ->
              s := { !s with retry_edns = succ !s.retry_edns } ;
              let transit, header, packet = build_query t ts proto q 1 zone None sender in
              Logs.debug (fun m -> m "resolve: requery without edns %a %a %a"
                             Ipaddr.V4.pp sender Udns_packet.pp_header header
                             Udns_packet.pp_v packet) ;
              let cs, _ = Udns_packet.encode `Udp header packet in
              ({ t with transit }, [], [ `Udp, sender, cs ])
            | `Upgrade_to_tcp cache ->
              s := { !s with tcp_upgrade = succ !s.tcp_upgrade } ;
              (* RFC 2181 Sec 9: correct would be to drop entire frame, and retry with tcp *)
              (* but we're happy to retrieve the partial information, it may be useful *)
              let t = { t with cache } in
              (* this may provoke the very same question again -
                 but since tcp is first, that should trigger the TCP connection,
                 which is then reused... ok, we may send the same query twice
                 with different ids *)
              (* TODO we may want to get rid of the handle_awaiting_queries
                 entirely here!? *)
              let (t, out_a, out_q), recursion_desired =
                match t.mode with
                | `Stub -> (t, [], []), true
                | `Recursive -> handle_awaiting_queries t ts q, false
              in
              (* TODO why is edns none here?  is edns bad over tcp? *)
              let transit, header, packet = build_query ~recursion_desired t ts `Tcp q 1 zone None sender in
              Logs.debug (fun m -> m "resolve: upgrade to tcp %a %a %a"
                             Ipaddr.V4.pp sender
                             Udns_packet.pp_header header
                             Udns_packet.pp_v packet) ;
              let cs, _ = Udns_packet.encode `Tcp header packet in
              ({ t with transit }, out_a, (`Tcp, sender, cs) :: out_q)
            | `Try_another_ns ->
              (* is this the right behaviour? by luck we'll use another path *)
              handle_awaiting_queries t ts q
            | `Cache cache ->
              let t = { t with cache } in
              handle_awaiting_queries t ts q
        in
        Ok r
      | question ->
        Logs.warn (fun m -> m "got %d questions %a"
                      (List.length question)
                      Fmt.(list ~sep:(unit ";@ ") Udns_types.pp_question) question) ;
        Error (error Udns_enum.FormErr)
    end (* `Query query *)
  | v ->
    Logs.err (fun m -> m "ignoring %a %a" Udns_packet.pp_header header Udns_packet.pp_v v) ;
    Error (error Udns_enum.FormErr)

let handle_delegation t ts proto sender sport header v opt v' =
  Logs.debug (fun m -> m "handling delegation %a (for %a)"
                 Udns_packet.pp_v v' Udns_packet.pp_v v) ;
  let error rcode =
    s := { !s with errors = succ !s.errors } ;
    let header = { header with Udns_packet.query = not header.Udns_packet.query } in
    match Udns_packet.error header v rcode with
    | None -> t, [], []
    | Some (cs, _) -> t, [ (proto, sender, sport, cs) ], []
  in
  match v with
  | `Query q ->
    begin match q.Udns_packet.question with
      | [ q ] ->
        begin match Udns_resolver_cache.answer t.cache ts q header.Udns_packet.id with
          | `Query (name, cache) ->
            (* parse v', which should contain an a record
               ask that for the very same query! *)
            let t = { t with cache } in
            let ip =
              match
                List.fold_left (fun acc rr -> match rr.Udns_packet.rdata with
                    | Udns_packet.A ip -> ip :: acc
                    | _ -> acc) []
                  (match v' with `Query v -> v.Udns_packet.additional | _ -> [])
              with
              | [] -> invalid_arg "bad delegation"
              | [ ip ] -> ip
              | ips ->
                List.nth ips (Randomconv.int ~bound:(List.length ips) t.rng)
            in
            Logs.debug (fun m -> m "found ip %a, maybe querying for %a (%a)"
                           Ipaddr.V4.pp ip Udns_enum.pp_rr_typ q.Udns_types.q_type Domain_name.pp name) ;
            (* TODO is Domain_name.root correct here? *)
            begin match maybe_query ~recursion_desired:true t ts 0 0 ip q.Udns_types.q_type name (proto, Domain_name.root, opt, sender, sport, q, header.Udns_packet.id) with
              | `Nothing, t ->
                Logs.warn (fun m -> m "maybe_query for %a at %a returned nothing"
                              Domain_name.pp name Ipaddr.V4.pp ip) ;
                t, [], []
              | `Query (cs, ip), t -> t, [], [ (`Udp, ip, cs) ]
            end
          | `Packet (header, pkt, cache) ->
            let max_size, edns = Udns_packet.reply_opt opt in
            Logs.debug (fun m -> m "delegation reply from cache %a %a"
                           Udns_packet.pp_header header Udns_packet.pp_v pkt) ;
            let pkt, _ = Udns_packet.encode ?max_size ?edns proto header pkt in
            { t with cache }, [ (proto, sender, sport, pkt) ], []
            (* send it out! we've a cache hit here! *)
        end
      | question ->
        Logs.warn (fun m -> m "got %d questions %a"
                      (List.length question)
                      Fmt.(list ~sep:(unit ";@ ") Udns_types.pp_question) question) ;
        error Udns_enum.FormErr
    end (* `Query query *)
  | v ->
    Logs.err (fun m -> m "ignoring %a %a" Udns_packet.pp_header header Udns_packet.pp_v v) ;
    error Udns_enum.FormErr

let handle_error ?(error = Udns_enum.FormErr) proto sender sport buf =
  match Udns_packet.decode_header buf with
  | Error e ->
    Logs.err (fun m -> m "couldn't parse header %a:@.%a"
                 Udns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    []
  | Ok header ->
    let empty =
      `Query { Udns_packet.question = [] ; answer = [] ;
               authority = [] ; additional = [] }
    and header = { header with Udns_packet.query = not header.Udns_packet.query }
    in
    match Udns_packet.error header empty error with
    | None -> []
    | Some (cs, _) -> [ (proto, sender, sport, cs) ]

let handle t now ts query proto sender sport buf =
  match Udns_packet.decode buf with
  | Error (`Bad_edns_version v) ->
    Logs.err (fun m -> m "bad edns version (from %a:%d) %u for@.%a"
                 Ipaddr.V4.pp sender sport
                 v Cstruct.hexdump_pp buf) ;
    s := { !s with errors = succ !s.errors } ;
    t, handle_error ~error:Udns_enum.BadVersOrSig proto sender sport buf, []
  | Error e ->
    Logs.err (fun m -> m "parse error (from %a:%d) %a for@.%a"
                 Ipaddr.V4.pp sender sport
                 Udns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    s := { !s with errors = succ !s.errors } ;
    t, handle_error proto sender sport buf, []
  | Ok ((header, v, opt, tsig), tsig_off) ->
    Logs.info (fun m -> m "reacting to (from %a:%d) %a: %a"
                  Ipaddr.V4.pp sender sport
                  Udns_packet.pp_header header
                  Udns_packet.pp_v v) ;
    match header.Udns_packet.query, query with
    | true, true ->
      begin
        match handle_primary t.primary now ts proto sender sport header v opt tsig tsig_off buf with
        | `Reply (primary, (pkt, _)) ->
          { t with primary }, [ (proto, sender, sport, pkt) ], []
        | `Delegation v' ->
          handle_delegation t ts proto sender sport header v opt v'
        | `None -> t, [], []
        | `No ->
          match resolve t ts proto sender sport header v opt with
          | Ok a -> a
          | Error (Some e) -> t, [ (proto, sender, sport, e) ], []
          | Error None -> t, [], []
      end
    | false, false ->
      begin
        match handle_reply t ts proto sender header v with
        | Ok a -> a
        | Error (Some e) -> t, [ (proto, sender, sport, e) ], []
        | Error None -> t, [], []
      end
    | _, _ ->
      Logs.err (fun m -> m "ignoring unsolicited packet (query allowed? %b)" query);
      t, [], []

let query_root t now proto =
  let q_name = Domain_name.root
  and q_type = Udns_enum.NS
  in
  let ip, cache =
    match Udns_resolver_cache.find_ns t.cache t.rng now Domain_name.Set.empty q_name with
    | `HaveIP ip, cache -> ip, cache
    | _ ->
      let roots = snd (List.split Udns_resolver_root.root_servers) in
      (List.nth roots (Randomconv.int ~bound:(List.length roots) t.rng),
       t.cache)
  in
  let q = { Udns_types.q_name ; q_type }
  and id = Randomconv.int16 t.rng
  in
  let packet = `Query { Udns_packet.question = [q] ; answer = [] ; authority = [] ; additional = [] } in
  let edns = Some (Udns_packet.opt ()) in
  let el = (now, 0, proto, Domain_name.root, edns, ip, 53, q, id) in
  let t = { t with transit = QM.add (q_type, q_name) el t.transit ; cache } in
  let cs, _ = Udns_packet.encode ?edns proto (header id) packet in
  t, (proto, ip, cs)

let max_retries = 5

let err_retries t q_type q_name =
  let t, reqs = find_queries t (q_type, q_name) in
  t, List.fold_left (fun acc (_, _, proto, _, _, ip, port, q, qid) ->
      Logs.debug (fun m -> m "now erroring to %a" Udns_types.pp_question q) ;
      let q = `Query { Udns_packet.question = [ q ] ; answer = [] ; authority = [] ; additional = [] } in
      let header =
        let h = header qid in
        { h with Udns_packet.query = false }
      in
      match Udns_packet.error header q Udns_enum.ServFail with
      | None -> acc
      | Some (pkt, _) -> (proto, ip, port, pkt) :: acc)
    [] reqs

let try_other_timer t ts =
  let transit, rem =
    QM.partition
      (fun _ (c, _, _, _, _, _, _, _, _) -> Int64.sub ts c < retry_interval)
      t.transit
  in
  let t = { t with transit } in
  if QM.cardinal transit > 0 || QM.cardinal rem > 0 then
    Logs.debug (fun m -> m "try_other timer wheel -- keeping %d, running over %d"
                   (QM.cardinal transit) (QM.cardinal rem)) ;
  QM.fold (fun (q_type, q_name) (_, retry, _, _, _, qs, _, _, _) (t, out_a, out_q) ->
      let retry = succ retry in
      if retry < max_retries then begin
        s := { !s with retransmits = succ !s.retransmits } ;
        let q = { Udns_types.q_name ; q_type } in
        let t, outa, outq = handle_awaiting_queries ~retry t ts q in
        (t, outa @ out_a, outq @ out_q)
      end else begin
        Logs.info (fun m -> m "retry limit exceeded for %a (%a) at %a!"
                      Domain_name.pp q_name Udns_enum.pp_rr_typ q_type
                      Ipaddr.V4.pp qs) ;
        let queried, out_as = err_retries t.queried q_type q_name in
        ({ t with queried }, out_as @ out_a, out_q)
      end)
    rem (t, [], [])

let _retry_timer t ts =
  if QM.cardinal t.transit > 0 then
    Logs.debug (fun m -> m "retry timer with %d entries" (QM.cardinal t.transit)) ;
  List.fold_left (fun (t, out_a, out_q) ((q_type, q_name), (c, retry, proto, zone, edns, qs, _port, _query, id)) ->
      if Int64.sub ts c < retry_interval then
        (Logs.debug (fun m -> m "ignoring retransmit %a (%a) for now %a"
                        Domain_name.pp q_name Udns_enum.pp_rr_typ q_type
                        Duration.pp (Int64.sub ts c) ) ;
         (t, out_a, out_q))
      else
        let retry = succ retry in
        if retry < max_retries then begin
          s := { !s with retransmits = succ !s.retransmits } ;
          Logs.info (fun m -> m "retransmit %a %a (%d of %d) to %a"
                        Domain_name.pp q_name Udns_enum.pp_rr_typ q_type
                        retry max_retries Ipaddr.V4.pp qs) ;
          let transit, header, packet = build_query ~id t ts proto { Udns_types.q_type ; q_name } retry zone edns qs in
          let cs, _ = Udns_packet.encode ?edns proto header packet in
          { t with transit }, out_a, (`Udp, qs, cs) :: out_q
        end else begin
          Logs.info (fun m -> m "retry limit exceeded for %a (%a) at %a!"
                        Domain_name.pp q_name Udns_enum.pp_rr_typ q_type
                        Ipaddr.V4.pp qs) ;
          (* answer all outstanding requestors! *)
          let transit = QM.remove (q_type, q_name) t.transit in
          let t = { t with transit } in
          let queried, out_as = err_retries t.queried q_type q_name in
          ({ t with queried }, out_as @ out_a, out_q)
        end)
    (t, [], []) (QM.bindings t.transit)

let timer = try_other_timer
