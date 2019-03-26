(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
(*

let rdata_name = function
  | MX (_, n) -> Domain_name.Set.singleton n
  | NS n -> Domain_name.Set.singleton n
  | SRV srv -> Domain_name.Set.singleton srv.target
  | _ -> Domain_name.Set.empty

let decode_rdata names buf off len = function
  | Udns_enum.TSIG ->
    decode_tsig names buf off >>= fun (tsig, names, off) ->
    Ok (TSIG tsig, names, off)
  | x -> Ok (Raw (x, Cstruct.sub buf off len), names, off + len)

let encode_rdata offs buf off = function
  | TSIG t -> encode_tsig t offs buf off
  | OPTS opts -> offs, encode_extensions opts.extensions buf off
  | Raw (_, rr) ->
    let len = Cstruct.len rr in
    Cstruct.blit rr 0 buf off len ;
    offs, off + len

type rr = {
  name : Domain_name.t ;
  ttl : int32 ;
  rdata : rdata
}

(*BISECT-IGNORE-BEGIN*)
let pp_rr ppf rr =
  Fmt.pf ppf "%a TTL %lu %a" Domain_name.pp rr.name rr.ttl pp_rdata rr.rdata

let pp_rrs = Fmt.(list ~sep:(unit ";@.") pp_rr)
(*BISECT-IGNORE-END*)

let rr_equal a b =
  Domain_name.compare a.name b.name = 0 &&
  a.ttl = b.ttl &&
  compare_rdata a.rdata b.rdata = 0

let rr_name rr = rdata_name rr.rdata

let rr_names =
  List.fold_left
    (fun acc rr -> Domain_name.Set.union (rr_name rr) acc)
    Domain_name.Set.empty

let encode_rr offs buf off rr =
  let clas, ttl = match rr.rdata with
    | OPTS opt ->
      let ttl =
        Int32.(add (shift_left (of_int opt.extended_rcode) 24)
                 (add (shift_left (of_int opt.version) 16)
                    (if opt.dnssec_ok then 0x8000l else 0x0000l)))
      in
      opt.payload_size, ttl
    | TSIG _ -> Udns_enum.(clas_to_int ANY_CLASS), 0l
    | _ -> Udns_enum.(clas_to_int IN), rr.ttl
  in
  let typ = rdata_to_rr_typ rr.rdata in
  let offs, off = encode_ntc offs buf off (rr.name, typ, clas) in
  Cstruct.BE.set_uint32 buf off ttl ;
  let offs, off' = encode_rdata offs buf (off + 6) rr.rdata in
  Cstruct.BE.set_uint16 buf (off + 4) (off' - (off + 6)) ;
  offs, off'


(*BISECT-IGNORE-BEGIN*)
let pp_query ppf t =
  Fmt.pf ppf "%a@ %a@ %a@ %a"
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_question) t.question
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr) t.answer
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr) t.authority
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr) t.additional
(*BISECT-IGNORE-END*)

(*
(* UPDATE *)
type rr_prereq =
  | Exists of Domain_name.t * Udns_enum.rr_typ
  | Exists_data of Domain_name.t * rdata
  | Not_exists of Domain_name.t * Udns_enum.rr_typ
  | Name_inuse of Domain_name.t
  | Not_name_inuse of Domain_name.t

(*BISECT-IGNORE-BEGIN*)
let pp_rr_prereq ppf = function
  | Exists (name, typ) ->
    Fmt.pf ppf "exists? %a %a" Domain_name.pp name Udns_enum.pp_rr_typ typ
  | Exists_data (name, rd) ->
    Fmt.pf ppf "exists data? %a %a"
      Domain_name.pp name pp_rdata rd
  | Not_exists (name, typ) ->
    Fmt.pf ppf "doesn't exists? %a %a" Domain_name.pp name Udns_enum.pp_rr_typ typ
  | Name_inuse name -> Fmt.pf ppf "name inuse? %a" Domain_name.pp name
  | Not_name_inuse name -> Fmt.pf ppf "name not inuse? %a" Domain_name.pp name
(*BISECT-IGNORE-END*)

let decode_rr_prereq names buf off =
  decode_ntc names buf off >>= fun ((name, typ, cls), names, off) ->
  let off' = off + 6 in
  guard (Cstruct.len buf >= off') `Partial >>= fun () ->
  let ttl = Cstruct.BE.get_uint32 buf off in
  guard (ttl = 0l) (`NonZeroTTL ttl) >>= fun () ->
  let rlen = Cstruct.BE.get_uint16 buf (off + 4) in
  let r0 = guard (rlen = 0) (`NonZeroRdlen rlen) in
  let open Udns_enum in
  match int_to_clas cls, typ with
  | Some ANY_CLASS, ANY -> r0 >>= fun () -> Ok (Name_inuse name, names, off')
  | Some NONE, ANY -> r0 >>= fun () -> Ok (Not_name_inuse name, names, off')
  | Some ANY_CLASS, _ -> r0 >>= fun () -> Ok (Exists (name, typ), names, off')
  | Some NONE, _ -> r0 >>= fun () -> Ok (Not_exists (name, typ), names, off')
  | Some IN, _ ->
    safe_decode_rdata names buf off' rlen typ >>= fun (rdata, names, off'') ->
    Ok (Exists_data (name, rdata), names, off'')
  | _ -> Error (`BadClass cls)

let encode_rr_prereq offs buf off = function
  | Exists (name, typ) ->
    let offs, off =
      encode_ntc offs buf off (name, typ, Udns_enum.(clas_to_int ANY_CLASS))
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Exists_data (name, rdata) ->
    let typ = rdata_to_rr_typ rdata in
    let offs, off =
      encode_ntc offs buf off (name, typ, Udns_enum.(clas_to_int IN))
    in
    let rdata_off = off + 6 in
    let offs, rdata_end = encode_rdata offs buf rdata_off rdata in
    Cstruct.BE.set_uint16 buf (rdata_off - 2) (rdata_end - rdata_off) ;
    (offs, rdata_end)
  | Not_exists (name, typ) ->
    let offs, off =
      encode_ntc offs buf off (name, typ, Udns_enum.(clas_to_int NONE))
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Name_inuse name ->
    let offs, off =
      encode_ntc offs buf off Udns_enum.(name, ANY, clas_to_int ANY_CLASS)
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Not_name_inuse name ->
    let offs, off =
      encode_ntc offs buf off Udns_enum.(name, ANY, clas_to_int NONE)
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)

type rr_update =
  | Remove of Domain_name.t * Udns_enum.rr_typ
  | Remove_all of Domain_name.t
  | Remove_single of Domain_name.t * rdata
  | Add of rr

let rr_update_name = function
  | Remove (name, _) -> name
  | Remove_all name -> name
  | Remove_single (name, _) -> name
  | Add rr -> rr.name

(*BISECT-IGNORE-BEGIN*)
let pp_rr_update ppf = function
  | Remove (name, typ) ->
    Fmt.pf ppf "remove! %a %a" Domain_name.pp name Udns_enum.pp_rr_typ typ
  | Remove_all name -> Fmt.pf ppf "remove all! %a" Domain_name.pp name
  | Remove_single (name, rd) ->
    Fmt.pf ppf "remove single! %a %a" Domain_name.pp name pp_rdata rd
  | Add rr ->
    Fmt.pf ppf "add! %a" pp_rr rr
(*BISECT-IGNORE-END*)

let decode_rr_update names buf off =
  decode_ntc names buf off >>= fun ((name, typ, cls), names, off) ->
  let off' = off + 6 in
  guard (Cstruct.len buf >= off') `Partial >>= fun () ->
  let ttl = Cstruct.BE.get_uint32 buf off in
  let rlen = Cstruct.BE.get_uint16 buf (off + 4) in
  let r0 = guard (rlen = 0) (`NonZeroRdlen rlen) in
  let ttl0 = guard (ttl = 0l) (`NonZeroTTL ttl) in
  match Udns_enum.int_to_clas cls, typ with
  | Some Udns_enum.ANY_CLASS, Udns_enum.ANY ->
    ttl0 >>= fun () ->
    r0 >>= fun () ->
    Ok (Remove_all name, names, off')
  | Some Udns_enum.ANY_CLASS, _ ->
    ttl0 >>= fun () ->
    r0 >>= fun () ->
    Ok (Remove (name, typ), names, off')
  | Some Udns_enum.NONE, _ ->
    ttl0 >>= fun () ->
    safe_decode_rdata names buf off' rlen typ >>= fun (rdata, names, off) ->
    Ok (Remove_single (name, rdata), names, off)
  | Some Udns_enum.IN, _ ->
    guard (check_ttl ttl) (`BadTTL ttl) >>= fun () ->
    safe_decode_rdata names buf off' rlen typ >>= fun (rdata, names, off) ->
    let rr = { name ; ttl ; rdata } in
    Ok (Add rr, names, off)
  | _ -> Error (`BadClass cls)

let encode_rr_update offs buf off = function
  | Remove (name, typ) ->
    let offs, off =
      encode_ntc offs buf off (name, typ, Udns_enum.(clas_to_int ANY_CLASS))
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Remove_all name ->
    let offs, off =
      encode_ntc offs buf off Udns_enum.(name, ANY, clas_to_int ANY_CLASS)
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Remove_single (name, rdata) ->
    let offs, off =
      let typ = rdata_to_rr_typ rdata in
      encode_ntc offs buf off (name, typ, Udns_enum.(clas_to_int NONE))
    in
    let rdata_off = off + 6 in
    let offs, rdata_end = encode_rdata offs buf rdata_off rdata in
    Cstruct.BE.set_uint16 buf (rdata_off - 2) (rdata_end - rdata_off) ;
    (offs, rdata_end)
  | Add rr -> encode_rr offs buf off rr

type update = {
  zone : question ;
  prereq : rr_prereq list ;
  update : rr_update list ;
  addition : rr list ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_update ppf t =
  Fmt.pf ppf "%a@ %a@ %a@ %a"
    pp_question t.zone
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr_prereq) t.prereq
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr_update) t.update
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr) t.addition
(*BISECT-IGNORE-END*)
*)
let rec decode_n f names buf off acc = function
  | 0 -> Ok (names, off, List.rev acc)
  | n ->
    match f names buf off with
    | Ok (ele, names, off') ->
      decode_n f names buf off' (ele :: acc) (pred n)
    | Error e -> Error e

let rec decode_n_additional names buf off r (acc, opt, tsig) = function
  | 0 -> Ok (off, List.rev acc, opt, tsig, r)
  | n ->
    match decode_rr names buf off with
    | Ok (ele, names, off') ->
      rdata_edns_tsig_ok ele opt tsig >>= fun (opt', tsig') ->
      decode_n_additional names buf off' (Some off) (ele :: acc, opt', tsig') (pred n)
    | Error e -> Error e
(*
let decode_update buf =
  guard (Cstruct.len buf >= hdr_len) `Partial >>= fun () ->
  let zcount = Cstruct.BE.get_uint16 buf 4
  and prcount = Cstruct.BE.get_uint16 buf 6
  and upcount = Cstruct.BE.get_uint16 buf 8
  and adcount = Cstruct.BE.get_uint16 buf 10
  in
  guard (zcount = 1) (`InvalidZoneCount zcount) >>= fun () ->
  decode_question Udns_name.IntMap.empty buf hdr_len >>= fun (q, ns, off) ->
  guard (q.q_type = Udns_enum.SOA) (`InvalidZoneRR q.q_type) >>= fun () ->
  decode_n decode_rr_prereq ns buf off [] prcount >>= fun (ns, off, pre) ->
  decode_n decode_rr_update ns buf off [] upcount >>= fun (ns, off, up) ->
  decode_n_additional ns buf off None ([], None, None) adcount >>= fun (off, addition, opt, tsig, loff) ->
  guard (Cstruct.len buf = off) `LeftOver >>= fun () ->
  Ok (`Update { zone = q ; prereq = pre ; update = up ; addition }, opt, tsig, loff)

let encode_update buf data =
  Cstruct.BE.set_uint16 buf 4 1 ;
  Cstruct.BE.set_uint16 buf 6 (List.length data.prereq) ;
  Cstruct.BE.set_uint16 buf 8 (List.length data.update) ;
  let offs, off =
    encode_question Domain_name.Map.empty buf hdr_len data.zone
  in
  let offs, off =
    List.fold_left (fun (offs, off) rr -> encode_rr_prereq offs buf off rr)
      (offs, off) data.prereq
  in
  List.fold_left (fun (offs, off) rr -> encode_rr_update offs buf off rr)
    (offs, off) data.update
*)
type v = [ `Query of query | `Update of update | `Notify of query ]
type t = header * v * opt option * (Domain_name.t * tsig) option

(*BISECT-IGNORE-BEGIN*)
let pp_v ppf = function
  | `Query q -> pp_query ppf q
  | `Update u -> pp_update ppf u
  | `Notify n -> pp_query ppf n

let pp ppf (hdr, v, _, _) =
  pp_header ppf hdr ;
  Fmt.sp ppf () ;
  pp_v ppf v
(*BISECT-IGNORE-END*)

type tsig_verify = ?mac:Cstruct.t -> Ptime.t -> v -> header ->
  Domain_name.t -> key:dnskey option -> tsig -> Cstruct.t ->
  (tsig * Cstruct.t * dnskey, Cstruct.t option) result

type tsig_sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> tsig ->
  key:dnskey -> Cstruct.t -> (Cstruct.t * Cstruct.t) option

let encode_v buf v =
  match v with
  | `Query q | `Notify q -> encode_query buf q
  | `Update u -> encode_update buf u

let opt_rr opt = { name = Domain_name.root ; ttl = 0l ; rdata = OPTS opt }

let encode_opt opt =
  (* this is unwise! *)
  let rr = opt_rr opt in
  let buf = Cstruct.create 128 in
  let _, off = encode_rr Domain_name.Map.empty buf 0 rr in
  Cstruct.sub buf 0 off

let encode_ad hdr ?edns offs buf off ads =
  let ads, edns = match edns with
    | None -> ads, None
    | Some opt ->
      let ext_rcode = (Udns_enum.rcode_to_int hdr.rcode) lsr 4 in
      (* don't overwrite if rcode was already set -- really needed? *)
      if opt.extended_rcode = 0 && ext_rcode > 0 then
        let edns = opt_rr { opt with extended_rcode = ext_rcode } in
        [ edns ], Some edns
      else
        let edns = opt_rr opt in
        ads @ [ edns ], Some edns
  in
  try
    Cstruct.BE.set_uint16 buf 10 (List.length ads) ;
    snd (List.fold_left (fun (offs, off) rr -> encode_rr offs buf off rr)
           (offs, off) ads)
  with _ ->
  (* This is RFC 2181 Sec 9, not set truncated, just drop additional *)
  match edns with
  | None -> off
  | Some e ->
    try
      (* we attempt encoding edns only *)
      Cstruct.BE.set_uint16 buf 10 1 ;
      snd (encode_rr offs buf off e)
    with _ -> off

let encode ?max_size ?edns protocol hdr v =
  let max, edns = size_edns max_size edns protocol hdr.query in
  (* TODO: enforce invariants: additionals no TSIG and no EDNS! *)
  let try_encoding buf =
    let off, trunc =
      try
        encode_header buf hdr ;
        let offs, off = encode_v buf v in
        let ad = match v with
          | `Query q | `Notify q -> q.additional
          | `Update u -> u.addition
        in
        encode_ad hdr ?edns offs buf off ad, false
      with Invalid_argument _ -> (* set truncated *)
        (* if we failed to store data into buf, set truncation bit! *)
        Cstruct.set_uint8 buf 2 (0x02 lor (Cstruct.get_uint8 buf 2)) ;
        Cstruct.len buf, true
    in
    Cstruct.sub buf 0 off, trunc
  in
  let rec doit s =
    let cs = Cstruct.create s in
    match try_encoding cs with
    | (cs, false) -> (cs, max)
    | (cs, true) ->
      let next = min max (s * 2) in
      if next = s then
        (cs, max)
      else
        doit next
  in
  doit (min max 4000) (* (mainly for TCP) we use a page as initial allocation *)

let error header v rcode =
  if not header.query then
    let header = { header with rcode }
    and question = match v with
      | `Update u -> [ u.zone ]
      | `Query q | `Notify q -> q.question
    in
    let errbuf = Cstruct.create max_reply_udp in
    let query = { question ; answer = [] ; authority = [] ; additional = [] } in
    encode_header errbuf header ;
    let encode query =
      let _, off = encode_query errbuf query in
      let extended_rcode = (Udns_enum.rcode_to_int rcode) lsr 4 in
      if extended_rcode > 0 then
        encode_ad header ~edns:(opt ()) Domain_name.Map.empty errbuf off []
      else
        off
    in
    let off = try encode query with
      | Invalid_argument _ ->
        (* the question section could be larger than 450 byte, a single question
           can't (domain-name: 256 byte, type: 2 byte, class: 2 byte) *)
        let question = match question with [] -> [] | q::_ -> [ q ] in
        let query = { question ; answer = [] ; authority = [] ; additional = [] } in
        encode query
    in
    Some (Cstruct.sub errbuf 0 off, max_reply_udp)
  else
    None
*)
