(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
(*
  | x -> Ok (Raw (x, Cstruct.sub buf off len), names, off + len)

let encode_rdata offs buf off = function
  | TSIG t -> encode_tsig t offs buf off
  | Raw (_, rr) ->
    let len = Cstruct.len rr in
    Cstruct.blit rr 0 buf off len ;
    offs, off + len

(*
(* UPDATE *)
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
*)
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
*)
