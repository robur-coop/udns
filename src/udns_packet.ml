(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
(*
(*BISECT-IGNORE-BEGIN*)
let pp_err ppf = function
  | #Udns_name.err as e -> Udns_name.pp_err ppf e
  | `BadTTL x -> Fmt.pf ppf "bad ttl %lu" x
  | `BadRRTyp x -> Fmt.pf ppf "bad rr typ %u" x
  | `DisallowedRRTyp x -> Fmt.pf ppf "disallowed rr typ %a" Udns_enum.pp_rr_typ x
  | `BadClass x -> Fmt.pf ppf "bad rr class %u" x
  | `DisallowedClass x -> Fmt.pf ppf "disallowed rr class %a" Udns_enum.pp_clas x
  | `UnsupportedClass x -> Fmt.pf ppf "unsupported rr class %a" Udns_enum.pp_clas x
  | `BadOpcode x -> Fmt.pf ppf "bad opcode %u" x
  | `UnsupportedOpcode x -> Fmt.pf ppf "unsupported opcode %a" Udns_enum.pp_opcode x
  | `BadRcode x -> Fmt.pf ppf "bad rcode %u" x
  | `BadCaaTag -> Fmt.string ppf "bad CAA tag"
  | `LeftOver -> Fmt.string ppf "leftover"
  | `NonZeroTTL ttl -> Fmt.pf ppf "TTL is %lu, must be 0" ttl
  | `NonZeroRdlen rdl -> Fmt.pf ppf "rdlen is %u, must be 0" rdl
  | `InvalidZoneCount x -> Fmt.pf ppf "invalid zone count %u, must be 0" x
  | `InvalidZoneRR typ -> Fmt.pf ppf "invalid zone typ %a, must be SOA" Udns_enum.pp_rr_typ typ
  | `InvalidTimestamp ts -> Fmt.pf ppf "invalid timestamp %Lu in TSIG" ts
  | `InvalidAlgorithm n -> Fmt.pf ppf "invalid algorithm %a" Domain_name.pp n
  | `BadProto num -> Fmt.pf ppf "bad protocol %u" num
  | `BadAlgorithm num -> Fmt.pf ppf "bad algorithm %u" num
  | `BadOpt -> Fmt.pf ppf "bad option"
  | `BadKeepalive -> Fmt.pf ppf "bad keepalive"
  | `BadTlsaCertUsage usage -> Fmt.pf ppf "bad TLSA cert usage %u" usage
  | `BadTlsaSelector selector -> Fmt.pf ppf "bad TLSA selector %u" selector
  | `BadTlsaMatchingType matching_type -> Fmt.pf ppf "bad TLSA matching type %u" matching_type
  | `BadSshfpAlgorithm i -> Fmt.pf ppf "bad SSHFP algorithm %u" i
  | `BadSshfpType i -> Fmt.pf ppf "bad SSHFP type %u" i
  | `Bad_edns_version i -> Fmt.pf ppf "bad edns version %u" i
  | `Multiple_tsig -> Fmt.string ppf "multiple TSIG"
  | `Multiple_edns -> Fmt.string ppf "multiple EDNS"
  | `Tsig_not_last -> Fmt.string ppf "TSIG not last"
(*BISECT-IGNORE-END*)

(* HEADER *)
let hdr_len = 12

type header = {
  id : int ;
  query : bool ;
  operation : Udns_enum.opcode ;
  authoritative : bool ;
  truncation : bool ;
  recursion_desired : bool ;
  recursion_available : bool ;
  authentic_data : bool ;
  checking_disabled : bool ;
  rcode : Udns_enum.rcode ;
}

let decode_flags hdr high low =
  let authoritative = if high land 0x04 > 0 then true else false
  and truncation = if high land 0x02 > 0 then true else false
  and recursion_desired = if high land 0x01 > 0 then true else false
  and recursion_available = if low land 0x80 > 0 then true else false
  and authentic_data = if low land 0x20 > 0 then true else false
  and checking_disabled = if low land 0x10 > 0 then true else false
  in
  { hdr with authoritative ; truncation ; recursion_desired ;
             recursion_available ; authentic_data ; checking_disabled }

let encode_flags hdr h l =
  let h =
    let h = if hdr.authoritative then h lor 0x04 else h in
    let h = if hdr.truncation then h lor 0x02 else h in
    if hdr.recursion_desired then h lor 0x01 else h
  and l =
    let l = if hdr.recursion_available then l lor 0x80 else l in
    let l = if hdr.authentic_data then l lor 0x20 else l in
    if hdr.checking_disabled then l lor 0x10 else l
  in
  (h, l)

(* header is:
bit 0  QR - 0 for query, 1 for response
bit 1 - 4 operation
bit 5  AA Authoritative Answer [RFC1035]                             \
bit 6  TC Truncated Response   [RFC1035]                             |
bit 7  RD Recursion Desired    [RFC1035]                             |
bit 8  RA Recursion Available  [RFC1035]                             |-> flags
bit 9     Reserved                                                   |
bit 10 AD Authentic Data       [RFC4035][RFC6840][RFC Errata 4924]   |
bit 11 CD Checking Disabled    [RFC4035][RFC6840][RFC Errata 4927]   /
bit 12-15 rcode *)

let decode_header buf =
  (* we only access the first 4 bytes, but anything <12 is a bad DNS frame *)
  guard (Cstruct.len buf >= hdr_len) `Partial >>= fun () ->
  let high = Cstruct.get_uint8 buf 2
  and low = Cstruct.get_uint8 buf 3
  in
  let op = (high land 0x78) lsr 3
  and rc = low land 0x0F
  in
  match Udns_enum.int_to_opcode op, Udns_enum.int_to_rcode rc with
  | None, _ -> Error (`BadOpcode op)
  | _, None -> Error (`BadRcode rc)
  | Some operation, Some rcode ->
    let id = Cstruct.BE.get_uint16 buf 0
    and query = high lsr 7 = 0
    in
    let hdr = { id ; query ; operation ; rcode ; authoritative = false ;
                truncation = false ; recursion_desired = false ;
                recursion_available = false ; authentic_data = false ;
                checking_disabled = false }
    in
    let hdr = decode_flags hdr high low in
    Ok hdr

let encode_header buf hdr =
  let h = if hdr.query then 0 else 0x80
  and l = 0
  in
  let h, l = encode_flags hdr h l in
  let h = ((Udns_enum.opcode_to_int hdr.operation) lsl 3) lor h
  and l = ((Udns_enum.rcode_to_int hdr.rcode) land 0xF) lor l
  in
  Cstruct.BE.set_uint16 buf 0 hdr.id ;
  Cstruct.set_uint8 buf 2 h ;
  Cstruct.set_uint8 buf 3 l

(*BISECT-IGNORE-BEGIN*)
let pp_header ppf hdr =
  let flags =
    (if hdr.authoritative then ["authoritative"] else []) @
    (if hdr.truncation then ["truncated"] else []) @
    (if hdr.recursion_desired then ["recursion desired"] else []) @
    (if hdr.recursion_available then ["recursion available"] else []) @
    (if hdr.authentic_data then ["authentic data"] else []) @
    (if hdr.checking_disabled then ["checking disabled"] else [])
  in
  Fmt.pf ppf "%04X (%s) operation '%a' rcode '@[%a@]' flags: '@[%a@]'"
    hdr.id (if hdr.query then "query" else "response")
    Udns_enum.pp_opcode hdr.operation
    Udns_enum.pp_rcode hdr.rcode
    (Fmt.list ~sep:(Fmt.unit ", ") Fmt.string) flags
(*BISECT-IGNORE-END*)


(* RESOURCE RECORD *)
let decode_ntc names buf off =
  Udns_name.decode ~hostname:false names buf off >>= fun (name, names, off) ->
  guard (Cstruct.len buf >= 4 + off) `Partial >>= fun () ->
  let typ = Cstruct.BE.get_uint16 buf off
  and cls = Cstruct.BE.get_uint16 buf (off + 2)
  (* CLS is interpreted differently by OPT, thus no int_to_clas called here *)
  in
  match Udns_enum.int_to_rr_typ typ with
  | None -> Error (`BadRRTyp typ)
  | Some Udns_enum.(DNSKEY | TSIG | TXT | CNAME as t) ->
    Ok ((name, t, cls), names, off + 4)
  | Some Udns_enum.(TLSA | SRV as t) when Domain_name.is_service name ->
    Ok ((name, t, cls), names, off + 4)
  | Some Udns_enum.SRV -> (* MUST be service name *)
    Error (`BadContent (Domain_name.to_string name))
  | Some t when Domain_name.is_hostname name ->
    Ok ((name, t, cls), names, off + 4)
  | Some _ ->
    Error (`BadContent (Domain_name.to_string name))

let encode_ntc offs buf off (n, t, c) =
  let offs, off = Udns_name.encode offs buf off n in
  Cstruct.BE.set_uint16 buf off (Udns_enum.rr_typ_to_int t) ;
  Cstruct.BE.set_uint16 buf (off + 2) c ;
  (offs, off + 4)

let decode_question names buf off =
  decode_ntc names buf off >>= fun ((q_name, q_type, c), names, off) ->
  match Udns_enum.int_to_clas c with
  | None -> Error (`BadClass c)
  | Some Udns_enum.IN -> Ok ({ q_name ; q_type }, names, off)
  | Some x -> Error (`UnsupportedClass x)

let encode_question offs buf off q =
  encode_ntc offs buf off (q.q_name, q.q_type, Udns_enum.clas_to_int Udns_enum.IN)

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

let safe_decode_rdata names buf off len typ =
  (* decode_rdata is mostly safe, apart from some Cstruct._.get_ *)
  (try decode_rdata names buf off len typ with _ -> Error `Partial)
  >>= fun (rdata, names, off') ->
  guard (off' = off + len) `LeftOver >>= fun () ->
  Ok (rdata, names, off')

(* TTL in range 0 .. 2 ^ 31 - 1 -- otherwise invalid (see RFC2181 sec 8) *)
let check_ttl ttl = Int32.logand ttl 0x80000000l = 0l

let decode_rr names buf off =
  decode_ntc names buf off >>= fun ((name, typ, c), names, off) ->
  guard (Cstruct.len buf >= 6 + off) `Partial >>= fun () ->
  (* since QTYPE (and QCLASS) are supersets of RR_TYPE and RR_CLASS, we
     complaing about these not belonging to RR_TYPE/RR_CLASS here *)
  (* we are only concerned about class = IN, according to RFC6895 Sec 3.3.2:
     The IN, or Internet, CLASS is thus the only DNS CLASS in global use on
     the Internet at this time! *)
  let ttl = Cstruct.BE.get_uint32 buf off in
  (match typ with
   | Udns_enum.AXFR | Udns_enum.MAILB | Udns_enum.MAILA | Udns_enum.ANY ->
     Error (`DisallowedRRTyp typ)
   | Udns_enum.OPT -> Ok ()
   | Udns_enum.TSIG -> (* TTL = 0! and class = ANY *)
     begin match Udns_enum.int_to_clas c with
       | Some Udns_enum.ANY_CLASS when ttl = 0l -> Ok ()
       | _ -> Error (`BadClass c)
     end
   | _ -> match Udns_enum.int_to_clas c with
     | Some Udns_enum.IN -> Ok ()
     | None -> Error (`BadClass c)
     | Some Udns_enum.ANY_CLASS -> Error (`DisallowedClass Udns_enum.ANY_CLASS)
     | Some x -> Error (`UnsupportedClass x)) >>= fun () ->
  let len = Cstruct.BE.get_uint16 buf (off + 4) in
  guard (Cstruct.len buf >= len + 6) `Partial >>= fun () ->
  match typ with
  | Udns_enum.OPT ->
    (* crazyness: payload_size is encoded in class *)
    let payload_size = c
    (* it continues: the ttl is split into: 4bit extended rcode, 4bit version, 1bit dnssec_ok, 7bit 0 *)
    and extended_rcode = Cstruct.get_uint8 buf off
    and version = Cstruct.get_uint8 buf (off + 1)
    and flags = Cstruct.BE.get_uint16 buf (off + 2)
    in
    let off = off + 6 in
    let dnssec_ok = flags land 0x8000 = 0x8000 in
    guard (version = 0) (`Bad_edns_version version) >>= fun () ->
    (try decode_extensions buf off len with _ -> Error `Partial) >>= fun extensions ->
    let opt = { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions } in
    Ok ({ name ; ttl ; rdata = OPTS opt }, names, (off + len))
  | _ ->
    let off = off + 6 in
    guard (check_ttl ttl) (`BadTTL ttl) >>= fun () ->
    safe_decode_rdata names buf off len typ >>= fun (rdata, names, off') ->
    Ok ({ name ; ttl ; rdata }, names, off')

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

(* QUERY *)
let rec decode_n_partial f names buf off acc = function
  | 0 -> Ok (`Full (names, off, List.rev acc))
  | n ->
    match f names buf off with
    | Ok (ele, names, off') ->
      decode_n_partial f names buf off' (ele :: acc) (pred n)
    | Error `Partial -> Ok (`Partial (List.rev acc))
    | Error e -> Error e

let rdata_edns_tsig_ok rr edns tsig =
  match rr.rdata, edns, tsig with
  | TSIG ts, opt, None -> Ok (opt, Some (rr.name, ts))
  | TSIG _, _, Some _ -> Error `Multiple_tsig
  | OPTS opt, None, None -> Ok (Some opt, None)
  | OPTS _, Some _, _ -> Error `Multiple_edns
  | _, _, Some _ -> Error `Tsig_not_last
  | _, opt, ts -> Ok (opt, ts)

let rec decode_n_additional_partial names buf off r (acc, opt, tsig) = function
  | 0 -> Ok (`Full (off, List.rev acc, opt, tsig, r))
  | n ->
    match decode_rr names buf off with
    | Ok (ele, names, off') ->
      rdata_edns_tsig_ok ele opt tsig >>= fun (opt', tsig') ->
      decode_n_additional_partial names buf off' (Some off) (ele :: acc, opt', tsig') (pred n)
    | Error `Partial -> Ok (`Partial (List.rev acc, opt, tsig))
    | Error e -> Error e

type query = {
  question : question list ;
  answer : rr list ;
  authority : rr list ;
  additional : rr list
}

let decode_query buf t =
  guard (Cstruct.len buf >= 12) `Partial >>= fun () ->
  let qcount = Cstruct.BE.get_uint16 buf 4
  and ancount = Cstruct.BE.get_uint16 buf 6
  and aucount = Cstruct.BE.get_uint16 buf 8
  and adcount = Cstruct.BE.get_uint16 buf 10
  in
  let query question answer authority additional =
    `Query { question ; answer ; authority ; additional }
  in
  let empty = Udns_name.IntMap.empty in
  decode_n_partial decode_question empty buf hdr_len [] qcount >>= function
  | `Partial qs -> guard t `Partial >>= fun () -> Ok (query qs [] [] [], None, None, None)
  | `Full (names, off, qs) ->
    decode_n_partial decode_rr names buf off [] ancount >>= function
    | `Partial an -> guard t `Partial >>= fun () -> Ok (query qs an [] [], None, None, None)
    | `Full (names, off, an) ->
      decode_n_partial decode_rr names buf off [] aucount >>= function
      | `Partial au -> guard t `Partial >>= fun () -> Ok (query qs an au [], None, None, None)
      | `Full (names, off, au) ->
        decode_n_additional_partial names buf off None ([], None, None) adcount >>= function
        | `Partial (ad, opt, tsig) ->
          guard t `Partial >>= fun () ->
          Ok (query qs an au ad, opt, tsig, None)
        | `Full (off, ad, opt, tsig, lastoff) ->
          (if Cstruct.len buf > off then
             let n = Cstruct.len buf - off in
             Logs.warn (fun m -> m "received %d extra bytes %a"
                           n Cstruct.hexdump_pp (Cstruct.sub buf off n))) ;
          Ok (query qs an au ad, opt, tsig, lastoff)

let encode_query buf data =
  Cstruct.BE.set_uint16 buf 4 (List.length data.question) ;
  Cstruct.BE.set_uint16 buf 6 (List.length data.answer) ;
  Cstruct.BE.set_uint16 buf 8 (List.length data.authority) ;
  let offs, off =
    List.fold_left (fun (offs, off) q -> encode_question offs buf off q)
      (Domain_name.Map.empty, hdr_len) data.question
  in
  List.fold_left (fun (offs, off) rr -> encode_rr offs buf off rr)
    (offs, off) (data.answer @ data.authority)

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

let decode_notify buf t =
  decode_query buf t >>| fun (`Query q, opt, tsig, off) ->
  (`Notify q, opt, tsig, off)

(* TODO: verify the following invariants:
   - notify allows only a single SOA in answer, rest better be empty
   - TSIG and EDNS are only allowed in additional section!
 *)
let decode buf =
  decode_header buf >>= fun hdr ->
  let t = hdr.truncation in
  let header = function
    | Some e when e.extended_rcode > 0 ->
      begin
        let rcode =
          Udns_enum.rcode_to_int hdr.rcode + e.extended_rcode lsl 4
        in
        match Udns_enum.int_to_rcode rcode with
        | None -> Error (`BadRcode rcode)
        | Some rcode -> Ok ({ hdr with rcode })
      end
    | _ -> Ok hdr
  in
  begin match hdr.operation with
  | Udns_enum.Query -> decode_query buf t
  | Udns_enum.Update -> decode_update buf
  | Udns_enum.Notify -> decode_notify buf t
  | x -> Error (`UnsupportedOpcode x)
  end >>= fun (data, opt, tsig, off) ->
  header opt >>| fun hdr ->
  ((hdr, data, opt, tsig), off)

let max_udp = 1484 (* in MirageOS. using IPv4 this is max UDP payload via ethernet *)
let max_reply_udp = 450 (* we don't want anyone to amplify! *)
let max_tcp = 1 lsl 16 - 1 (* DNS-over-TCP is 2 bytes len ++ payload *)

let size_edns max_size edns protocol query =
  let max = match max_size, query with
    | Some x, true -> x
    | Some x, false -> min x max_reply_udp
    | None, true -> max_udp
    | None, false -> max_reply_udp
  in
  (* it's udp payload size only, ignore any value for tcp *)
  let maximum = match protocol with
    | `Udp -> max
    | `Tcp -> max_tcp
  in
  let edns = match edns with
    | None -> None
    | Some opts -> Some ({ opts with payload_size = max })
  in
  maximum, edns

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
