(* (c) 2017-2019 Hannes Mehnert, all rights reserved *)

type proto = [ `Tcp | `Udp ]

let andThen v f = match v with 0 -> f | x -> x

let int_compare (a : int) (b : int) = compare a b
let int32_compare (a : int32) (b : int32) = Int32.compare a b

let guard p err = if p then Ok () else Error err

type question = {
  q_name : Domain_name.t ;
  q_type : Udns_enum.rr_typ ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_question ppf q =
  Fmt.pf ppf "%a %a?" Domain_name.pp q.q_name Udns_enum.pp_rr_typ q.q_type
(*BISECT-IGNORE-END*)

let compare_question q q' =
  andThen (Domain_name.compare q.q_name q'.q_name)
    (int_compare (Udns_enum.rr_typ_to_int q.q_type)
       (Udns_enum.rr_typ_to_int q'.q_type))

(* resource records *)

(* start of authority *)
type soa = {
  nameserver : Domain_name.t ;
  hostmaster : Domain_name.t ;
  serial : int32 ;
  refresh : int32 ;
  retry : int32 ;
  expiry : int32 ;
  minimum : int32 ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_soa ppf soa =
  Fmt.pf ppf "SOA %a %a %lu %lu %lu %lu %lu"
    Domain_name.pp soa.nameserver Domain_name.pp soa.hostmaster
    soa.serial soa.refresh soa.retry soa.expiry soa.minimum
(*BISECT-IGNORE-END*)

let compare_soa soa soa' =
  andThen (int32_compare soa.serial soa.serial)
    (andThen (Domain_name.compare soa.nameserver soa'.nameserver)
       (andThen (Domain_name.compare soa.hostmaster soa'.hostmaster)
          (andThen (int32_compare soa.refresh soa'.refresh)
             (andThen (int32_compare soa.retry soa'.retry)
                (andThen (int32_compare soa.expiry soa'.expiry)
                   (int32_compare soa.minimum soa'.minimum))))))

let decode_soa names buf off =
  let open Rresult.R.Infix in
  let hostname = false in
  Udns_name.decode ~hostname names buf off >>= fun (nameserver, names, off) ->
  Udns_name.decode ~hostname names buf off >>| fun (hostmaster, names, off) ->
  let serial = Cstruct.BE.get_uint32 buf off in
  let refresh = Cstruct.BE.get_uint32 buf (off + 4) in
  let retry = Cstruct.BE.get_uint32 buf (off + 8) in
  let expiry = Cstruct.BE.get_uint32 buf (off + 12) in
  let minimum = Cstruct.BE.get_uint32 buf (off + 16) in
  let soa =
    { nameserver ; hostmaster ; serial ; refresh ; retry ; expiry ; minimum }
  in
  (soa, names, off + 20)

let encode_soa soa offs buf off =
  let offs, off = Udns_name.encode offs buf off soa.nameserver in
  let offs, off = Udns_name.encode offs buf off soa.hostmaster in
  Cstruct.BE.set_uint32 buf off soa.serial ;
  Cstruct.BE.set_uint32 buf (off + 4) soa.refresh ;
  Cstruct.BE.set_uint32 buf (off + 8) soa.retry ;
  Cstruct.BE.set_uint32 buf (off + 12) soa.expiry ;
  Cstruct.BE.set_uint32 buf (off + 16) soa.minimum ;
  offs, off + 20

(* name server *)
type ns = Domain_name.t

(*BISECT-IGNORE-BEGIN*)
let pp_ns ppf ns =
  Fmt.pf ppf "NS %a" Domain_name.pp ns
(*BISECT-IGNORE-END*)

let compare_ns = Domain_name.compare



(* mail exchange *)
type mx = {
  preference : int ;
  mail_exchange : Domain_name.t ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_mx ppf { preference ; mail_exchange } =
  Fmt.pf ppf "MX %u %a" preference Domain_name.pp mail_exchange
(*BISECT-IGNORE-END*)

let compare_mx mx mx' =
  andThen (int_compare mx.preference mx'.preference)
    (Domain_name.compare mx.mail_exchange mx'.mail_exchange)

let decode_mx names buf off =
  let open Rresult.R.Infix in
  let preference = Cstruct.BE.get_uint16 buf off in
  Udns_name.decode ~hostname:false names buf (off + 2) >>| fun (mail_exchange, names, off) ->
  { preference ; mail_exchange }, names, off

let encode_mx { Udns_types.preference ; mail_exchange } offs buf off =
  Cstruct.BE.set_uint16 buf off preference ;
  Udns_name.encode offs buf (off + 2) mail_exchange

(* canonical name *)
type cname = Domain_name.t

(*BISECT-IGNORE-BEGIN*)
let pp_cname ppf alias =
  Fmt.pf ppf "CNAME %a" Domain_name.pp alias
(*BISECT-IGNORE-END*)

let compare_cname = Domain_name.compare

(* address record *)
type a = Ipaddr.V4.t

(*BISECT-IGNORE-BEGIN*)
let pp_a ppf address =
  Fmt.pf ppf "A %a" Ipaddr.V4.pp address
(*BISECT-IGNORE-END*)

let compare_a = Ipaddr.V4.compare

let encode_a ip offs buf off =
  let ip = Ipaddr.V4.to_int32 ip in
  Cstruct.BE.set_uint32 buf off ip ;
  (offs, off + 4)


(* quad-a record *)
type aaaa = Ipaddr.V6.t

(*BISECT-IGNORE-BEGIN*)
let pp_aaaa ppf address =
  Fmt.pf ppf "AAAA %a" Ipaddr.V6.pp address
(*BISECT-IGNORE-END*)

let compare_aaaa = Ipaddr.V6.compare

let encode_aaaa ip offs buf off =
  let iph, ipl = Ipaddr.V6.to_int64 ip in
  Cstruct.BE.set_uint64 buf off iph ;
  Cstruct.BE.set_uint64 buf (off + 8) ipl ;
  (offs, off + 16)

(* domain name pointer - reverse entries *)
type ptr = Domain_name.t

(*BISECT-IGNORE-BEGIN*)
let pp_ptr ppf rev =
  Fmt.pf ppf "PTR %a" Domain_name.pp rev
(*BISECT-IGNORE-END*)

let compare_ptr = Domain_name.compare

(* service record *)
type srv = {
  priority : int ;
  weight : int ;
  port : int ;
  target : Domain_name.t
}

(*BISECT-IGNORE-BEGIN*)
let pp_srv ppf t =
  Fmt.pf ppf
    "SRV priority %d weight %d port %d target %a"
    t.priority t.weight t.port Domain_name.pp t.target
(*BISECT-IGNORE-END*)

let compare_srv a b =
  andThen (compare a.priority b.priority)
    (andThen (compare a.weight b.weight)
       (andThen (compare a.port b.port)
          (Domain_name.compare a.target b.target)))

let decode_srv names buf off =
  let open Rresult.R.Infix in
  let priority = Cstruct.BE.get_uint16 buf off
  and weight = Cstruct.BE.get_uint16 buf (off + 2)
  and port = Cstruct.BE.get_uint16 buf (off + 4)
  in
  Udns_name.decode names buf (off + 6) >>= fun (target, names, off) ->
  Ok ({ priority ; weight ; port ; target }, names, off)

let encode_srv t offs buf off =
  Cstruct.BE.set_uint16 buf off t.priority ;
  Cstruct.BE.set_uint16 buf (off + 2) t.weight ;
  Cstruct.BE.set_uint16 buf (off + 4) t.port ;
  Udns_name.encode offs buf (off + 6) t.target

(* DNS key *)
type dnskey = {
  flags : int ; (* uint16 *)
  key_algorithm :  Udns_enum.dnskey ; (* u_int8_t *)
  key : Cstruct.t ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_dnskey ppf t =
  Fmt.pf ppf
    "DNSKEY flags %u algo %a key %a"
    t.flags Udns_enum.pp_dnskey t.key_algorithm
    Cstruct.hexdump_pp t.key
(*BISECT-IGNORE-END*)

let compare_dnskey a b =
  andThen (compare a.key_algorithm b.key_algorithm)
    (Cstruct.compare a.key b.key)

let decode_dnskey names buf off =
  let open Rresult.R.Infix in
  let flags = Cstruct.BE.get_uint16 buf off
  and proto = Cstruct.get_uint8 buf (off + 2)
  and algo = Cstruct.get_uint8 buf (off + 3)
  in
  guard (proto = 3) (`BadProto proto) >>= fun () ->
  match Udns_enum.int_to_dnskey algo with
  | None -> Error (`BadAlgorithm algo)
  | Some key_algorithm ->
    let len = Udns_enum.dnskey_len key_algorithm in
    let key = Cstruct.sub buf (off + 4) len in
    Ok ({ flags ; key_algorithm ; key }, names, off + len + 4)

let encode_dnskey t offs buf off =
  Cstruct.BE.set_uint16 buf off t.flags ;
  Cstruct.set_uint8 buf (off + 2) 3 ;
  Cstruct.set_uint8 buf (off + 3) (Udns_enum.dnskey_to_int t.key_algorithm) ;
  let kl = Cstruct.len t.key in
  Cstruct.blit t.key 0 buf (off + 4) kl ;
  offs, off + 4 + kl

let dnskey_of_string key =
  let parse flags algo key =
    let key = Cstruct.of_string key in
    match Udns_enum.string_to_dnskey algo with
    | None -> None
    | Some key_algorithm -> Some { flags ; key_algorithm ; key }
  in
  match Astring.String.cuts ~sep:":" key with
  | [ flags ; algo ; key ] ->
    begin match try Some (int_of_string flags) with Failure _ -> None with
      | Some flags -> parse flags algo key
      | None -> None
    end
  | [ algo ; key ] -> parse 0 algo key
  | _ -> None

let name_dnskey_of_string str =
  match Astring.String.cut ~sep:":" str with
  | None -> Error (`Msg ("couldn't parse " ^ str))
  | Some (name, key) -> match Domain_name.of_string ~hostname:false name, dnskey_of_string key with
    | Error _, _ | _, None -> Error (`Msg ("failed to parse key " ^ key))
    | Ok name, Some dnskey -> Ok (name, dnskey)

(* certificate authority authorization *)
type caa = {
  critical : bool ;
  tag : string ;
  value : string list ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_caa ppf t =
  Fmt.pf ppf
    "CAA critical %b tag %s value %a"
    t.critical t.tag Fmt.(list ~sep:(unit "; ") string) t.value
(*BISECT-IGNORE-END*)

let compare_caa a b =
  andThen (compare a.critical b.critical)
    (andThen (String.compare a.tag b.tag)
       (List.fold_left2 (fun r a b -> match r with
            | 0 -> String.compare a b
            | x -> x)
           0 a.value b.value))

let decode_caa buf off len =
  let open Rresult.R.Infix in
  let critical = Cstruct.get_uint8 buf off = 0x80
  and tl = Cstruct.get_uint8 buf (succ off)
  in
  guard (tl > 0 && tl < 16) `BadCaaTag >>= fun () ->
  let tag = Cstruct.sub buf (off + 2) tl in
  let tag = Cstruct.to_string tag in
  let vs = 2 + tl in
  let value = Cstruct.sub buf (off + vs) (len - vs) in
  let value = Astring.String.cuts ~sep:";" (Cstruct.to_string value) in
  Ok { critical ; tag ; value }

let encode_caa t offs buf off =
  Cstruct.set_uint8 buf off (if t.critical then 0x80 else 0x0) ;
  let tl = String.length t.tag in
  Cstruct.set_uint8 buf (succ off) tl ;
  Cstruct.blit_from_string t.tag 0 buf (off + 2) tl ;
  let value = Astring.String.concat ~sep:";" t.value in
  let vl = String.length value in
  Cstruct.blit_from_string value 0 buf (off + 2 + tl) vl ;
  offs, off + tl + 2 + vl

(* transport layer security A *)
type tlsa = {
  tlsa_cert_usage : Udns_enum.tlsa_cert_usage ;
  tlsa_selector : Udns_enum.tlsa_selector ;
  tlsa_matching_type : Udns_enum.tlsa_matching_type ;
  tlsa_data : Cstruct.t ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_tlsa ppf tlsa =
  Fmt.pf ppf "TLSA @[<v>%a %a %a@ %a@]"
    Udns_enum.pp_tlsa_cert_usage tlsa.tlsa_cert_usage
    Udns_enum.pp_tlsa_selector tlsa.tlsa_selector
    Udns_enum.pp_tlsa_matching_type tlsa.tlsa_matching_type
    Cstruct.hexdump_pp tlsa.tlsa_data
(*BISECT-IGNORE-END*)

let compare_tlsa t1 t2 =
  andThen (compare t1.tlsa_cert_usage t2.tlsa_cert_usage)
    (andThen (compare t1.tlsa_selector t2.tlsa_selector)
       (andThen (compare t1.tlsa_matching_type t2.tlsa_matching_type)
          (Cstruct.compare t1.tlsa_data t2.tlsa_data)))

let decode_tlsa buf off len =
  let usage, selector, matching_type =
    Cstruct.get_uint8 buf off,
    Cstruct.get_uint8 buf (off + 1),
    Cstruct.get_uint8 buf (off + 2)
  in
  let tlsa_data = Cstruct.sub buf (off + 3) (len - 3) in
  match
    Udns_enum.int_to_tlsa_cert_usage usage,
    Udns_enum.int_to_tlsa_selector selector,
    Udns_enum.int_to_tlsa_matching_type matching_type
  with
  | Some tlsa_cert_usage, Some tlsa_selector, Some tlsa_matching_type ->
    Ok { tlsa_cert_usage ; tlsa_selector ; tlsa_matching_type ; tlsa_data }
  | None, _, _ -> Error (`BadTlsaCertUsage usage)
  | _, None, _ -> Error (`BadTlsaSelector selector)
  | _, _, None -> Error (`BadTlsaMatchingType matching_type)

let encode_tlsa tlsa offs buf off =
  Cstruct.set_uint8 buf off (Udns_enum.tlsa_cert_usage_to_int tlsa.tlsa_cert_usage) ;
  Cstruct.set_uint8 buf (off + 1) (Udns_enum.tlsa_selector_to_int tlsa.tlsa_selector) ;
  Cstruct.set_uint8 buf (off + 2) (Udns_enum.tlsa_matching_type_to_int tlsa.tlsa_matching_type) ;
  let l = Cstruct.len tlsa.tlsa_data in
  Cstruct.blit tlsa.tlsa_data 0 buf (off + 3) l ;
  offs, off + 3 + l

(* secure shell fingerprint *)
type sshfp = {
  sshfp_algorithm : Udns_enum.sshfp_algorithm ;
  sshfp_type : Udns_enum.sshfp_type ;
  sshfp_fingerprint : Cstruct.t ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_sshfp ppf sshfp =
  Fmt.pf ppf "SSHFP %a %a %a"
    Udns_enum.pp_sshfp_algorithm sshfp.sshfp_algorithm
    Udns_enum.pp_sshfp_type sshfp.sshfp_type
    Cstruct.hexdump_pp sshfp.sshfp_fingerprint
(*BISECT-IGNORE-END*)

let compare_sshfp s1 s2 =
  andThen (compare s1.sshfp_algorithm s2.sshfp_algorithm)
    (andThen (compare s1.sshfp_type s2.sshfp_type)
       (Cstruct.compare s1.sshfp_fingerprint s2.sshfp_fingerprint))

let decode_sshfp buf off len =
  let algo, typ = Cstruct.get_uint8 buf off, Cstruct.get_uint8 buf (succ off) in
  let sshfp_fingerprint = Cstruct.sub buf (off + 2) (len - 2) in
  match Udns_enum.int_to_sshfp_algorithm algo, Udns_enum.int_to_sshfp_type typ with
  | Some sshfp_algorithm, Some sshfp_type ->
    Ok { sshfp_algorithm ; sshfp_type ; sshfp_fingerprint }
  | None, _ -> Error (`BadSshfpAlgorithm algo)
  | _, None -> Error (`BadSshfpType typ)

let encode_sshfp sshfp offs buf off =
  Cstruct.set_uint8 buf off (Udns_enum.sshfp_algorithm_to_int sshfp.sshfp_algorithm) ;
  Cstruct.set_uint8 buf (succ off) (Udns_enum.sshfp_type_to_int sshfp.sshfp_type) ;
  let l = Cstruct.len sshfp.sshfp_fingerprint in
  Cstruct.blit sshfp.sshfp_fingerprint 0 buf (off + 2) l ;
  offs, off + l + 2

(* Text record *)
type txt = string list

(*BISECT-IGNORE-BEGIN*)
let pp_txt ppf txt =
  Fmt.pf ppf "TXT %a" Fmt.(list ~sep:(unit ";@ ") string) txt
(*BISECT-IGNORE-END*)

let compare_txt a a' =
  andThen (compare (List.length a) (List.length a'))
    (List.fold_left2 (fun r a b -> match r with
         | 0 -> String.compare a b
         | x -> x)
        0 a a')

let encode_character_str buf off s =
  let l = String.length s in
  Cstruct.set_uint8 buf off l ;
  Cstruct.blit_from_string s 0 buf (succ off) l ;
  off + l + 1

let encode_txt txts offs buf off =
  let off = List.fold_left (encode_character_str buf) off txts in
  offs, off

let decode_character_str buf off =
  let l = Cstruct.get_uint8 buf off in
  let data = Cstruct.to_string (Cstruct.sub buf (succ off) l) in
  (data, off + l + 1)

let decode_txt buf ~off ~len =
  let sub = Cstruct.sub buf off len in
  let rec more acc off =
    if len = off then List.rev acc
    else
      let d, off = decode_character_str sub off in
      more (d::acc) off
  in
  more [] 0

(* ... here comes our GADT ... *)


type rdata =
  | Record of b
  | OPTS of opt
  | TSIG of tsig
  | Raw of int32 * Udns_enum.rr_typ * Cstruct.t

type rr = Domain_name.t * rdata

type query = {
  question : question ;
  answer : t Domain_name.Map.t ;
  authority : t Domain_name.Map.t ;
  additional : t Domain_name.Map.t ;
}

let decode_query buf =


let decode buf =
  (* decode header! *)
  decode_query buf
