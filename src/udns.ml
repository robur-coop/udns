(* (c) 2017-2019 Hannes Mehnert, all rights reserved *)

type proto = [ `Tcp | `Udp ]

let andThen v f = match v with 0 -> f | x -> x

let int_compare (a : int) (b : int) = compare a b
let int32_compare (a : int32) (b : int32) = Int32.compare a b

let guard p err = if p then Ok () else Error err

module Name = struct
  module IntMap = Map.Make(struct
      type t = int
      let compare = int_compare
    end)

  open Domain_name

  type err =
    [ `Partial
    | `BadOffset of int
    | `BadTag of int
    | `BadContent of string
    | `TooLong ]

  (*BISECT-IGNORE-BEGIN*)
  let pp_err ppf = function
    | `Partial -> Fmt.string ppf "partial"
    | `BadOffset off -> Fmt.pf ppf "bad offset %d" off
    | `BadTag x -> Fmt.pf ppf "bad tag %d" x
    | `BadContent s -> Fmt.pf ppf "bad content %s" s
    | `TooLong -> Fmt.string ppf "name too long"
  (*BISECT-IGNORE-END*)

  type offset_name_map = (Domain_name.t * int) IntMap.t

  let ptr_tag = 0xC0 (* = 1100 0000 *)

  let decode ?(hostname = true) names buf ~off =
    let open Rresult.R.Infix in
    (* first collect all the labels (and their offsets) *)
    let rec aux offsets off =
      match Cstruct.get_uint8 buf off with
      | 0 -> Ok ((`Z, off), offsets, succ off)
      | i when i >= ptr_tag ->
        let ptr = (i - ptr_tag) lsl 8 + Cstruct.get_uint8 buf (succ off) in
        Ok ((`P ptr, off), offsets, off + 2)
      | i when i >= 64 -> Error (`BadTag i) (* bit patterns starting with 10 or 01 *)
      | i -> (* this is clearly < 64! *)
        let name = Cstruct.to_string (Cstruct.sub buf (succ off) i) in
        aux ((name, off) :: offsets) (succ off + i)
    in
    (* Cstruct.xxx can raise, and we'll have a partial parse then *)
    (try aux [] off with _ -> Error `Partial) >>= fun (l, offs, foff) ->
    (* treat last element special -- either Z or P *)
    (match l with
     | `Z, off -> Ok (off, root, 1)
     | `P p, off -> match IntMap.find p names with
       | exception Not_found -> Error (`BadOffset p)
       | (exp, size) -> Ok (off, exp, size)) >>= fun (off, name, size) ->
    (* insert last label into names Map*)
    let names = IntMap.add off (name, size) names in
    (* fold over offs, insert into names Map, and reassemble the actual name *)
    let t = Array.(append (to_array name) (make (List.length offs) "")) in
    let names, _, size =
      List.fold_left (fun (names, idx, size) (label, off) ->
          let s = succ size + String.length label in
          Array.set t idx label ;
          let sub = of_array (Array.sub t 0 (succ idx)) in
          IntMap.add off (sub, s) names, succ idx, s)
        (names, Array.length (to_array name), size) offs
    in
    let t = of_array t in
    if size > 255 then
      Error `TooLong
    else if hostname && not (is_hostname t) then
      Error (`BadContent (to_string t))
    else
      Ok (t, names, foff)

  type name_offset_map = int Domain_name.Map.t

  let encode ?(compress = true) name names buf off =
    let encode_lbl lbl off =
      let l = String.length lbl in
      Cstruct.set_uint8 buf off l ;
      Cstruct.blit_from_string lbl 0 buf (succ off) l ;
      off + succ l
    and z off =
      Cstruct.set_uint8 buf off 0 ;
      succ off
    in
    let names, off =
      if compress then
        let rec one names off name =
          let arr = to_array name in
          let l = Array.length arr in
          if l = 0 then
            names, z off
          else
            match Map.find name names with
            | None ->
              let last = Array.get arr (pred l)
              and rem = Array.sub arr 0 (pred l)
              in
              let l = encode_lbl last off in
              one (Map.add name off names) l (of_array rem)
            | Some ptr ->
              let data = ptr_tag lsl 8 + ptr in
              Cstruct.BE.set_uint16 buf off data ;
              names, off + 2
        in
        one names off name
      else
        let rec one names off name =
          let arr = to_array name in
          let l = Array.length arr in
          if l = 0 then
            names, z off
          else
            let last = Array.get arr (pred l)
            and rem = Array.sub arr 0 (pred l)
            in
            let l = encode_lbl last off in
            one (Map.add name off names) l (of_array rem)
        in
        one names off name
    in
    names, off
end

(*BISECT-IGNORE-BEGIN*)
let pp_err ppf = function
  | #Name.err as e -> Name.pp_err ppf e
  | `BadTTL x -> Fmt.pf ppf "bad ttl %lu" x
  | `BadRRTyp x -> Fmt.pf ppf "bad rr typ %u" x
  | `UnsupportedRRTyp x -> Fmt.pf ppf "unsupported rr typ %a" Udns_enum.pp_rr_typ x
  | `BadClass x -> Fmt.pf ppf "bad rr class %u" x
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
  | `BadEdns -> Fmt.pf ppf "bad edns"
  | `BadKeepalive -> Fmt.pf ppf "bad keepalive"
  | `BadTlsaCertUsage usage -> Fmt.pf ppf "bad TLSA cert usage %u" usage
  | `BadTlsaSelector selector -> Fmt.pf ppf "bad TLSA selector %u" selector
  | `BadTlsaMatchingType matching_type -> Fmt.pf ppf "bad TLSA matching type %u" matching_type
  | `BadSshfpAlgorithm i -> Fmt.pf ppf "bad SSHFP algorithm %u" i
  | `BadSshfpType i -> Fmt.pf ppf "bad SSHFP type %u" i
  | `Bad_edns_version i -> Fmt.pf ppf "bad edns version %u" i
  | `None_or_multiple_questions -> Fmt.string ppf "none or multiple questions"
(*BISECT-IGNORE-END*)

(* each resource record module has the following signature:
     module S : sig
       type t
       val pp : t Fmt.t
       val compare : t -> t -> int
       val decode : Name.offset_name_map -> Cstruct.t -> off:int -> len:int -> (t * Name.offset_name_map * int, Name.err) result
       val encode : t -> Name.name_offset_map -> Cstruct.t -> off:int -> Name.name_offset_map * int
     end
*)

(* start of authority *)
module Soa = struct
  type t = {
    nameserver : Domain_name.t ;
    hostmaster : Domain_name.t ;
    serial : int32 ;
    refresh : int32 ;
    retry : int32 ;
    expiry : int32 ;
    minimum : int32 ;
  }

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf soa =
    Fmt.pf ppf "SOA %a %a %lu %lu %lu %lu %lu"
      Domain_name.pp soa.nameserver Domain_name.pp soa.hostmaster
      soa.serial soa.refresh soa.retry soa.expiry soa.minimum
  (*BISECT-IGNORE-END*)

  let compare soa soa' =
    andThen (int32_compare soa.serial soa.serial)
      (andThen (Domain_name.compare soa.nameserver soa'.nameserver)
         (andThen (Domain_name.compare soa.hostmaster soa'.hostmaster)
            (andThen (int32_compare soa.refresh soa'.refresh)
               (andThen (int32_compare soa.retry soa'.retry)
                  (andThen (int32_compare soa.expiry soa'.expiry)
                     (int32_compare soa.minimum soa'.minimum))))))

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let hostname = false in
    Name.decode ~hostname names buf ~off >>= fun (nameserver, names, off) ->
    Name.decode ~hostname names buf ~off >>| fun (hostmaster, names, off) ->
    let serial = Cstruct.BE.get_uint32 buf off in
    let refresh = Cstruct.BE.get_uint32 buf (off + 4) in
    let retry = Cstruct.BE.get_uint32 buf (off + 8) in
    let expiry = Cstruct.BE.get_uint32 buf (off + 12) in
    let minimum = Cstruct.BE.get_uint32 buf (off + 16) in
    let soa =
      { nameserver ; hostmaster ; serial ; refresh ; retry ; expiry ; minimum }
    in
    (soa, names, off + 20)

  let encode soa offs buf off =
    let offs, off = Name.encode soa.nameserver offs buf off in
    let offs, off = Name.encode soa.hostmaster offs buf off in
    Cstruct.BE.set_uint32 buf off soa.serial ;
    Cstruct.BE.set_uint32 buf (off + 4) soa.refresh ;
    Cstruct.BE.set_uint32 buf (off + 8) soa.retry ;
    Cstruct.BE.set_uint32 buf (off + 12) soa.expiry ;
    Cstruct.BE.set_uint32 buf (off + 16) soa.minimum ;
    offs, off + 20
end

(* name server *)
module Ns = struct
  type t = Domain_name.t

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf ns = Fmt.pf ppf "NS %a" Domain_name.pp ns
  (*BISECT-IGNORE-END*)

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_ = Name.decode ~hostname:true names buf ~off

  let encode = Name.encode
end

(* mail exchange *)
module Mx = struct
  type t = {
    preference : int ;
    mail_exchange : Domain_name.t ;
  }

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf { preference ; mail_exchange } =
    Fmt.pf ppf "MX %u %a" preference Domain_name.pp mail_exchange
  (*BISECT-IGNORE-END*)

  let compare mx mx' =
    andThen (int_compare mx.preference mx'.preference)
      (Domain_name.compare mx.mail_exchange mx'.mail_exchange)

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let preference = Cstruct.BE.get_uint16 buf off in
    Name.decode ~hostname:false names buf ~off:(off + 2) >>| fun (mx, names, off) ->
    { preference ; mail_exchange = mx }, names, off

  let encode { preference ; mail_exchange } offs buf off =
    Cstruct.BE.set_uint16 buf off preference ;
    Name.encode mail_exchange offs buf (off + 2)
end

(* canonical name *)
module Cname = struct
  type t = Domain_name.t

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf alias = Fmt.pf ppf "CNAME %a" Domain_name.pp alias
  (*BISECT-IGNORE-END*)

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_= Name.decode ~hostname:false names buf ~off

  let encode = Name.encode
end

(* address record *)
module A = struct
  type t = Ipaddr.V4.t

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf address = Fmt.pf ppf "A %a" Ipaddr.V4.pp address
  (*BISECT-IGNORE-END*)

  let compare = Ipaddr.V4.compare

  let decode names buf ~off ~len:_ =
    let ip = Cstruct.BE.get_uint32 buf off in
    Ok (Ipaddr.V4.of_int32 ip, names, off + 4)

  let encode ip offs buf off =
    let ip = Ipaddr.V4.to_int32 ip in
    Cstruct.BE.set_uint32 buf off ip ;
    offs, off + 4
end

(* quad-a record *)
module Aaaa = struct
  type t = Ipaddr.V6.t

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf address = Fmt.pf ppf "AAAA %a" Ipaddr.V6.pp address
  (*BISECT-IGNORE-END*)

  let compare = Ipaddr.V6.compare

  let decode names buf ~off ~len:_ =
    let iph = Cstruct.BE.get_uint64 buf off
    and ipl = Cstruct.BE.get_uint64 buf (off + 8)
    in
    Ok (Ipaddr.V6.of_int64 (iph, ipl), names, off + 16)

  let encode ip offs buf off =
    let iph, ipl = Ipaddr.V6.to_int64 ip in
    Cstruct.BE.set_uint64 buf off iph ;
    Cstruct.BE.set_uint64 buf (off + 8) ipl ;
    offs, off + 16
end

(* domain name pointer - reverse entries *)
module Ptr = struct
  type t = Domain_name.t

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf rev = Fmt.pf ppf "PTR %a" Domain_name.pp rev
  (*BISECT-IGNORE-END*)

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_ = Name.decode ~hostname:true names buf ~off

  let encode = Name.encode
end

(* service record *)
module Srv = struct
  type t = {
    priority : int ;
    weight : int ;
    port : int ;
    target : Domain_name.t
  }

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf t =
    Fmt.pf ppf
      "SRV priority %d weight %d port %d target %a"
      t.priority t.weight t.port Domain_name.pp t.target
  (*BISECT-IGNORE-END*)

  let compare a b =
    andThen (int_compare a.priority b.priority)
      (andThen (int_compare a.weight b.weight)
         (andThen (int_compare a.port b.port)
            (Domain_name.compare a.target b.target)))

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let priority = Cstruct.BE.get_uint16 buf off
    and weight = Cstruct.BE.get_uint16 buf (off + 2)
    and port = Cstruct.BE.get_uint16 buf (off + 4)
    in
    Name.decode names buf ~off:(off + 6) >>= fun (target, names, off) ->
    Ok ({ priority ; weight ; port ; target }, names, off)

  let encode t offs buf off =
    Cstruct.BE.set_uint16 buf off t.priority ;
    Cstruct.BE.set_uint16 buf (off + 2) t.weight ;
    Cstruct.BE.set_uint16 buf (off + 4) t.port ;
    Name.encode t.target offs buf (off + 6)
end

(* DNS key *)
module Dnskey = struct
  type t = {
    flags : int ; (* uint16 *)
    algorithm :  Udns_enum.dnskey ; (* u_int8_t *)
    key : Cstruct.t ;
  }

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf t =
    Fmt.pf ppf "DNSKEY flags %u algo %a key %a"
      t.flags Udns_enum.pp_dnskey t.algorithm
      Cstruct.hexdump_pp t.key
  (*BISECT-IGNORE-END*)

  let compare a b =
    andThen (compare a.algorithm b.algorithm)
      (Cstruct.compare a.key b.key)

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let flags = Cstruct.BE.get_uint16 buf off
    and proto = Cstruct.get_uint8 buf (off + 2)
    and algo = Cstruct.get_uint8 buf (off + 3)
    in
    guard (proto = 3) (`BadProto proto) >>= fun () ->
    match Udns_enum.int_to_dnskey algo with
    | None -> Error (`BadAlgorithm algo)
    | Some algorithm ->
      let len = Udns_enum.dnskey_len algorithm in
      let key = Cstruct.sub buf (off + 4) len in
      Ok ({ flags ; algorithm ; key }, names, off + len + 4)

  let encode t offs buf off =
    Cstruct.BE.set_uint16 buf off t.flags ;
    Cstruct.set_uint8 buf (off + 2) 3 ;
    Cstruct.set_uint8 buf (off + 3) (Udns_enum.dnskey_to_int t.algorithm) ;
    let kl = Cstruct.len t.key in
    Cstruct.blit t.key 0 buf (off + 4) kl ;
    offs, off + 4 + kl

  let of_string key =
    let parse flags algo key =
      let key = Cstruct.of_string key in
      match Udns_enum.string_to_dnskey algo with
      | None -> None
      | Some algorithm -> Some { flags ; algorithm ; key }
    in
    match Astring.String.cuts ~sep:":" key with
    | [ flags ; algo ; key ] ->
      begin match try Some (int_of_string flags) with Failure _ -> None with
        | Some flags -> parse flags algo key
        | None -> None
      end
    | [ algo ; key ] -> parse 0 algo key
    | _ -> None

  let name_key_of_string str =
    match Astring.String.cut ~sep:":" str with
    | None -> Error (`Msg ("couldn't parse " ^ str))
    | Some (name, key) -> match Domain_name.of_string ~hostname:false name, of_string key with
      | Error _, _ | _, None -> Error (`Msg ("failed to parse key " ^ key))
      | Ok name, Some dnskey -> Ok (name, dnskey)
end

(* certificate authority authorization *)
module Caa = struct
  type t = {
    critical : bool ;
    tag : string ;
    value : string list ;
  }

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf t =
    Fmt.pf ppf "CAA critical %b tag %s value %a"
      t.critical t.tag Fmt.(list ~sep:(unit "; ") string) t.value
  (*BISECT-IGNORE-END*)

  let compare a b =
    andThen (compare a.critical b.critical)
      (andThen (String.compare a.tag b.tag)
         (List.fold_left2
            (fun r a b -> match r with 0 -> String.compare a b | x -> x)
            0 a.value b.value))

  let decode names buf ~off ~len =
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
    Ok ({ critical ; tag ; value }, names, off + len)

  let encode t offs buf off =
    Cstruct.set_uint8 buf off (if t.critical then 0x80 else 0x0) ;
    let tl = String.length t.tag in
    Cstruct.set_uint8 buf (succ off) tl ;
    Cstruct.blit_from_string t.tag 0 buf (off + 2) tl ;
    let value = Astring.String.concat ~sep:";" t.value in
    let vl = String.length value in
    Cstruct.blit_from_string value 0 buf (off + 2 + tl) vl ;
    offs, off + tl + 2 + vl
end

(* transport layer security A *)
module Tlsa = struct
  type t = {
    tlsa_cert_usage : Udns_enum.tlsa_cert_usage ;
    tlsa_selector : Udns_enum.tlsa_selector ;
    tlsa_matching_type : Udns_enum.tlsa_matching_type ;
    tlsa_data : Cstruct.t ;
  }

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf tlsa =
    Fmt.pf ppf "TLSA @[<v>%a %a %a@ %a@]"
      Udns_enum.pp_tlsa_cert_usage tlsa.tlsa_cert_usage
      Udns_enum.pp_tlsa_selector tlsa.tlsa_selector
      Udns_enum.pp_tlsa_matching_type tlsa.tlsa_matching_type
      Cstruct.hexdump_pp tlsa.tlsa_data
  (*BISECT-IGNORE-END*)

  let compare t1 t2 =
    andThen (compare t1.tlsa_cert_usage t2.tlsa_cert_usage)
      (andThen (compare t1.tlsa_selector t2.tlsa_selector)
         (andThen (compare t1.tlsa_matching_type t2.tlsa_matching_type)
            (Cstruct.compare t1.tlsa_data t2.tlsa_data)))

  let decode names buf ~off ~len =
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
      let tlsa = { tlsa_cert_usage ; tlsa_selector ; tlsa_matching_type ; tlsa_data } in
      Ok (tlsa, names, off + len)
    | None, _, _ -> Error (`BadTlsaCertUsage usage)
    | _, None, _ -> Error (`BadTlsaSelector selector)
    | _, _, None -> Error (`BadTlsaMatchingType matching_type)

  let encode tlsa offs buf off =
    Cstruct.set_uint8 buf off (Udns_enum.tlsa_cert_usage_to_int tlsa.tlsa_cert_usage) ;
    Cstruct.set_uint8 buf (off + 1) (Udns_enum.tlsa_selector_to_int tlsa.tlsa_selector) ;
    Cstruct.set_uint8 buf (off + 2) (Udns_enum.tlsa_matching_type_to_int tlsa.tlsa_matching_type) ;
    let l = Cstruct.len tlsa.tlsa_data in
    Cstruct.blit tlsa.tlsa_data 0 buf (off + 3) l ;
    offs, off + 3 + l
end

(* secure shell fingerprint *)
module Sshfp = struct
  type t = {
    sshfp_algorithm : Udns_enum.sshfp_algorithm ;
    sshfp_type : Udns_enum.sshfp_type ;
    sshfp_fingerprint : Cstruct.t ;
  }

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf sshfp =
    Fmt.pf ppf "SSHFP %a %a %a"
      Udns_enum.pp_sshfp_algorithm sshfp.sshfp_algorithm
      Udns_enum.pp_sshfp_type sshfp.sshfp_type
      Cstruct.hexdump_pp sshfp.sshfp_fingerprint
  (*BISECT-IGNORE-END*)

  let compare s1 s2 =
    andThen (compare s1.sshfp_algorithm s2.sshfp_algorithm)
      (andThen (compare s1.sshfp_type s2.sshfp_type)
         (Cstruct.compare s1.sshfp_fingerprint s2.sshfp_fingerprint))

  let decode names buf ~off ~len =
    let algo, typ = Cstruct.get_uint8 buf off, Cstruct.get_uint8 buf (succ off) in
    let sshfp_fingerprint = Cstruct.sub buf (off + 2) (len - 2) in
    match Udns_enum.int_to_sshfp_algorithm algo, Udns_enum.int_to_sshfp_type typ with
    | Some sshfp_algorithm, Some sshfp_type ->
      let sshfp = { sshfp_algorithm ; sshfp_type ; sshfp_fingerprint } in
      Ok (sshfp, names, off + len)
    | None, _ -> Error (`BadSshfpAlgorithm algo)
    | _, None -> Error (`BadSshfpType typ)

  let encode sshfp offs buf off =
    Cstruct.set_uint8 buf off (Udns_enum.sshfp_algorithm_to_int sshfp.sshfp_algorithm) ;
    Cstruct.set_uint8 buf (succ off) (Udns_enum.sshfp_type_to_int sshfp.sshfp_type) ;
    let l = Cstruct.len sshfp.sshfp_fingerprint in
    Cstruct.blit sshfp.sshfp_fingerprint 0 buf (off + 2) l ;
    offs, off + l + 2
end

(* Text record *)
module Txt = struct
  type t = string list

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf txt = Fmt.pf ppf "TXT %a" Fmt.(list ~sep:(unit ";@ ") string) txt
  (*BISECT-IGNORE-END*)

  let compare a a' =
    andThen (compare (List.length a) (List.length a'))
      (List.fold_left2
         (fun r a b -> match r with 0 -> String.compare a b | x -> x)
         0 a a')

  let decode names buf ~off ~len =
    let decode_character_str buf off =
      let len = Cstruct.get_uint8 buf off in
      let data = Cstruct.to_string (Cstruct.sub buf (succ off) len) in
      (data, off + len + 1)
    in
    let sub = Cstruct.sub buf off len in
    let rec more acc off =
      if len = off then
        List.rev acc
      else
        let d, off = decode_character_str sub off in
        more (d::acc) off
    in
    let txts = more [] 0 in
    Ok (txts, names, off + len)

  let encode txts offs buf off =
    let encode_character_str buf off s =
      let len = String.length s in
      Cstruct.set_uint8 buf off len ;
      Cstruct.blit_from_string s 0 buf (succ off) len ;
      off + len + 1
    in
    let off = List.fold_left (encode_character_str buf) off txts in
    offs, off
end

module Tsig = struct
  type algorithm =
    | SHA1
    | SHA224
    | SHA256
    | SHA384
    | SHA512

  type t = {
    algorithm : algorithm ;
    signed : Ptime.t ;
    fudge : Ptime.Span.t ;
    mac : Cstruct.t ;
    original_id : int ; (* again 16 bit *)
    error : Udns_enum.rcode ;
    other : Ptime.t option
  }

  let algorithm_to_name, algorithm_of_name =
    let of_s = Domain_name.of_string_exn in
    let map =
      [ (* of_s "HMAC-MD5.SIG-ALG.REG.INT", MD5 ; *)
        of_s "hmac-sha1", SHA1 ;
        of_s "hmac-sha224", SHA224 ;
        of_s "hmac-sha256", SHA256 ;
        of_s "hmac-sha384", SHA384 ;
        of_s "hmac-sha512", SHA512 ]
    in
    (fun a -> fst (List.find (fun (_, t) -> t = a) map)),
    (fun b ->
       try Some (snd (List.find (fun (n, _) -> Domain_name.equal b n) map))
       with Not_found -> None)

  (*BISECT-IGNORE-BEGIN*)
  let pp_algorithm ppf a = Domain_name.pp ppf (algorithm_to_name a)
  (*BISECT-IGNORE-END*)

  (* this is here because I don't like float, and rather convert Ptime.t to int64 *)
  let s_in_d = 86_400L
  let ps_in_s = 1_000_000_000_000L

  let ptime_span_to_int64 ts =
    let d_min, d_max = Int64.(div min_int s_in_d, div max_int s_in_d) in
    let d, ps = Ptime.Span.to_d_ps ts in
    let d = Int64.of_int d in
    if d < d_min || d > d_max then
      None
    else
      let s = Int64.mul d s_in_d in
      let s' = Int64.(add s (div ps ps_in_s)) in
      if s' < s then
        None
      else
        Some s'

  let ptime_of_int64 s =
    let d, ps = Int64.(div s s_in_d, mul (rem s s_in_d) ps_in_s) in
    if d < Int64.of_int min_int || d > Int64.of_int max_int then
      None
    else
      Some (Ptime.v (Int64.to_int d, ps))

  let valid_time now tsig =
    let ts = tsig.signed
    and fudge = tsig.fudge
    in
    match Ptime.add_span now fudge, Ptime.sub_span now fudge with
    | None, _ -> false
    | _, None -> false
    | Some late, Some early ->
      Ptime.is_earlier ts ~than:late && Ptime.is_later ts ~than:early

  let tsig ~algorithm ~signed ?(fudge = Ptime.Span.of_int_s 300)
      ?(mac = Cstruct.create 0) ?(original_id = 0) ?(error = Udns_enum.NoError)
      ?other () =
    match ptime_span_to_int64 (Ptime.to_span signed), ptime_span_to_int64 fudge with
    | None, _ | _, None -> None
    | Some ts, Some fu ->
      if
        Int64.logand 0xffff_0000_0000_0000L ts = 0L &&
        Int64.logand 0xffff_ffff_ffff_0000L fu = 0L
      then
        Some { algorithm ; signed ; fudge ; mac ; original_id ; error ; other }
      else
        None

  let with_mac tsig mac = { tsig with mac }

  let with_error tsig error = { tsig with error }

  let with_signed tsig signed =
    match ptime_span_to_int64 (Ptime.to_span signed) with
    | Some x when Int64.logand 0xffff_0000_0000_0000L x = 0L ->
      Some { tsig with signed }
    | _ -> None

  let with_other tsig other =
    match other with
    | None -> Some { tsig with other }
    | Some ts ->
      match ptime_span_to_int64 (Ptime.to_span ts) with
      | Some x when Int64.logand 0xffff_0000_0000_0000L x = 0L ->
        Some { tsig with other }
      | _ -> None

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf t =
    Fmt.pf ppf
      "TSIG %a signed %a fudge %a mac %a original id %04X err %a other %a"
      pp_algorithm t.algorithm
      (Ptime.pp_rfc3339 ()) t.signed Ptime.Span.pp t.fudge
      Cstruct.hexdump_pp t.mac t.original_id Udns_enum.pp_rcode t.error
      Fmt.(option ~none:(unit "none") (Ptime.pp_rfc3339 ())) t.other
  (*BISECT-IGNORE-END*)

  let decode_48bit_time buf off =
    let a = Cstruct.BE.get_uint16 buf off
    and b = Cstruct.BE.get_uint16 buf (off + 2)
    and c = Cstruct.BE.get_uint16 buf (off + 4)
    in
    Int64.(add
             (add (shift_left (of_int a) 32) (shift_left (of_int b) 16))
             (of_int c))

  (* TODO maybe revise, esp. all the guards *)
  let decode names buf ~off =
    let open Rresult.R.Infix in
    guard (Cstruct.len buf - off >= 6) `Partial >>= fun () ->
    let ttl = Cstruct.BE.get_uint32 buf off in
    guard (ttl = 0l) (`BadTTL ttl) >>= fun () ->
    let len = Cstruct.BE.get_uint16 buf (off + 4) in
    let rdata_start = off + 6 in
    guard (Cstruct.len buf - rdata_start >= len) `Partial >>= fun () ->
    Name.decode ~hostname:false names buf ~off:rdata_start >>= fun (algorithm, names, off) ->
    guard (Cstruct.len buf - off >= 10) `Partial >>= fun () ->
    let signed = decode_48bit_time buf off
    and fudge = Cstruct.BE.get_uint16 buf (off + 6)
    and mac_len = Cstruct.BE.get_uint16 buf (off + 8)
    in
    guard (Cstruct.len buf - off >= 10 + mac_len + 6) `Partial >>= fun () ->
    let mac = Cstruct.sub buf (off + 10) mac_len
    and original_id = Cstruct.BE.get_uint16 buf (off + 10 + mac_len)
    and error = Cstruct.BE.get_uint16 buf (off + 12 + mac_len)
    and other_len = Cstruct.BE.get_uint16 buf (off + 14 + mac_len)
    in
    let rdata_end = off + 10 + mac_len + 6 + other_len in
    guard (rdata_end - rdata_start = len) `Partial >>= fun () ->
    guard (Cstruct.len buf >= rdata_end) `Partial >>= fun () ->
    guard (other_len = 0 || other_len = 6) `Partial >>= fun () -> (* TODO: better error! *)
    match algorithm_of_name algorithm, ptime_of_int64 signed, Udns_enum.int_to_rcode error with
    | None, _, _ -> Error (`InvalidAlgorithm algorithm)
    | _, None, _ -> Error (`InvalidTimestamp signed)
    | _, _, None -> Error (`BadRcode error)
    | Some algorithm, Some signed, Some error ->
      (if other_len = 0 then
         Ok None
       else
         let other = decode_48bit_time buf (off + 16 + mac_len) in
         match ptime_of_int64 other with
         | None -> Error (`InvalidTimestamp other)
         | Some x -> Ok (Some x)) >>= fun other ->
      let fudge = Ptime.Span.of_int_s fudge in
      Ok ({ algorithm ; signed ; fudge ; mac ; original_id ; error ; other },
          names,
          off + 16 + mac_len + other_len)

  let encode_48bit_time buf ?(off = 0) ts =
    match ptime_span_to_int64 (Ptime.to_span ts) with
    | None ->
      Logs.warn (fun m -> m "couldn't convert (to_span %a) to int64" Ptime.pp ts)
    | Some secs ->
      if Int64.logand secs 0xffff_0000_0000_0000L > 0L then
        Logs.warn (fun m -> m "secs %Lu > 48 bit" secs)
      else
        let a, b, c =
          let f s = Int64.(to_int (logand 0xffffL (shift_right secs s))) in
          f 32, f 16, f 0
        in
        Cstruct.BE.set_uint16 buf off a ;
        Cstruct.BE.set_uint16 buf (off + 2) b ;
        Cstruct.BE.set_uint16 buf (off + 4) c

  let encode_16bit_time buf ?(off = 0) ts =
    match ptime_span_to_int64 ts with
    | None ->
      Logs.warn (fun m -> m "couldn't convert span %a to int64" Ptime.Span.pp ts)
    | Some secs ->
      if Int64.logand secs 0xffff_ffff_ffff_0000L > 0L then
        Logs.warn (fun m -> m "secs %Lu > 16 bit" secs)
      else
        let a = Int64.(to_int (logand 0xffffL secs)) in
        Cstruct.BE.set_uint16 buf off a

  let encode t offs buf off =
    let algo = algorithm_to_name t.algorithm in
    let offs, off = Name.encode ~compress:false algo offs buf off in
    encode_48bit_time buf ~off t.signed ;
    encode_16bit_time buf ~off:(off + 6) t.fudge ;
    let mac_len = Cstruct.len t.mac in
    Cstruct.BE.set_uint16 buf (off + 8) mac_len ;
    Cstruct.blit t.mac 0 buf (off + 10) mac_len ;
    Cstruct.BE.set_uint16 buf (off + 10 + mac_len) t.original_id ;
    Cstruct.BE.set_uint16 buf (off + 12 + mac_len) (Udns_enum.rcode_to_int t.error) ;
    let other_len = match t.other with None -> 0 | Some _ -> 6 in
    Cstruct.BE.set_uint16 buf (off + 14 + mac_len) other_len ;
    (match t.other with
     | None -> ()
     | Some t -> encode_48bit_time buf ~off:(off + 16 + mac_len) t) ;
    offs, off + 16 + mac_len + other_len

  let canonical_name name =
    let buf = Cstruct.create 255
    and emp = Domain_name.Map.empty
    and nam = Domain_name.canonical name
    in
    let _, off = Name.encode ~compress:false nam emp buf 0 in
    Cstruct.sub buf 0 off

  let encode_raw_tsig_base name t =
    let name = canonical_name name
    and aname = canonical_name (algorithm_to_name t.algorithm)
    in
    let clttl = Cstruct.create 6 in
    Cstruct.BE.set_uint16 clttl 0 Udns_enum.(clas_to_int ANY_CLASS) ;
    Cstruct.BE.set_uint32 clttl 2 0l ;
    let time = Cstruct.create 8 in
    encode_48bit_time time t.signed ;
    encode_16bit_time time ~off:6 t.fudge ;
    let other =
      let buf = match t.other with
        | None ->
          let buf = Cstruct.create 4 in
          Cstruct.BE.set_uint16 buf 2 0 ;
          buf
        | Some t ->
          let buf = Cstruct.create 10 in
          Cstruct.BE.set_uint16 buf 2 6 ;
          encode_48bit_time buf ~off:4 t ;
          buf
      in
      Cstruct.BE.set_uint16 buf 0 (Udns_enum.rcode_to_int t.error) ;
      buf
    in
    name, clttl, [ aname ; time ], other

  let encode_raw name t =
    let name, clttl, mid, fin = encode_raw_tsig_base name t in
    Cstruct.concat (name :: clttl :: mid @ [ fin ])

  let encode_full name t =
    let name, clttl, mid, fin = encode_raw_tsig_base name t in
    let typ =
      let typ = Cstruct.create 2 in
      Cstruct.BE.set_uint16 typ 0 Udns_enum.(rr_typ_to_int TSIG) ;
      typ
    and mac =
      let len = Cstruct.len t.mac in
      let l = Cstruct.create 2 in
      Cstruct.BE.set_uint16 l 0 len ;
      let orig = Cstruct.create 2 in
      Cstruct.BE.set_uint16 orig 0 t.original_id ;
      [ l ; t.mac ; orig ]
    in
    let rdata = Cstruct.concat (mid @ mac @ [ fin ]) in
    let len =
      let buf = Cstruct.create 2 in
      Cstruct.BE.set_uint16 buf 0 (Cstruct.len rdata) ;
      buf
    in
    Cstruct.concat [ name ; typ ; clttl ; len ; rdata ]

  let dnskey_to_tsig_algo key =
    match key.Dnskey.algorithm with
    | Udns_enum.MD5 -> None
    | Udns_enum.SHA1 -> Some SHA1
    | Udns_enum.SHA224 -> Some SHA224
    | Udns_enum.SHA256 -> Some SHA256
    | Udns_enum.SHA384 -> Some SHA384
    | Udns_enum.SHA512 -> Some SHA512
end

module Edns = struct
  type extension =
    | Nsid of Cstruct.t
    | Cookie of Cstruct.t
    | Tcp_keepalive of int option
    | Padding of int
    | Extension of int * Cstruct.t

  type t = {
    extended_rcode : int ;
    version : int ;
    dnssec_ok : bool ;
    payload_size : int ;
    extensions : extension list ;
  }

  let edns ?(extended_rcode = 0) ?(version = 0) ?(dnssec_ok = false)
      ?(payload_size = 512) ?(extensions = []) () =
    { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions }

  (* once we handle cookies, dnssec, or other extensions, need to adjust *)
  let reply = function
    | None -> None, None
    | Some opt ->
      let payload_size = opt.payload_size in
      Some payload_size, Some (edns ~payload_size ())

  let compare_extension a b = match a, b with
    | Nsid a, Nsid b -> Cstruct.compare a b
    | Nsid _, _ -> 1 | _, Nsid _ -> -1
    | Cookie a, Cookie b -> Cstruct.compare a b
    | Cookie _, _ -> 1 | _, Cookie _ -> -1
    | Tcp_keepalive a, Tcp_keepalive b ->
      begin match a, b with
        | None, None -> 0
        | None, Some _ -> -1
        | Some _, None -> 1
        | Some a, Some b -> int_compare a b
      end
    | Tcp_keepalive _, _ -> 1 | _, Tcp_keepalive _ -> -1
    | Padding a, Padding b -> int_compare a b
    | Padding _, _ -> 1 | _, Padding _ -> -1
    | Extension (t, v), Extension (t', v') ->
      andThen (int_compare t t') (Cstruct.compare v v')

  let compare_opt a b =
    andThen (int_compare a.extended_rcode b.extended_rcode)
      (andThen (int_compare a.version b.version)
         (andThen (compare a.dnssec_ok b.dnssec_ok)
            (andThen (int_compare a.payload_size b.payload_size)
               (List.fold_left2
                  (fun r a b -> if r = 0 then compare_extension a b else r)
                  (compare (List.length a.extensions) (List.length b.extensions))
                  a.extensions b.extensions))))

  (*BISECT-IGNORE-BEGIN*)
  let pp_extension ppf = function
    | Nsid cs -> Fmt.pf ppf "nsid %a" Cstruct.hexdump_pp cs
    | Cookie cs -> Fmt.pf ppf "cookie %a" Cstruct.hexdump_pp cs
    | Tcp_keepalive i -> Fmt.pf ppf "keepalive %a" Fmt.(option ~none:(unit "none") int) i
    | Padding i -> Fmt.pf ppf "padding %d" i
    | Extension (t, v) -> Fmt.pf ppf "unknown option %d: %a" t Cstruct.hexdump_pp v

  let pp ppf opt =
    Fmt.(pf ppf "EDNS (ext %u version %u dnssec_ok %b payload_size %u extensions %a"
           opt.extended_rcode opt.version opt.dnssec_ok opt.payload_size
           (list ~sep:(unit ", ") pp_extension) opt.extensions)
  (*BISECT-IGNORE-END*)

  let decode_extension buf ~off ~len =
    let open Rresult.R.Infix in
    let code = Cstruct.BE.get_uint16 buf off
    and tl = Cstruct.BE.get_uint16 buf (off + 2)
    in
    guard (tl <= len - 4) `BadEdns >>= fun () ->
    let v = Cstruct.sub buf (off + 4) tl in
    let len = tl + 4 in
    match Udns_enum.int_to_edns_opt code with
    | Some Udns_enum.NSID -> Ok (Nsid v, len)
    | Some Udns_enum.Cookie -> Ok (Cookie v, len)
    | Some Udns_enum.TCP_keepalive ->
      (begin match tl with
         | 0 -> Ok None
         | 2 -> Ok (Some (Cstruct.BE.get_uint16 v 0))
         | _ -> Error `BadKeepalive
       end >>= fun i ->
       Ok (Tcp_keepalive i, len))
    | Some Udns_enum.Padding -> Ok (Padding tl, len)
    | _ -> Ok (Extension (code, v), len)

  let decode_extensions buf ~len =
    let open Rresult.R.Infix in
    let rec one acc pos =
      if len = pos then
        Ok (List.rev acc)
      else
        decode_extension buf ~off:pos ~len:(len - pos) >>= fun (opt, len) ->
        one (opt :: acc) (pos + len)
    in
    one [] 0

  let decode buf ~off =
    let open Rresult.R.Infix in
    (* EDNS is special -- the incoming off points to before name type clas *)
    (* name must be the root, typ is OPT, class is used for length *)
    guard (Cstruct.len buf - off >= 11) `Partial >>= fun () ->
    guard (Cstruct.get_uint8 buf off = 0) `BadEdns >>= fun () ->
    (* crazyness: payload_size is encoded in class *)
    let payload_size = Cstruct.BE.get_uint16 buf (off + 3)
    (* it continues: the ttl is split into: 8bit extended rcode, 8bit version, 1bit dnssec_ok, 7bit 0 *)
    and extended_rcode = Cstruct.get_uint8 buf (off + 5)
    and version = Cstruct.get_uint8 buf (off + 6)
    and flags = Cstruct.BE.get_uint16 buf (off + 7)
    and len = Cstruct.BE.get_uint16 buf (off + 9)
    in
    let off = off + 11 in
    let dnssec_ok = flags land 0x8000_0000 = 0x8000_0000 in
    guard (version = 0) (`Bad_edns_version version) >>= fun () ->
    let exts_buf = Cstruct.sub buf off len in
    (try decode_extensions exts_buf ~len with _ -> Error `Partial) >>= fun extensions ->
    let opt = { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions } in
    Ok (opt, off + len)

  let encode_extension t buf off =
    let o_i = Udns_enum.edns_opt_to_int in
    let code, v = match t with
      | Nsid cs -> o_i Udns_enum.NSID, cs
      | Cookie cs -> o_i Udns_enum.Cookie, cs
      | Tcp_keepalive i -> o_i Udns_enum.TCP_keepalive, (match i with None -> Cstruct.create 0 | Some i -> let buf = Cstruct.create 2 in Cstruct.BE.set_uint16 buf 0 i ; buf)
      | Padding i -> o_i Udns_enum.Padding, Cstruct.create i
      | Extension (t, v) -> t, v
    in
    let l = Cstruct.len v in
    Cstruct.BE.set_uint16 buf off code ;
    Cstruct.BE.set_uint16 buf (off + 2) l ;
    Cstruct.blit v 0 buf (off + 4) l ;
    off + 4 + l

  let encode_extensions t buf off =
    List.fold_left (fun off opt -> encode_extension opt buf off) off t

  let encode t buf off =
    (* name is . *)
    Cstruct.set_uint8 buf off 0 ;
    (* type *)
    Cstruct.BE.set_uint16 buf (off + 1) Udns_enum.(rr_typ_to_int OPT) ;
    (* class is payload size! *)
    Cstruct.BE.set_uint16 buf (off + 3) t.payload_size ;
    (* it continues: the ttl is split into: 8bit extended rcode, 8bit version, 1bit dnssec_ok, 7bit 0 *)
    Cstruct.set_uint8 buf (off + 5) t.extended_rcode ;
    Cstruct.set_uint8 buf (off + 6) t.version ;
    Cstruct.BE.set_uint16 buf (off + 7) (if t.dnssec_ok then 0x8000_0000 else 0) ;
    let ext_start = off + 11 in
    let ext_end = encode_extensions t.extensions buf ext_start in
    Cstruct.BE.set_uint16 buf (off + 9) (ext_end - ext_start) ;
    ext_end

  let allocate_and_encode edns =
    (* this is unwise! *)
    let buf = Cstruct.create 128 in
    let off = encode edns buf 0 in
    Cstruct.sub buf 0 off
end

let encode_ntc offs buf off (n, t, c) =
  let offs, off = Name.encode n offs buf off in
  Cstruct.BE.set_uint16 buf off (Udns_enum.rr_typ_to_int t) ;
  Cstruct.BE.set_uint16 buf (off + 2) c ;
  (offs, off + 4)

(* resource record map *)
module Map = struct
  module Mx_set = Set.Make(Mx)
  module Txt_set = Set.Make(Txt)
  module Ipv4_set = Set.Make(Ipaddr.V4)
  module Ipv6_set = Set.Make(Ipaddr.V6)
  module Srv_set = Set.Make(Srv)
  module Dnskey_set = Set.Make(Dnskey)
  module Caa_set = Set.Make(Caa)
  module Tlsa_set = Set.Make(Tlsa)
  module Sshfp_set = Set.Make(Sshfp)

  type _ k =
    | Soa : (int32 * Soa.t) k
    | Ns : (int32 * Domain_name.Set.t) k
    | Mx : (int32 * Mx_set.t) k
    | Cname : (int32 * Domain_name.t) k
    | A : (int32 * Ipv4_set.t) k
    | Aaaa : (int32 * Ipv6_set.t) k
    | Ptr : (int32 * Domain_name.t) k
    | Srv : (int32 * Srv_set.t) k
    | Dnskey : (int32 * Dnskey_set.t) k
    | Caa : (int32 * Caa_set.t) k
    | Tlsa : (int32 * Tlsa_set.t) k
    | Sshfp : (int32 * Sshfp_set.t) k
    | Txt : (int32 * Txt_set.t) k

  let equal_k : type a b . a k -> a -> b k -> b -> bool = fun k v k' v' ->
    match k, v, k', v' with
    | Cname, (_, alias), Cname, (_, alias') -> Domain_name.equal alias alias'
    | Mx, (_, mxs), Mx, (_, mxs') -> Mx_set.equal mxs mxs'
    | Ns, (_, ns), Ns, (_, ns') -> Domain_name.Set.equal ns ns'
    | Ptr, (_, name), Ptr, (_, name') -> Domain_name.equal name name'
    | Soa, (_, soa), Soa, (_, soa') -> Soa.compare soa soa' = 0
    | Txt, (_, txts), Txt, (_, txts') -> Txt_set.equal txts txts'
    | A, (_, aas), A, (_, aas') -> Ipv4_set.equal aas aas'
    | Aaaa, (_, aaaas), Aaaa, (_, aaaas') -> Ipv6_set.equal aaaas aaaas'
    | Srv, (_, srvs), Srv, (_, srvs') -> Srv_set.equal srvs srvs'
    | Dnskey, (_, keys), Dnskey, (_, keys') -> Dnskey_set.equal keys keys'
    | Caa, (_, caas), Caa, (_, caas') -> Caa_set.equal caas caas'
    | Tlsa, (_, tlsas), Tlsa, (_, tlsas') -> Tlsa_set.equal tlsas tlsas'
    | Sshfp, (_, sshfps), Sshfp, (_, sshfps') -> Sshfp_set.equal sshfps sshfps'
    | _, _, _, _ -> false

  let k_to_rr_typ : type a. a k -> Udns_enum.rr_typ = function
    | Cname -> Udns_enum.CNAME
    | Mx -> Udns_enum.MX
    | Ns -> Udns_enum.NS
    | Ptr -> Udns_enum.PTR
    | Soa -> Udns_enum.SOA
    | Txt -> Udns_enum.TXT
    | A -> Udns_enum.A
    | Aaaa -> Udns_enum.AAAA
    | Srv -> Udns_enum.SRV
    | Dnskey -> Udns_enum.DNSKEY
    | Caa -> Udns_enum.CAA
    | Tlsa -> Udns_enum.TLSA
    | Sshfp -> Udns_enum.SSHFP

  let encode : type a. Domain_name.t -> a k -> a -> Name.name_offset_map -> Cstruct.t -> int ->
    (Name.name_offset_map * int) * int = fun name k v offs buf off ->
    let typ = k_to_rr_typ k
    and clas = Udns_enum.clas_to_int Udns_enum.IN
    in
    let rr offs f off ttl =
      let offs', off' = encode_ntc offs buf off (name, typ, clas) in
      (* leave 6 bytes space for TTL and length *)
      let rdata_start = off' + 6 in
      let offs'', rdata_end = f offs' buf rdata_start in
      let rdata_len = rdata_end - rdata_start in
      Cstruct.BE.set_uint32 buf off' ttl ;
      Cstruct.BE.set_uint16 buf (off' + 4) rdata_len ;
      (offs'', rdata_end)
    in
    match k, v with
    | Soa, (ttl, soa) -> rr offs (Soa.encode soa) off ttl, 1
    | Ns, (ttl, ns) ->
      Domain_name.Set.fold (fun name ((offs, off), count) ->
          rr offs (Ns.encode name) off ttl, succ count)
        ns ((offs, off), 0)
    | Mx, (ttl, mx) ->
      Mx_set.fold (fun mx ((offs, off), count) ->
          rr offs (Mx.encode mx) off ttl, succ count)
        mx ((offs, off), 0)
    | Cname, (ttl, alias) ->
      rr offs (Cname.encode alias) off ttl, 1
    | A, (ttl, addresses) ->
      Ipv4_set.fold (fun address ((offs, off), count) ->
        rr offs (A.encode address) off ttl, succ count)
        addresses ((offs, off), 0)
    | Aaaa, (ttl, aaaas) ->
      Ipv6_set.fold (fun address ((offs, off), count) ->
          rr offs (Aaaa.encode address) off ttl, succ count)
        aaaas ((offs, off), 0)
    | Ptr, (ttl, rev) ->
      rr offs (Ptr.encode rev) off ttl, 1
    | Srv, (ttl, srvs) ->
      Srv_set.fold (fun srv ((offs, off), count) ->
          rr offs (Srv.encode srv) off ttl, succ count)
        srvs ((offs, off), 0)
    | Dnskey, (ttl, dnskeys) ->
      Dnskey_set.fold (fun dnskey ((offs, off), count) ->
        rr offs (Dnskey.encode dnskey) off ttl, succ count)
        dnskeys ((offs, off), 0)
    | Caa, (ttl, caas) ->
      Caa_set.fold (fun caa ((offs, off), count) ->
          rr offs (Caa.encode caa) off ttl, succ count)
        caas ((offs, off), 0)
    | Tlsa, (ttl, tlsas) ->
      Tlsa_set.fold (fun tlsa ((offs, off), count) ->
          rr offs (Tlsa.encode tlsa) off ttl, succ count)
        tlsas ((offs, off), 0)
    | Sshfp, (ttl, sshfps) ->
      Sshfp_set.fold (fun sshfp ((offs, off), count) ->
          rr offs (Sshfp.encode sshfp) off ttl, succ count)
        sshfps ((offs, off), 0)
    | Txt, (ttl, txts) ->
      Txt_set.fold (fun txt ((offs, off), count) ->
          rr offs (Txt.encode txt) off ttl, succ count)
        txts ((offs, off), 0)

  let combine : type a. a k -> a -> a option -> a option = fun k v old ->
    match k, v, old with
    | _, v, None -> Some v
    | t, v, Some old ->
      Some (match t, v, old with
          | Cname, _, cname -> cname
          | Mx, (_, mxs), (ttl, mxs') -> (ttl, Mx_set.union mxs mxs')
          | Ns, (_, ns), (ttl, ns') -> (ttl, Domain_name.Set.union ns ns')
          | Ptr, _, ptr -> ptr
          | Soa, _, soa -> soa
          | Txt, (_, txts), (ttl, txts') -> (ttl, Txt_set.union txts txts')
          | A, (_, ips), (ttl, ips') -> (ttl, Ipv4_set.union ips ips')
          | Aaaa, (_, ips), (ttl, ips') -> (ttl, Ipv6_set.union ips ips')
          | Srv, (_, srvs), (ttl, srvs') -> (ttl, Srv_set.union srvs srvs')
          | Dnskey, (_, keys), (ttl, keys') -> (ttl, Dnskey_set.union keys keys')
          | Caa, (_, caas), (ttl, caas') -> (ttl, Caa_set.union caas caas')
          | Tlsa, (_, tlsas), (ttl, tlsas') -> (ttl, Tlsa_set.union tlsas tlsas')
          | Sshfp, (_, sshfps), (ttl, sshfps') -> (ttl, Sshfp_set.union sshfps sshfps'))

  let text : type a. ?origin:Domain_name.t -> ?default_ttl:int32 ->
    Domain_name.t -> a k -> a -> string = fun ?origin ?default_ttl n t v ->
    let hex cs =
      let buf = Bytes.create (Cstruct.len cs * 2) in
      for i = 0 to pred (Cstruct.len cs) do
        let byte = Cstruct.get_uint8 cs i in
        let up, low = byte lsr 4, byte land 0x0F in
        let to_hex_char v = char_of_int (if v < 10 then 0x30 + v else 0x37 + v) in
        Bytes.set buf (i * 2) (to_hex_char up) ;
        Bytes.set buf (i * 2 + 1) (to_hex_char low)
      done;
      Bytes.unsafe_to_string buf
    in
    let origin = match origin with
      | None -> None
      | Some n -> Some (n, Array.length (Domain_name.to_array n))
    in
    let name n = match origin with
      | Some (domain, amount) when Domain_name.sub ~subdomain:n ~domain ->
        let n' = Domain_name.drop_labels_exn ~back:true ~amount n in
        if Domain_name.equal n' Domain_name.root then
          "@"
        else
          Domain_name.to_string n'
      | _ -> Domain_name.to_string ~trailing:true n
    in
    let ttl_opt ttl = match default_ttl with
      | Some d when Int32.compare ttl d = 0 -> None
      | _ -> Some ttl
    in
    let ttl_fmt = Fmt.(option (suffix (unit "\t") uint32)) in
    let str_name = name n in
    let strs =
      match t, v with
      | Cname, (ttl, alias) ->
        [ Fmt.strf "%s\t%aCNAME\t%s" str_name ttl_fmt (ttl_opt ttl) (name alias) ]
      | Mx, (ttl, mxs) ->
        Mx_set.fold (fun { preference ; mail_exchange } acc ->
            Fmt.strf "%s\t%aMX\t%u\t%s" str_name ttl_fmt (ttl_opt ttl) preference (name mail_exchange) :: acc)
          mxs []
      | Ns, (ttl, ns) ->
        Domain_name.Set.fold (fun ns acc ->
            Fmt.strf "%s\t%aNS\t%s" str_name ttl_fmt (ttl_opt ttl) (name ns) :: acc)
          ns []
      | Ptr, (ttl, ptr) ->
        [ Fmt.strf "%s\t%aPTR\t%s" str_name ttl_fmt (ttl_opt ttl) (name ptr) ]
      | Soa, (ttl, soa) ->
        [ Fmt.strf "%s\t%aSOA\t%s\t%s\t%lu\t%lu\t%lu\t%lu\t%lu" str_name
            ttl_fmt (ttl_opt ttl)
            (name soa.nameserver)
            (name soa.hostmaster)
            soa.serial soa.refresh soa.retry
            soa.expiry soa.minimum ]
      | Txt, (ttl, txts) ->
        Txt_set.fold (fun txt acc ->
            Fmt.strf "%s\t%aTXT\t%s" str_name ttl_fmt (ttl_opt ttl) (String.concat "" txt) :: acc)
          txts []
      | A, (ttl, a) ->
        Ipv4_set.fold (fun ip acc ->
          Fmt.strf "%s\t%aA\t%s" str_name ttl_fmt (ttl_opt ttl) (Ipaddr.V4.to_string ip) :: acc)
          a []
      | Aaaa, (ttl, aaaa) ->
        Ipv6_set.fold (fun ip acc ->
            Fmt.strf "%s\t%aAAAA\t%s" str_name ttl_fmt (ttl_opt ttl) (Ipaddr.V6.to_string ip) :: acc)
          aaaa []
      | Srv, (ttl, srvs) ->
        Srv_set.fold (fun srv acc ->
            Fmt.strf "%s\t%aSRV\t%u\t%u\t%u\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              srv.priority srv.weight srv.port
              (name srv.target) :: acc)
          srvs []
      | Dnskey, (ttl, keys) ->
        Dnskey_set.fold (fun key acc ->
            Fmt.strf "%s%a\tDNSKEY\t%u\t3\t%d\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              key.flags
              (Udns_enum.dnskey_to_int key.algorithm)
              (hex key.key) :: acc)
          keys []
      | Caa, (ttl, caas) ->
        Caa_set.fold (fun caa acc ->
            Fmt.strf "%s\t%aCAA\t%s\t%s\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              (if caa.critical then "128" else "0")
              caa.tag (String.concat ";" caa.value) :: acc)
          caas []
      | Tlsa, (ttl, tlsas) ->
        Tlsa_set.fold (fun tlsa acc ->
            Fmt.strf "%s\t%aTLSA\t%u\t%u\t%u\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              (Udns_enum.tlsa_cert_usage_to_int tlsa.tlsa_cert_usage)
              (Udns_enum.tlsa_selector_to_int tlsa.tlsa_selector)
              (Udns_enum.tlsa_matching_type_to_int tlsa.tlsa_matching_type)
              (hex tlsa.tlsa_data) :: acc)
          tlsas []
      | Sshfp, (ttl, sshfps) ->
        Sshfp_set.fold (fun sshfp acc ->
            Fmt.strf "%s\t%aSSHFP\t%u\t%u\t%s" str_name ttl_fmt (ttl_opt ttl)
              (Udns_enum.sshfp_algorithm_to_int sshfp.sshfp_algorithm)
              (Udns_enum.sshfp_type_to_int sshfp.sshfp_type)
              (hex sshfp.sshfp_fingerprint) :: acc)
          sshfps []
    in
    String.concat "\n" strs

  module K = struct
    type 'a t = 'a k

    let compare : type a b. a t -> b t -> (a, b) Gmap.Order.t = fun t t' ->
      let open Gmap.Order in
      match t, t' with
      | Soa, Soa -> Eq | Soa, _ -> Lt | _, Soa -> Gt
      | Ns, Ns -> Eq | Ns, _ -> Lt | _, Ns -> Gt
      | Mx, Mx -> Eq | Mx, _ -> Lt | _, Mx -> Gt
      | Cname, Cname -> Eq | Cname, _ -> Lt | _, Cname -> Gt
      | A, A -> Eq | A, _ -> Lt | _, A -> Gt
      | Aaaa, Aaaa -> Eq | Aaaa, _ -> Lt | _, Aaaa -> Gt
      | Ptr, Ptr -> Eq | Ptr, _ -> Lt | _, Ptr -> Gt
      | Srv, Srv -> Eq | Srv, _ -> Lt | _, Srv -> Gt
      | Dnskey, Dnskey -> Eq | Dnskey, _ -> Lt | _, Dnskey -> Gt
      | Caa, Caa -> Eq | Caa, _ -> Lt | _, Caa -> Gt
      | Tlsa, Tlsa -> Eq | Tlsa, _ -> Lt | _, Tlsa -> Gt
      | Sshfp, Sshfp -> Eq | Sshfp, _ -> Lt | _, Sshfp -> Gt
      | Txt, Txt -> Eq (* | Txt, _ -> Lt | _, Txt -> Gt *)

    let pp : type a. Format.formatter -> a t -> a -> unit = fun ppf t v ->
      match t, v with
      | Cname, (ttl, cname) -> Fmt.pf ppf "ttl %lu %a" ttl Cname.pp cname
      | Mx, (ttl, mxs) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Mx.pp) (Mx_set.elements mxs)
      | Ns, (ttl, names) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Ns.pp) (Domain_name.Set.elements names)
      | Ptr, (ttl, name) -> Fmt.pf ppf "ttl %lu %a" ttl Ptr.pp name
      | Soa, (ttl, soa) -> Fmt.pf ppf "ttl %lu %a" ttl Soa.pp soa
      | Txt, (ttl, txts) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Txt.pp) (Txt_set.elements txts)
      | A, (ttl, a) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") A.pp) (Ipv4_set.elements a)
      | Aaaa, (ttl, aaaas) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Aaaa.pp) (Ipv6_set.elements aaaas)
      | Srv, (ttl, srvs) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Srv.pp) (Srv_set.elements srvs)
      | Dnskey, (ttl, keys) ->
        Fmt.pf ppf "%lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Dnskey.pp) (Dnskey_set.elements keys)
      | Caa, (ttl, caas) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Caa.pp) (Caa_set.elements caas)
      | Tlsa, (ttl, tlsas) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Tlsa.pp) (Tlsa_set.elements tlsas)
      | Sshfp, (ttl, sshfps) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Sshfp.pp) (Sshfp_set.elements sshfps)
  end

  include Gmap.Make(K)

  let get_ttl : b -> int32 = fun (B (k, v)) ->
    match k, v with
    | Cname, (ttl, _) -> ttl
    | Mx, (ttl, _) -> ttl
    | Ns, (ttl, _) -> ttl
    | Ptr, (ttl, _) -> ttl
    | Soa, (ttl, _) -> ttl
    | Txt, (ttl, _) -> ttl
    | A, (ttl, _) -> ttl
    | Aaaa, (ttl, _) -> ttl
    | Srv, (ttl, _) -> ttl
    | Dnskey, (ttl, _) -> ttl
    | Caa, (ttl, _) -> ttl
    | Tlsa, (ttl, _) -> ttl
    | Sshfp, (ttl, _) -> ttl

  let with_ttl : b -> int32 -> b = fun (B (k, v)) ttl ->
    match k, v with
    | Cname, (_, cname) -> B (k, (ttl, cname))
    | Mx, (_, mxs) -> B (k, (ttl, mxs))
    | Ns, (_, ns) -> B (k, (ttl, ns))
    | Ptr, (_, ptr) -> B (k, (ttl, ptr))
    | Soa, (_, soa) -> B (k, (ttl, soa))
    | Txt, (_, txts) -> B (k, (ttl, txts))
    | A, (_, ips) -> B (k, (ttl, ips))
    | Aaaa, (_, ips) -> B (k, (ttl, ips))
    | Srv, (_, srvs) -> B (k, (ttl, srvs))
    | Dnskey, keys -> B (k, keys)
    | Caa, (_, caas) -> B (k, (ttl, caas))
    | Tlsa, (_, tlsas) -> B (k, (ttl, tlsas))
    | Sshfp, (_, sshfps) -> B (k, (ttl, sshfps))

  let pp_b ppf (B (k, v)) = K.pp ppf k v

  let equal_b (B (k, v)) (B (k', v')) = equal_k k v k' v'

  let names : type a. a k -> a -> Domain_name.Set.t = fun k v ->
    match k, v with
    | Cname, (_, alias) -> Domain_name.Set.singleton alias
    | Mx, (_, mxs) ->
      Mx_set.fold (fun { mail_exchange ; _} acc ->
          Domain_name.Set.add mail_exchange acc)
        mxs Domain_name.Set.empty
    | Ns, (_, names) -> names
    | Srv, (_, srvs) ->
      Srv_set.fold (fun x acc -> Domain_name.Set.add x.target acc)
        srvs Domain_name.Set.empty
    | _ -> Domain_name.Set.empty

  let namesb (B (k, v)) = names k v

  let lookup_rr : Udns_enum.rr_typ -> t -> b option = fun rr t ->
    match rr with
    | Udns_enum.MX -> findb Mx t
    | Udns_enum.NS -> findb Ns t
    | Udns_enum.PTR -> findb Ptr t
    | Udns_enum.SOA -> findb Soa t
    | Udns_enum.TXT -> findb Txt t
    | Udns_enum.A -> findb A t
    | Udns_enum.AAAA -> findb Aaaa t
    | Udns_enum.SRV -> findb Srv t
    | Udns_enum.DNSKEY -> findb Dnskey t
    | Udns_enum.CAA -> findb Caa t
    | Udns_enum.TLSA -> findb Tlsa t
    | Udns_enum.SSHFP -> findb Sshfp t
    | _ -> None

  let remove_rr : Udns_enum.rr_typ -> t -> t = fun rr t ->
    match rr with
    | Udns_enum.MX -> remove Mx t
    | Udns_enum.NS -> remove Ns t
    | Udns_enum.PTR -> remove Ptr t
    | Udns_enum.SOA -> remove Soa t
    | Udns_enum.TXT -> remove Txt t
    | Udns_enum.A -> remove A t
    | Udns_enum.AAAA -> remove Aaaa t
    | Udns_enum.SRV -> remove Srv t
    | Udns_enum.DNSKEY -> remove Dnskey t
    | Udns_enum.CAA -> remove Caa t
    | Udns_enum.TLSA -> remove Tlsa t
    | Udns_enum.SSHFP -> remove Sshfp t
    | _ -> t

  let decode names buf off typ =
    let open Rresult.R.Infix in
    guard (Cstruct.len buf - off >= 6) `Partial >>= fun () ->
    let ttl = Cstruct.BE.get_uint32 buf off
    and len = Cstruct.BE.get_uint16 buf (off + 4)
    and rdata_start = off + 6
    in
    guard (Int32.logand ttl 0x8000_0000l = 0l) (`BadTTL ttl) >>= fun () ->
    guard (Cstruct.len buf - rdata_start >= len) `Partial >>= fun () ->
    (match typ with
     | Udns_enum.SOA ->
       Soa.decode names buf ~off:rdata_start ~len >>| fun (soa, names, off) ->
       (B (Soa, (ttl, soa)), names, off)
     | Udns_enum.NS ->
       Ns.decode names buf ~off:rdata_start ~len >>| fun (ns, names, off) ->
       (B (Ns, (ttl, Domain_name.Set.singleton ns)), names, off)
     | Udns_enum.MX ->
       Mx.decode names buf ~off:rdata_start ~len >>| fun (mx, names, off) ->
       (B (Mx, (ttl, Mx_set.singleton mx)), names, off)
     | Udns_enum.CNAME ->
       Cname.decode names buf ~off:rdata_start ~len >>| fun (alias, names, off) ->
       (B (Cname, (ttl, alias)), names, off)
     | Udns_enum.A ->
       A.decode names buf ~off:rdata_start ~len >>| fun (address, names, off) ->
       (B (A, (ttl, Ipv4_set.singleton address)), names, off)
     | Udns_enum.AAAA ->
       Aaaa.decode names buf ~off:rdata_start ~len >>| fun (address, names, off) ->
       (B (Aaaa, (ttl, Ipv6_set.singleton address)), names, off)
     | Udns_enum.PTR ->
       Ptr.decode names buf ~off:rdata_start ~len >>| fun (rev, names, off) ->
       (B (Ptr, (ttl, rev)), names, off)
     | Udns_enum.SRV ->
       Srv.decode names buf ~off:rdata_start ~len >>| fun (srv, names, off) ->
       (B (Srv, (ttl, Srv_set.singleton srv)), names, off)
     | Udns_enum.DNSKEY ->
       Dnskey.decode names buf ~off:rdata_start ~len >>| fun (dnskey, names, off) ->
       (B (Dnskey, (ttl, Dnskey_set.singleton dnskey)), names, off)
     | Udns_enum.CAA ->
       Caa.decode names buf ~off:rdata_start ~len >>| fun (caa, names, off) ->
       (B (Caa, (ttl, Caa_set.singleton caa)), names, off)
     | Udns_enum.TLSA ->
       Tlsa.decode names buf ~off:rdata_start ~len >>| fun (tlsa, names, off) ->
       (B (Tlsa, (ttl, Tlsa_set.singleton tlsa)), names, off)
     | Udns_enum.SSHFP ->
       Sshfp.decode names buf ~off:rdata_start ~len >>| fun (sshfp, names, off) ->
       (B (Sshfp, (ttl, Sshfp_set.singleton sshfp)), names, off)
     | Udns_enum.TXT ->
       Txt.decode names buf ~off:rdata_start ~len >>| fun (txt, names, off) ->
       (B (Txt, (ttl, Txt_set.singleton txt)), names, off)
     | other -> Error (`UnsupportedRRTyp other)) >>= fun (b, names, rdata_end) ->
    guard (len = rdata_end - rdata_start) `LeftOver >>| fun () ->
    (b, names, rdata_end)

  let add_entry dmap name (B (k, v)) =
    let m = match Domain_name.Map.find name dmap with
      | None -> empty
      | Some map -> map
    in
    let m' = update k (combine k v) m in
    Domain_name.Map.add name m' dmap

  let remove_sub map sub =
    (* remove all entries which are in sub from map *)
    (* we don't compare values, just do it based on rrtype! *)
    Domain_name.Map.fold (fun name rrmap map ->
        match Domain_name.Map.find name map with
        | None -> map
        | Some rrs ->
          let rrs' = fold (fun (B (k, _)) map -> remove k map) rrmap rrs in
          Domain_name.Map.add name rrs' map)
      sub map

  let textb ?origin ?default_ttl name (B (key, v)) =
    text ?origin ?default_ttl name key v
end

module Header = struct
  module Flags = struct
    type t = [
      | `Authoritative
      | `Truncation
      | `Recursion_desired
      | `Recursion_available
      | `Authentic_data
      | `Checking_disabled
    ]

    let all = [
      `Authoritative ; `Truncation ; `Recursion_desired ;
      `Recursion_available ; `Authentic_data ; `Checking_disabled
    ]

    let compare a b = match a, b with
      | `Authoritative, `Authoritative -> 0
      | `Authoritative, _ -> 1 | _, `Authoritative -> -1
      | `Truncation, `Truncation -> 0
      | `Truncation, _ -> 1 | _, `Truncation -> -1
      | `Recursion_desired, `Recursion_desired -> 0
      | `Recursion_desired, _ -> 1 | _, `Recursion_desired -> -1
      | `Recursion_available, `Recursion_available -> 0
      | `Recursion_available, _ -> 1 | _, `Recursion_available -> -1
      | `Authentic_data, `Authentic_data -> 0
      | `Authentic_data, _ -> 1 | _, `Authentic_data -> -1
      | `Checking_disabled, `Checking_disabled -> 0
      (* | `Checking_disabled, _ -> 1 | _, `Checking_disabled -> -1 *)

    let pp ppf = function
      | `Authoritative -> Fmt.string ppf "authoritative"
      | `Truncation -> Fmt.string ppf "truncation"
      | `Recursion_desired -> Fmt.string ppf "recursion desired"
      | `Recursion_available -> Fmt.string ppf "recursion available"
      | `Authentic_data -> Fmt.string ppf "authentic data"
      | `Checking_disabled -> Fmt.string ppf "checking disabled"

    let pp_short ppf = function
      | `Authoritative -> Fmt.string ppf "AA"
      | `Truncation -> Fmt.string ppf "TC"
      | `Recursion_desired -> Fmt.string ppf "RD"
      | `Recursion_available -> Fmt.string ppf "RA"
      | `Authentic_data -> Fmt.string ppf "AD"
      | `Checking_disabled -> Fmt.string ppf "CD"

    let bit = function
      | `Authoritative -> 5
      | `Truncation -> 6
      | `Recursion_desired -> 7
      | `Recursion_available -> 8
      | `Authentic_data -> 10
      | `Checking_disabled -> 11

    let number f = 1 lsl (15 - bit f)
  end

  module FS = Set.Make(Flags)

  type t = {
    id : int ;
    query : bool ;
    operation : Udns_enum.opcode ;
    rcode : Udns_enum.rcode ;
    flags : FS.t
  }

  let compare a b =
    andThen (int_compare a.id b.id)
      (andThen (compare a.query b.query)
         (andThen (int_compare (Udns_enum.opcode_to_int a.operation) (Udns_enum.opcode_to_int b.operation))
            (andThen (int_compare (Udns_enum.rcode_to_int a.rcode) (Udns_enum.rcode_to_int b.rcode))
               (FS.compare a.flags b.flags))))

  let len = 12

  (* header is:
     0  QR - 0 for query, 1 for response
     1-4   operation
     5  AA Authoritative Answer [RFC1035]                             \
     6  TC Truncated Response   [RFC1035]                             |
     7  RD Recursion Desired    [RFC1035]                             |
     8  RA Recursion Available  [RFC1035]                             |-> flags
     9     Reserved                                                   |
     10 AD Authentic Data       [RFC4035][RFC6840][RFC Errata 4924]   |
     11 CD Checking Disabled    [RFC4035][RFC6840][RFC Errata 4927]   /
     12-15 rcode *)

  let decode_flags hdr =
    List.fold_left (fun flags flag ->
        if Flags.number flag land hdr > 0 then
          FS.add flag flags
        else
          flags)
      FS.empty Flags.all

  let decode buf =
    let open Rresult.R.Infix in
    (* we only access the first 4 bytes, but anything <12 is a bad DNS frame *)
    guard (Cstruct.len buf >= len) `Partial >>= fun () ->
    let hdr = Cstruct.BE.get_uint16 buf 2 in
    let op = (hdr land 0x7800) lsr 11
    and rc = hdr land 0x000F
    in
    match Udns_enum.int_to_opcode op, Udns_enum.int_to_rcode rc with
    | None, _ -> Error (`BadOpcode op)
    | _, None -> Error (`BadRcode rc)
    | Some operation, Some rcode ->
      let id = Cstruct.BE.get_uint16 buf 0
      and query = hdr lsr 15 = 0
      and flags = decode_flags hdr
      in
      Ok { id ; query ; operation ; rcode ; flags }

  let encode_flags hdr =
    FS.fold (fun f acc -> acc + Flags.number f) hdr.flags 0

  let encode buf hdr =
    let query = if hdr.query then 0x0000 else 0x8000 in
    let flags = encode_flags hdr in
    let op = (Udns_enum.opcode_to_int hdr.operation) lsl 11 in
    let rcode = (Udns_enum.rcode_to_int hdr.rcode) land 0x000F in
    let header = query lor flags lor op lor rcode in
    Cstruct.BE.set_uint16 buf 0 hdr.id ;
    Cstruct.BE.set_uint16 buf 2 header

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf hdr =
    Fmt.pf ppf "%04X (%s) operation %a rcode @[%a@] flags: @[%a@]"
      hdr.id (if hdr.query then "query" else "response")
      Udns_enum.pp_opcode hdr.operation
      Udns_enum.pp_rcode hdr.rcode
      Fmt.(list ~sep:(unit ", ") Flags.pp) (FS.elements hdr.flags)
  (*BISECT-IGNORE-END*)
end

let decode_ntc names buf off =
  let open Rresult.R.Infix in
  Name.decode ~hostname:false names buf ~off >>= fun (name, names, off) ->
  guard (Cstruct.len buf - off >= 4) `Partial >>= fun () ->
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

module Question = struct
  type t = Domain_name.t * Udns_enum.rr_typ

  (*BISECT-IGNORE-BEGIN*)
  let pp ppf (name, typ) =
    Fmt.pf ppf "%a %a?" Domain_name.pp name Udns_enum.pp_rr_typ typ
  (*BISECT-IGNORE-END*)

  let compare (name, typ) (name', typ') =
    andThen (Domain_name.compare name name')
      (int_compare (Udns_enum.rr_typ_to_int typ)
         (Udns_enum.rr_typ_to_int typ'))

  let decode names buf off =
    let open Rresult.R.Infix in
    decode_ntc names buf off >>= fun ((name, typ, c), names, off) ->
    match Udns_enum.int_to_clas c with
    | None -> Error (`BadClass c)
    | Some Udns_enum.IN -> Ok ((name, typ), names, off)
    | Some x -> Error (`UnsupportedClass x)

  let encode offs buf off (name, typ) =
    encode_ntc offs buf off (name, typ, Udns_enum.clas_to_int Udns_enum.IN)
end

type query = {
  question : Question.t ;
  answer : Map.t Domain_name.Map.t ;
  authority : Map.t Domain_name.Map.t ;
  additional : Map.t Domain_name.Map.t ;
}

let query question =
  let empty = Domain_name.Map.empty in
  { question ; answer = empty ; authority = empty ; additional = empty }

let equal_map a b =
  Domain_name.Map.equal (Map.equal Map.equal_b) a b

(*BISECT-IGNORE-BEGIN*)
let pp_map ppf map =
  Fmt.(list ~sep:(unit ";@ ") (pair ~sep:(unit " ") Domain_name.pp Map.pp))
    ppf (Domain_name.Map.bindings map)

let pp_query ppf t =
  Fmt.pf ppf "question %a@ answer %a@ authority %a@ additional %a"
    Question.pp t.question
    pp_map t.answer pp_map t.authority pp_map t.additional
(*BISECT-IGNORE-END*)

let decode_rr names buf off =
  let open Rresult.R.Infix in
  decode_ntc names buf off >>= fun ((name, typ, clas), names, off) ->
  guard (clas = Udns_enum.clas_to_int Udns_enum.IN) (`BadClass clas) >>= fun () ->
  Map.decode names buf off typ >>| fun (b, names, off) ->
  (name, b, names, off)

let rec decode_n names buf off acc = function
  | 0 -> Ok (`Full (names, off, acc))
  | n ->
    match decode_rr names buf off with
    | Ok (name, b, names, off') ->
      let acc' = Map.add_entry acc name b in
      decode_n names buf off' acc' (pred n)
    | Error `Partial -> Ok (`Partial acc)
    | Error e -> Error e

let decode_additional ~tsig edns names buf off =
  let open Rresult.R.Infix in
  decode_ntc names buf off >>= fun ((name, typ, clas), names, off') ->
  match typ with
  | Udns_enum.OPT when edns = None ->
    (* OPT is special and needs class! (also, name is guarded to be .) *)
    Edns.decode buf ~off >>| fun (edns, off') ->
    `Edns (edns, names, off')
  | Udns_enum.TSIG when tsig ->
    guard (clas = Udns_enum.(clas_to_int ANY_CLASS)) (`BadClass clas) >>= fun () ->
    Tsig.decode names buf ~off:off' >>| fun (tsig, names, off') ->
    `Tsig ((name, tsig, off), names, off')
  | _ ->
    guard (clas = Udns_enum.(clas_to_int IN)) (`BadClass clas) >>= fun () ->
    Map.decode names buf off' typ >>| fun (b, names, off') ->
    `Binding (name, b, names, off')

let rec decode_n_additional names buf off map edns tsig = function
  | 0 -> Ok (`Full (off, map, edns, tsig))
  | n ->
    match decode_additional ~tsig:(n = 1) edns names buf off with
    | Error `Partial -> Ok (`Partial (map, edns, tsig))
    | Error e -> Error e
    | Ok (`Edns (edns, names, off')) ->
      decode_n_additional names buf off' map (Some edns) tsig (pred n)
    | Ok (`Tsig (tsig, names, off')) ->
      decode_n_additional names buf off' map edns (Some tsig) (pred n)
    | Ok (`Binding (name, b, names, off')) ->
      let map' = Map.add_entry map name b in
      decode_n_additional names buf off' map' edns tsig (pred n)

let decode_query buf truncated =
  let open Rresult.R.Infix in
  guard (Cstruct.len buf >= 12) `Partial >>= fun () ->
  let qcount = Cstruct.BE.get_uint16 buf 4
  and ancount = Cstruct.BE.get_uint16 buf 6
  and aucount = Cstruct.BE.get_uint16 buf 8
  and adcount = Cstruct.BE.get_uint16 buf 10
  in
  guard (qcount = 1) `None_or_multiple_questions >>= fun () ->
  Question.decode Name.IntMap.empty buf Header.len >>= fun (question, names, off) ->
  let empty = Domain_name.Map.empty in
  let query = query question in
  decode_n names buf off empty ancount >>= function
  | `Partial answer ->
    guard truncated `Partial >>| fun () -> { query with answer }, None, None
  | `Full (names, off, answer) ->
    let query = { query with answer } in
    decode_n names buf off empty aucount >>= function
    | `Partial authority ->
      guard truncated `Partial >>| fun () -> { query with authority }, None, None
    | `Full (names, off, authority) ->
      let query = { query with authority } in
      decode_n_additional names buf off empty None None adcount >>= function
      | `Partial (additional, edns, tsig) ->
        guard truncated `Partial >>| fun () ->
        { query with additional }, edns, tsig
      | `Full (off, additional, edns, tsig) ->
        (* if there's edns, interpret extended rcode *)
        (* if there's tsig, maybe interpret extended rcode *)
        (if Cstruct.len buf > off then
           let n = Cstruct.len buf - off in
           Logs.warn (fun m -> m "received %d extra bytes %a"
                         n Cstruct.hexdump_pp (Cstruct.sub buf off n))) ;
        Ok ({ query with additional }, edns, tsig)

let decode buf =
  let ext_rcode hdr = function
    | Some e when e.Edns.extended_rcode > 0 ->
      begin
        let rcode =
          Udns_enum.rcode_to_int hdr.Header.rcode + e.extended_rcode lsl 4
        in
        match Udns_enum.int_to_rcode rcode with
        | None -> Error (`BadRcode rcode)
        | Some rcode -> Ok ({ hdr with rcode })
      end
    | _ -> Ok hdr
  in
  let open Rresult.R.Infix in
  Header.decode buf >>= fun hdr ->
  let truncated = Header.FS.mem `Truncation hdr.flags in
  match hdr.Header.operation with
  | Udns_enum.Query ->
    decode_query buf truncated >>= fun (q, edns, tsig) ->
    ext_rcode hdr edns >>| fun hdr ->
    hdr, `Query q, edns, tsig
  | Udns_enum.Notify ->
    decode_query buf truncated >>= fun (n, edns, tsig) ->
    ext_rcode hdr edns >>| fun hdr ->
    hdr, `Notify n, edns, tsig
  | Udns_enum.Update -> assert false
  | x -> Error (`UnsupportedOpcode x)

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
    | Some opts -> Some ({ opts with Edns.payload_size = max })
  in
  maximum, edns

let encode_answer (qname, qtyp) map offs buf off =
  Logs.debug (fun m -> m "trying to encode the answer, following question %a %a"
                 Question.pp (qname, qtyp) pp_map map) ;
  (* A foo.com? foo.com CNAME bar.com ; bar.com A 127.0.0.1 *)
  let rec encode_one offs off count name =
    Logs.debug (fun m -> m "encoding %d %a" count Domain_name.pp name) ;
    match Domain_name.Map.find name map with
    | None ->
      Logs.warn (fun m -> m "nothing found") ;
      (offs, off), count
    | Some rrmap ->
      Logs.warn (fun m -> m "found an rrmap %a" Map.pp rrmap) ;
      let (offs, off), count, alias =
        Map.fold (fun (Map.B (k, v)) ((offs, off), count, alias) ->
            let alias' = match k, v with
              | Cname, (_, alias) -> Some alias
              | _ -> alias
            in
            let r, amount = Map.encode name k v offs buf off in
            (r, amount + count, alias'))
          rrmap ((offs, off), count, None)
      in
      match alias with
      | None ->
        Logs.info (fun m -> m "returning %d" count) ;
        (offs, off), count
      | Some n ->
        Logs.info (fun m -> m "continuing with %a" Domain_name.pp n) ;
        encode_one offs off count n
  in
  encode_one offs off 0 qname

let encode_map map offs buf off =
  Domain_name.Map.fold (fun name rrmap acc ->
      Map.fold (fun (Map.B (k, v)) ((offs, off), count) ->
          let r, amount = Map.encode name k v offs buf off in
          (r, amount + count))
        rrmap acc)
    map ((offs, off), 0)

let encode_query buf data =
  let offs, off = Question.encode Domain_name.Map.empty buf Header.len data.question in
  Cstruct.BE.set_uint16 buf 4 1 ;
  (* if AXFR, SOA needs to be first and last element! *)
  (* TODO the latter needs to be verified in decode as well -- esp. since AXFR may span over multiple frames *)
  let (offs, off), ancount = encode_answer data.question data.answer offs buf off in
  Cstruct.BE.set_uint16 buf 6 ancount ;
  let (offs, off), aucount = encode_map data.authority offs buf off in
  Cstruct.BE.set_uint16 buf 8 aucount ;
  let (_offs, off), adcount = encode_map data.additional offs buf off in
  Cstruct.BE.set_uint16 buf 10 adcount ;
  off

let encode_v buf = function
  | `Query q -> encode_query buf q
  | `Notify n -> encode_query buf n

let encode_edns hdr edns buf off = match edns with
  | None -> off
  | Some edns ->
    let extended_rcode = (Udns_enum.rcode_to_int hdr.Header.rcode) lsr 4 in
    let adcount = Cstruct.BE.get_uint16 buf 10 in
    let off = Edns.encode { edns with Edns.extended_rcode } buf off in
    Cstruct.BE.set_uint16 buf 10 (adcount + 1) ;
    off

let encode ?max_size ?edns protocol hdr v =
  let max, edns = size_edns max_size edns protocol hdr.Header.query in
  let try_encoding buf =
    let off, trunc =
      try
        Header.encode buf hdr ;
        let off = encode_v buf v in
        (* TODO we used to drop all other additionals if rcode <> 0 *)
        (* TODO if edns embedding would truncate, we used to drop all other additionals and only encode EDNS *)
        (* TODO if additional would truncate, drop them (do not set truncation) *)
        encode_edns hdr edns buf off, false
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
  if not header.Header.query then
    let header = { header with rcode }
    and question = match v with
      (*      | `Update u -> [ u.zone ] *)
      | `Query q | `Notify q -> q.question
    in
    let errbuf = Cstruct.create max_reply_udp in
    let query = query question in
    Header.encode errbuf header ;
    let encode query =
      let off = encode_query errbuf query in
      encode_edns header (Some (Edns.edns ())) errbuf off
    in
    let off = encode query in
    Some (Cstruct.sub errbuf 0 off, max_reply_udp)
  else
    None

type v = [
  | `Query of query
  | `Notify of query
]

(*BISECT-IGNORE-BEGIN*)
let pp_v ppf = function
  | `Query q -> pp_query ppf q
  (*  | `Update u -> pp_update ppf u *)
  | `Notify n -> pp_query ppf n

let pp_tsig ppf (name, tsig, off) =
  Fmt.pf ppf "tsig %a %a %d" Domain_name.pp name Tsig.pp tsig off

let pp ppf (header, v, edns, tsig) =
  Fmt.pf ppf "header %a@ %a@ edns %a@ tsig %a@ "
    Header.pp header pp_v v
    Fmt.(option ~none:(unit "no") Edns.pp) edns
    Fmt.(option ~none:(unit "no") pp_tsig) tsig
(*BISECT-IGNORE-END*)

type tsig_verify = ?mac:Cstruct.t -> Ptime.t -> v -> Header.t ->
  Domain_name.t -> key:Dnskey.t option -> Tsig.t -> Cstruct.t ->
  (Tsig.t * Cstruct.t * Dnskey.t, Cstruct.t option) result

type tsig_sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> Tsig.t ->
  key:Dnskey.t -> Cstruct.t -> (Cstruct.t * Cstruct.t) option
