(* (c) 2019 Hannes Mehnert, all rights reserved *)

type proto = [ `Tcp | `Udp ]

type question = {
  q_name : Domain_name.t ;
  q_type : Udns_enum.rr_typ ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_question ppf q =
  Fmt.pf ppf "%a %a?" Domain_name.pp q.q_name Udns_enum.pp_rr_typ q.q_type
(*BISECT-IGNORE-END*)

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

let andThen v f = match v with 0 -> f | x -> x

let int_compare (a : int) (b : int) = compare a b
let int32_compare (a : int32) (b : int32) = Int32.compare a b

let compare_soa soa soa' =
  andThen (int32_compare soa.serial soa.serial)
    (andThen (Domain_name.compare soa.nameserver soa'.nameserver)
       (andThen (Domain_name.compare soa.hostmaster soa'.hostmaster)
          (andThen (int32_compare soa.refresh soa'.refresh)
             (andThen (int32_compare soa.retry soa'.retry)
                (andThen (int32_compare soa.expiry soa'.expiry)
                   (int32_compare soa.minimum soa'.minimum))))))

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

type dnskey = {
  flags : int ; (* uint16 *)
  key_algorithm :  Udns_enum.dnskey ; (* u_int8_t *)
  key : Cstruct.t ;
}

let compare_dnskey a b =
  andThen (compare a.key_algorithm b.key_algorithm)
    (Cstruct.compare a.key b.key)


(*BISECT-IGNORE-BEGIN*)
let pp_dnskey ppf t =
  Fmt.pf ppf
    "DNSKEY flags %u algo %a key %a"
    t.flags Udns_enum.pp_dnskey t.key_algorithm
    Cstruct.hexdump_pp t.key
(*BISECT-IGNORE-END*)

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


type srv = {
  priority : int ;
  weight : int ;
  port : int ;
  target : Domain_name.t
}

let compare_srv a b =
  andThen (compare a.priority b.priority)
    (andThen (compare a.weight b.weight)
       (andThen (compare a.port b.port)
          (Domain_name.compare a.target b.target)))

(*BISECT-IGNORE-BEGIN*)
let pp_srv ppf t =
  Fmt.pf ppf
    "SRV priority %d weight %d port %d target %a"
    t.priority t.weight t.port Domain_name.pp t.target
(*BISECT-IGNORE-END*)

type caa = {
  critical : bool ;
  tag : string ;
  value : string list ;
}

let compare_caa a b =
  andThen (compare a.critical b.critical)
    (andThen (String.compare a.tag b.tag)
       (List.fold_left2 (fun r a b -> match r with
            | 0 -> String.compare a b
            | x -> x)
           0 a.value b.value))

(*BISECT-IGNORE-BEGIN*)
let pp_caa ppf t =
  Fmt.pf ppf
    "CAA critical %b tag %s value %a"
    t.critical t.tag Fmt.(list ~sep:(unit "; ") string) t.value
(*BISECT-IGNORE-END*)

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


type sshfp = {
  sshfp_algorithm : Udns_enum.sshfp_algorithm ;
  sshfp_type : Udns_enum.sshfp_type ;
  sshfp_fingerprint : Cstruct.t ;
}

let compare_sshfp s1 s2 =
  andThen (compare s1.sshfp_algorithm s2.sshfp_algorithm)
    (andThen (compare s1.sshfp_type s2.sshfp_type)
       (Cstruct.compare s1.sshfp_fingerprint s2.sshfp_fingerprint))

(*BISECT-IGNORE-BEGIN*)
let pp_sshfp ppf sshfp =
  Fmt.pf ppf "SSHFP %a %a %a"
    Udns_enum.pp_sshfp_algorithm sshfp.sshfp_algorithm
    Udns_enum.pp_sshfp_type sshfp.sshfp_type
    Cstruct.hexdump_pp sshfp.sshfp_fingerprint
(*BISECT-IGNORE-END*)
