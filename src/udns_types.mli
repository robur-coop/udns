(* (c) 2019 Hannes Mehnert, all rights reserved *)

type proto = [ `Tcp | `Udp ]
(** The type of support protocols (influence maximum packet size, encoding,
   etc.). *)

type question = {
  q_name : Domain_name.t ;
  q_type : Udns_enum.rr_typ ;
}
(** The type of DNS questions: a domain-name and a resource record type. The
   class is always IN. *)

val pp_question : question Fmt.t
(** [pp_question ppf question] pretty-prints the [question] on [ppf]. *)

type soa = {
  nameserver : Domain_name.t ;
  hostmaster : Domain_name.t ;
  serial : int32 ;
  refresh : int32 ;
  retry : int32 ;
  expiry : int32 ;
  minimum : int32 ;
}
(** The type of a start of authority (SOA) entry. *)

val pp_soa : soa Fmt.t
(** [pp_soa ppf soa] pretty-prints the [soa] on [ppf]. *)

val compare_soa : soa -> soa -> int
(** [compare_soa soa soa'] compares the serial, nameserver, hostmaster, refresh,
    retry, expiry, and minimum of two SOA records. *)

type mx = {
  preference : int ;
  mail_exchange : Domain_name.t ;
}
(** The type of Mail Exchanges. *)

val pp_mx : mx Fmt.t
(** [pp_mx ppf mx] pretty-printf the [mx] on [ppf]. *)

val compare_mx : mx -> mx -> int
(** [compare_mx mx mx'] compares the preference and mail exchange name of the
    two MX records. *)

type dnskey = {
  flags : int ; (* uint16 *)
  key_algorithm :  Udns_enum.dnskey ; (* u_int8_t *)
  key : Cstruct.t ;
}
(** The type of dnskey resource records. *)

val dnskey_of_string : string -> dnskey option
(** [dnskey_of_string str] parses [str] from [flags:]algorithm:base64-key. *)

val name_dnskey_of_string : string -> (Domain_name.t * dnskey, [ `Msg of string ]) result
(** [name_dnskey_of_string str] attempts to parse a domain_name, colon (':'),
    and a dnskey (optional flags, algorithm, base64-key). *)

val pp_dnskey : dnskey Fmt.t
(** [pp_dnskey ppf dnskey] pretty-prints the [dnskey] on [ppf]. *)

val compare_dnskey : dnskey -> dnskey -> int
(** [compare_dnskey key key'] compares the keys. *)

type srv = {
  priority : int ;
  weight : int ;
  port : int ;
  target : Domain_name.t
}
(** The type for service resource records. *)

val pp_srv : srv Fmt.t
(** [pp_srv ppf srv] pretty-prints [srv] on [ppf]. *)

val compare_srv : srv -> srv -> int
(** [compare_srv srv srv'] compares the service records [srv] and [srv']. *)

type caa = {
  critical : bool ;
  tag : string ;
  value : string list ;
}
(** The type of CAA resource records. *)

val compare_caa : caa -> caa -> int
(** [compare_caa caa caa'] compare the CAA records [caa] and [caa']. *)

val pp_caa : caa Fmt.t
(** [pp_caa ppf caa] pretty-prints the [caa] on [ppf]. *)

type tlsa = {
  tlsa_cert_usage : Udns_enum.tlsa_cert_usage ;
  tlsa_selector : Udns_enum.tlsa_selector ;
  tlsa_matching_type : Udns_enum.tlsa_matching_type ;
  tlsa_data : Cstruct.t ;
}
(** The type of TLSA resource records. *)

val compare_tlsa : tlsa -> tlsa -> int
(** [compare_tlsa tlsa tlsa'] compares [tlsa] with [tlsa']. *)

val pp_tlsa : tlsa Fmt.t
(** [pp_tlsa ppf tlsa] pretty-prints [tlsa] on [ppf]. *)

type sshfp = {
  sshfp_algorithm : Udns_enum.sshfp_algorithm ;
  sshfp_type : Udns_enum.sshfp_type ;
  sshfp_fingerprint : Cstruct.t ;
}
(** The type of SSHFP resource records. *)

val compare_sshfp : sshfp -> sshfp -> int
(** [compare_sshfp sshfp sshfp'] compares [sshfp] with [sshfp']. *)

val pp_sshfp : sshfp Fmt.t
(** [pp_sshfp ppf sshfp] pretty-prints [sshfp] on [ppf]. *)
