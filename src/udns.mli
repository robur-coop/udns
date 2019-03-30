(* (c) 2017-2019 Hannes Mehnert, all rights reserved *)
(** µDNS - an opinionated Domain Name System (DNS) library

    The Domain Name System is a hierarchical and decentralized naming system
   used on the Internet. It associates domain names with nearly arbitrary
   information. Best known is the translation of easily memoizable domain names
   to numerical IP addresses, which are used by computers for establishing
   communication channels - so called {{!A}address} records. DNS has been
   deployed since 1985 on the Internet. It is a widely deployed, fault-tolerant,
   distributed key-value store with built-in caching mechanisms. The keys
   are domain names and record type, the values are record sets. Each record
   set has a time-to-live associated with it: the maximum time this entry may
   be cached.

    A set of 13 authoritative name servers form the root zone which delegate
   authority for subdomains to registrars (using country codes, etc.), which
   delegate domains to individuals who host their Internet presence there.

    The delegation mechanism utilizes the DNS protocol itself, using
   {{!Ns}name server} records, and {{!Soa}start of authority} records. The
   globally federated eMail system uses {{!Mx}mail exchange} records.

    Each Internet domain has at least two authoritative name servers registered
   to enable fault tolerance. To keep these synchronised, a zone transfer
   mechanism is part of DNS. In-protocol DNS extension mechanisms include
   dynamic updates, authentication, and notifications, which allow arbitrary
   synchronized, authenticated modifications.

    From a client perspective, the C library functions [gethostbyname] or
   [getaddrinfo] are mainly used, which receive a string (and a record type)
   and return a reply. A client requests a caching recursive resolver hosted
   close to the client - e.g. at their ISP, and awaits an answer. The recursive
   resolver iterates over the domain name parts, and requests the registered
   authoritative name servers, until the name server responsible for the
   requested domain name is found.

    The core µDNS library includes type definitions of supported record types,
  decoding and encoding thereof to the binary protocol used on the Internet,
  also serialising and parsing of the standardized text form. The record types
  and their values are defined by the {{!Rr_map.k}key} type, which has for
  each record type a specific value type, using a generalized algebraic data
  type -- i.e. an address record may only contain a time-to-live and a set of
  IPv4 addresses. This is used to construct a map data structure.

    Different µDNS libraries implement various DNS components:
    {ul
    {- {!Udns_tsig} implements TSIG authentication}
    {- {!Udns_server} implements the authoritative server logic (both primary and secondary)}
    {- {!Udns_client} implements a client API}
    {- {!Udns_zonesfile} implements the zone file parser}
    {- {!Udns_resolver} implements the resolver logic}}

    {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}} *)

type proto = [ `Tcp | `Udp ]

(* start of authority *)
module Soa : sig
  type t = {
    nameserver : Domain_name.t ;
    hostmaster : Domain_name.t ;
    serial : int32 ;
    refresh : int32 ;
    retry : int32 ;
    expiry : int32 ;
    minimum : int32 ;
  }

  val pp : t Fmt.t

  val compare : t -> t -> int
  val newer : old:t -> t -> bool
end

(* name server *)
module Ns : sig
  type t = Domain_name.t

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* mail exchange *)
module Mx : sig
  type t = {
    preference : int ;
    mail_exchange : Domain_name.t ;
  }

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* canonical name *)
module Cname : sig
  type t = Domain_name.t

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* address record *)
module A : sig
  type t = Ipaddr.V4.t

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* quad-a record *)
module Aaaa : sig
  type t = Ipaddr.V6.t

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* domain name pointer - reverse entries *)
module Ptr : sig
  type t = Domain_name.t

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* service record *)
module Srv : sig
  type t = {
    priority : int ;
    weight : int ;
    port : int ;
    target : Domain_name.t
  }

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* DNS key *)
module Dnskey : sig
  type t = {
    flags : int ; (* uint16 *)
    algorithm :  Udns_enum.dnskey ; (* u_int8_t *)
    key : Cstruct.t ;
  }

  val pp : t Fmt.t

  val compare : t -> t -> int

  val of_string : string -> t option

  val name_key_of_string : string -> (Domain_name.t * t, [> `Msg of string ]) result
end

(* certificate authority authorization *)
module Caa : sig
  type t = {
    critical : bool ;
    tag : string ;
    value : string list ;
  }

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* transport layer security A *)
module Tlsa : sig
  type t = {
    tlsa_cert_usage : Udns_enum.tlsa_cert_usage ;
    tlsa_selector : Udns_enum.tlsa_selector ;
    tlsa_matching_type : Udns_enum.tlsa_matching_type ;
    tlsa_data : Cstruct.t ;
  }


  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* secure shell fingerprint *)
module Sshfp : sig
  type t = {
    sshfp_algorithm : Udns_enum.sshfp_algorithm ;
    sshfp_type : Udns_enum.sshfp_type ;
    sshfp_fingerprint : Cstruct.t ;
  }

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(* Text record *)
module Txt : sig
  type t = string

  val pp : t Fmt.t

  val compare : t -> t -> int
end

module Tsig : sig
  type algorithm =
    | SHA1
    | SHA224
    | SHA256
    | SHA384
    | SHA512

  type t = private {
    algorithm : algorithm ;
    signed : Ptime.t ;
    fudge : Ptime.Span.t ;
    mac : Cstruct.t ;
    original_id : int ; (* again 16 bit *)
    error : Udns_enum.rcode ;
    other : Ptime.t option
  }

  val algorithm_to_name : algorithm -> Domain_name.t

  val algorithm_of_name : Domain_name.t -> algorithm option

  val pp_algorithm : algorithm Fmt.t

  val tsig : algorithm:algorithm -> signed:Ptime.t ->
    ?fudge:Ptime.span -> ?mac:Cstruct.t -> ?original_id:int ->
    ?error:Udns_enum.rcode -> ?other:Ptime.t -> unit -> t option

  val with_mac : t -> Cstruct.t -> t

  val with_error : t -> Udns_enum.rcode -> t

  val with_signed : t -> Ptime.t -> t option

  val with_other : t -> Ptime.t option -> t option

  val pp : t Fmt.t

  val encode_raw : Domain_name.t -> t -> Cstruct.t

  val encode_full : Domain_name.t -> t -> Cstruct.t

  val dnskey_to_tsig_algo : Dnskey.t -> algorithm option

  val valid_time : Ptime.t -> t -> bool
end

module Edns : sig
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

  val create : ?extended_rcode:int -> ?version:int -> ?dnssec_ok:bool ->
    ?payload_size:int -> ?extensions:extension list -> unit -> t

  (* once we handle cookies, dnssec, or other extensions, need to adjust *)
  val reply : t option -> int option * t option

  val compare : t -> t -> int

  val pp : t Fmt.t

  val allocate_and_encode : t -> Cstruct.t

end

(* resource record map *)
module Rr_map : sig
(** A map whose key are DNS resource record types and their values are the time
   to live and the resource record. This module uses a GADT to express the
   binding between record type and resource record. *)

  module Mx_set : Set.S with type elt = Mx.t
  module Txt_set : Set.S with type elt = Txt.t
  module Ipv4_set : Set.S with type elt = A.t
  module Ipv6_set : Set.S with type elt = Aaaa.t
  module Srv_set : Set.S with type elt = Srv.t
  module Dnskey_set : Set.S with type elt = Dnskey.t
  module Caa_set : Set.S with type elt = Caa.t
  module Tlsa_set : Set.S with type elt = Tlsa.t
  module Sshfp_set : Set.S with type elt = Sshfp.t

  type _ k =
    | Soa : Soa.t k
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

  val equal_k : 'a k -> 'a -> 'b k -> 'b -> bool

  include Gmap.S with type 'a key = 'a k

  (** {2 Conversion functions} *)

  val to_rr_typ : b -> Udns_enum.rr_typ
  (** [to_rr_typ b] is the resource record typ of [b]. *)

  val k_to_rr_typ : 'a k -> Udns_enum.rr_typ
  (** [k_to_rr_typ k] is the resource record typ of [k]. *)

  val names : 'a k -> 'a -> Domain_name.Set.t
  (** [names k v] are the referenced domain names in the given binding. *)

  val names_b : b -> Domain_name.Set.t
  (** [names_b binding] are the referenced domain names in the given binding. *)

  val lookup_rr : Udns_enum.rr_typ -> t -> b option
  (** [lookup_rr typ t] looks up the [typ] in [t]. *)

  val remove_rr : Udns_enum.rr_typ -> t -> t
  (** [remove_rr typ t] removes the [typ] in [t]. *)

  val pp_b : b Fmt.t
  (** [pp_b ppf b] pretty-prints the binding [b]. *)

  val equal_b : b -> b -> bool
  (** [equal_b b b'] is [true] if the bindings are equal. *)

  val text_b : ?origin:Domain_name.t -> ?default_ttl:int32 -> Domain_name.t -> b -> string
  (** [text ~origin ~default_ttl domain-name binding] is the zone file format of [binding] using
      [domain-name]. *)

  val subtract_k : 'a k -> 'a -> 'a -> 'a option

  val combine_k : 'a k -> 'a -> 'a -> 'a
  val combine_opt : 'a k -> 'a -> 'a option -> 'a option

  val text : ?origin:Domain_name.t -> ?default_ttl:int32 -> Domain_name.t -> 'a k -> 'a -> string

  val get_ttl : b -> int32
  val with_ttl : b -> int32 -> b

end

module Name_rr_map : sig

  type t = Rr_map.t Domain_name.Map.t

  val empty : t
  val equal : t -> t -> bool

  val pp : t Fmt.t

  val add : Domain_name.t -> Rr_map.b -> t -> t

  val find : Domain_name.t -> 'a Rr_map.k -> t -> 'a option

  val remove_sub : t -> t -> t
end

module Packet : sig

  type err = [
    | `Invalid of int * string * int
    | `Invalids of int * string * string
    | `Leftover of int * string
    | `Malformed of int * string
    | `Partial
    | `Bad_edns_version of int
  ]

  val pp_err : err Fmt.t

  module Header : sig
    module Flags : sig
      type t = [
        | `Authoritative
        | `Truncation
        | `Recursion_desired
        | `Recursion_available
        | `Authentic_data
        | `Checking_disabled
      ]

      val compare : t -> t -> int
      val pp : t Fmt.t
      val pp_short : t Fmt.t
    end

    module FS : Set.S with type elt = Flags.t

    type t = {
      id : int ;
      query : bool ;
      operation : Udns_enum.opcode ;
      rcode : Udns_enum.rcode ;
      flags : FS.t
    }

    val compare : t -> t -> int

    val pp : t Fmt.t

    val decode : Cstruct.t -> (t, err) result

    val encode : Cstruct.t -> t -> unit
  end

  module Name : sig
    module Int_map : Map.S with type key = int

    type offset_name_map = (Domain_name.t * int) Int_map.t

    type name_offset_map = int Domain_name.Map.t

    val decode : ?hostname:bool -> offset_name_map -> Cstruct.t -> off:int ->
      (Domain_name.t * offset_name_map * int, err) result

    val encode : ?compress:bool -> Domain_name.t -> name_offset_map -> Cstruct.t ->
      int -> name_offset_map * int
  end

  module Question : sig
    type t = Domain_name.t * Udns_enum.rr_typ

    val pp : t Fmt.t
    val compare : t -> t -> int

    val decode : ?names:Name.offset_name_map -> ?off:int -> Cstruct.t ->
      (t * Name.offset_name_map * int, err) result
  end

  module Query : sig
    type t = Name_rr_map.t * Name_rr_map.t
    val empty : t
    val pp : t Fmt.t
    val equal : t -> t -> bool
  end

  module Axfr : sig
    type t = (Soa.t * Name_rr_map.t) option
    val empty : t
    val pp : t Fmt.t
    val equal : t -> t -> bool
  end

  module Update : sig
    type prereq =
      | Exists of Udns_enum.rr_typ
      | Exists_data of Rr_map.b
      | Not_exists of Udns_enum.rr_typ
      | Name_inuse
      | Not_name_inuse
    val pp_prereq : prereq Fmt.t
    val equal_prereq : prereq -> prereq -> bool

    type update =
      | Remove of Udns_enum.rr_typ
      | Remove_all
      | Remove_single of Rr_map.b
      | Add of Rr_map.b
    val pp_update : update Fmt.t
    val equal_update : update -> update -> bool

    type t = prereq list Domain_name.Map.t * update list Domain_name.Map.t
    val empty : t
    val pp : t Fmt.t
    val equal : t -> t -> bool
  end

  type t = [
    | `Query of Query.t
    | `Notify of Query.t
    | `Axfr of Axfr.t
    | `Update of Update.t
  ]

  val pp : t Fmt.t

  val equal : t -> t -> bool

  type res = Header.t * Question.t * t * Name_rr_map.t * Edns.t option * (Domain_name.t * Tsig.t * int) option

  val pp_res : res Fmt.t

  val decode : Cstruct.t -> (res, err) result

  val is_reply : ?not_error:bool -> ?not_truncated:bool -> Header.t -> Question.t -> res -> bool
  (** [is_reply ~not_error ~not_truncated header question response] validates the reply, and returns either
      [true] or [false] and logs the failure. The following basic checks are
      performed:
      {ul
      {- Is the header identifier of [header] and [response] equal?}
      {- Is [res] a reply (first bit set)?}
      {- Is the operation of [header] and [res] the same?}
      {- If [not_error] is [true] (the default): is the rcode of [header] NoError?}
      {- If [not_truncated] is [true] (the default): is the [truncation] flag not set?}
      {- Is the [question] and the question of [response] equal?}} *)

  val size_edns : int option -> Edns.t option -> proto -> bool -> int * Edns.t option

  val encode : ?max_size:int -> ?additional:Name_rr_map.t -> ?edns:Edns.t ->
    proto -> Header.t -> Question.t -> t -> Cstruct.t * int

  val error : Header.t -> Question.t -> Udns_enum.rcode -> (Cstruct.t * int) option
end

module Tsig_op : sig
  type verify = ?mac:Cstruct.t -> Ptime.t -> Packet.Header.t -> Packet.Question.t ->
    Domain_name.t -> key:Dnskey.t option -> Tsig.t -> Cstruct.t ->
    (Tsig.t * Cstruct.t * Dnskey.t, Cstruct.t option) result

  type sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> Tsig.t ->
    key:Dnskey.t -> Cstruct.t -> (Cstruct.t * Cstruct.t) option
end
