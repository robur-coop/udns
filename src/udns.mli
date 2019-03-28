(* (c) 2017-2019 Hannes Mehnert, all rights reserved *)

type proto = [ `Tcp | `Udp ]

module Name : sig
  module IntMap : Map.S with type key = int

  type err =
    [ `Partial
    | `BadOffset of int
    | `BadTag of int
    | `BadContent of string
    | `TooLong ]

  val pp_err : err Fmt.t

  type offset_name_map = (Domain_name.t * int) IntMap.t

  type name_offset_map = int Domain_name.Map.t

  val decode : ?hostname:bool -> offset_name_map -> Cstruct.t -> off:int ->
    (Domain_name.t * offset_name_map * int, err) result

  val encode : ?compress:bool -> Domain_name.t -> name_offset_map -> Cstruct.t ->
    int -> name_offset_map * int
end

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
  type t = string list

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

  type t = {
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

  val edns : ?extended_rcode:int -> ?version:int -> ?dnssec_ok:bool ->
    ?payload_size:int -> ?extensions:extension list -> unit -> t

  (* once we handle cookies, dnssec, or other extensions, need to adjust *)
  val reply : t option -> int option * t option

  val compare : t -> t -> int

  val pp : t Fmt.t

  val allocate_and_encode : t -> Cstruct.t

end

(* resource record map *)
module Umap : sig
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


  include Gmap.S with type 'a key = 'a k

  (** {2 Conversion functions} *)

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

  val combine : 'a k -> 'a -> 'a option -> 'a option

  val text : ?origin:Domain_name.t -> ?default_ttl:int32 -> Domain_name.t -> 'a k -> 'a -> string

  val get_ttl : b -> int32
  val with_ttl : b -> int32 -> b

  val add_entry : t Domain_name.Map.t -> Domain_name.t -> b -> t Domain_name.Map.t

  val find_entry : t Domain_name.Map.t -> Domain_name.t -> 'a k -> 'a option

  val remove_sub : t Domain_name.Map.t -> t Domain_name.Map.t -> t Domain_name.Map.t

end

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

    val all : t list

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

  val decode : Cstruct.t -> (t, [> `BadOpcode of int | `BadRcode of int | `Partial ]) result

  val encode : Cstruct.t -> t -> unit
end

module Question : sig
  type t = Domain_name.t * Udns_enum.rr_typ

  val pp : t Fmt.t
  val compare : t -> t -> int

  val decode : (Domain_name.t * int) Name.IntMap.t -> Cstruct.t ->
    Name.IntMap.key ->
    ((Domain_name.t * Udns_enum.rr_typ) * (Domain_name.t * int) Name.IntMap.t *
     int,
     [> `BadClass of Cstruct.uint16
     | `BadContent of string
     | `BadOffset of Name.IntMap.key
     | `BadRRTyp of Cstruct.uint16
     | `BadTag of Cstruct.uint8
     | `Partial
     | `TooLong
     | `UnsupportedClass of Udns_enum.clas ]) result
end


type data = Umap.t Domain_name.Map.t

val equal_data : data -> data -> bool

val pp_data : data Fmt.t

module Packet : sig

  module Query : sig

    type t = {
      question : Question.t ;
      answer : data ;
      authority : data ;
      additional : data ;
    }

    val query : ?answer:data -> ?authority:data -> ?additional:data -> Question.t -> t

    val pp : t Fmt.t
  end

  module Axfr : sig

    type t = {
      soa : (int32 * Soa.t) ;
      entries : data ;
    }

    val pp : t Fmt.t
  end

  module Update : sig

    type prereq =
      | Exists of Udns_enum.rr_typ
      | Exists_data of Umap.b
      | Not_exists of Udns_enum.rr_typ
      | Name_inuse
      | Not_name_inuse

    type update =
      | Remove of Udns_enum.rr_typ
      | Remove_all
      | Remove_single of Umap.b
      | Add of Umap.b

    type t = {
      zone : Question.t ;
      prereq : prereq Domain_name.Map.t ;
      update : update Domain_name.Map.t ;
      addition : data ;
    }

    val pp : t Fmt.t
  end

  type t = [
    | `Query of Query.t
    | `Notify of Query.t
    | `Axfr of Question.t * Axfr.t option
    | `Update of Update.t
  ]

  val pp : t Fmt.t

  type res = Header.t * t * Edns.t option * (Domain_name.t * Tsig.t * int) option

  val pp_res : res Fmt.t

  type err = [
    | `BadAlgorithm of int
    | `BadCaaTag
    | `BadClass of int
    | `BadContent of string
    | `BadEdns
    | `BadKeepalive
    | `BadOffset of int
    | `BadOpcode of int
    | `BadProto of int
    | `BadRRTyp of int
    | `BadRcode of int
    | `BadSshfpAlgorithm of int
    | `BadSshfpType of int
    | `BadTTL of int32
    | `BadTag of int
    | `BadTlsaCertUsage of int
    | `BadTlsaMatchingType of int
    | `BadTlsaSelector of int
    | `Bad_edns_version of int
    | `InvalidAlgorithm of Domain_name.t
    | `InvalidTimestamp of int64
    | `InvalidZoneCount of int
    | `InvalidZoneRR of Udns_enum.rr_typ
    | `Invalid_axfr of string
    | `LeftOver
    | `NonZeroRdlen of int
    | `NonZeroTTL of int32
    | `None_or_multiple_questions
    | `Partial
    | `TooLong
    | `UnsupportedClass of Udns_enum.clas
    | `UnsupportedOpcode of Udns_enum.opcode
    | `UnsupportedRRTyp of Udns_enum.rr_typ
  ]

  val pp_err : err Fmt.t

  val decode : Cstruct.t -> (res, err) result

  val size_edns : int option -> Edns.t option -> proto -> bool -> int * Edns.t option

  val encode_t : Cstruct.t -> t -> int

  val encode : ?max_size:int -> ?edns:Edns.t -> proto -> Header.t -> t -> Cstruct.t * int

  val error : Header.t -> t -> Udns_enum.rcode -> (Cstruct.t * int) option
end

type tsig_verify = ?mac:Cstruct.t -> Ptime.t -> Packet.t -> Header.t ->
  Domain_name.t -> key:Dnskey.t option -> Tsig.t -> Cstruct.t ->
  (Tsig.t * Cstruct.t * Dnskey.t, Cstruct.t option) result

type tsig_sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> Tsig.t ->
  key:Dnskey.t -> Cstruct.t -> (Cstruct.t * Cstruct.t) option
