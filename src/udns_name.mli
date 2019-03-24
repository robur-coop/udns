(* (c) 2017 Hannes Mehnert, all rights reserved *)

module IntMap : Map.S with type key = int
(** The module of an integer map *)

type err =
  [ `Partial
  | `BadOffset of int
  | `BadTag of int
  | `BadContent of string
  | `TooLong ]
(** Errors while decoding a domain name. *)

val pp_err : err Fmt.t
(** [pp ppf error] pretty prints the [error] on [ppf]. *)

type offset_name_map = (Domain_name.t * int) IntMap.t
(** The type of a map which keys are integers, and values being domain names
    and their size. *)

val decode : ?hostname:bool -> offset_name_map -> Cstruct.t ->
  int -> (Domain_name.t * offset_name_map * int, [> err ]) result
(** [decode ~hostname map buf off] decodes a domain name from [buf] at
    position [off].  If [hostname] is provided and [true] (the default), the
    domain name is additionally checked for being a hostname using
    {!is_hostname}.

    RFC 1035 specifies label compression: a domain name may either end with the
    root label or a pointer (byte offset from the beginning of the frame) to a
    domain name.  To support decompression, a [map] between offsets and domain
    names and length is passed around, and the absolute [offset] in the frame.
    The return value is either a decoded and decompressed domain name, an
    extended map, and the consumed bytes (as offset into the buffer), or an
    error.  *)

type name_offset_map = int Domain_name.Map.t
(** The type of a map which keys are domain names, and values being integer
   offsets. *)

val encode : ?compress:bool -> name_offset_map -> Cstruct.t -> int ->
  Domain_name.t -> name_offset_map * int
(** [encode ~compress map buf off t] encodes [t] into [buf], extending the
    [map].  If [compress] is [true] (the default), and a (sub)domain name of [t]
    is in [map], a pointer is inserted instead of the full domain name.

    NB: DNS (especially RFC 3597) mentions that pointers should only point to
    domain names in resource data which are well known (which means specified in
    RFC 1035).  To achieve this, the caller of [encode] if inside of other
    resource data fields needs to discard the returned [map], and continue to
    use the provided [map].  There should be no reason to use [~compress:false]
    (esp. these resource data fields which are _not_ well known may still
    contain pointers to well known ones.

    @raise Invalid_argument if the provided [buf] is too small.  *)
