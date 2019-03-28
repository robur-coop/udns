(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

(** DNS TSIG signatures *)

val compute_tsig : Domain_name.t -> Tsig.t -> key:Cstruct.t ->
  Cstruct.t -> Cstruct.t
(** [compute_tsig name tsig ~key buffer] computes the mac over [buffer]
    and [tsig], using the provided [key] and [name]. *)

val sign : Udns.tsig_sign
(** [sign] is the signature function. *)

val verify : Udns.tsig_verify
(** [verify] is the verify function. *)

val encode_and_sign : ?proto:proto -> Header.t ->
  Packet.t -> Ptime.t -> Udns.Dnskey.t -> Domain_name.t ->
  (Cstruct.t * Cstruct.t, string) result
(** [encode_and_sign ~proto hdr v now dnskey name] signs and encodes the DNS
   packet. *)

val decode_and_verify : Ptime.t -> Dnskey.t -> Domain_name.t ->
  ?mac:Cstruct.t -> Cstruct.t ->
  (Header.t * Packet.t * Edns.t option * Tsig.t * Cstruct.t, string) result
(** [decode_and_verify now dnskey name ~mac buffer] decodes and verifies the
   given buffer using the key material, resulting in a DNS packet and the mac,
   or a failure. *)
