(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

val scrub : ?mode:[ `Recursive | `Stub ] -> Domain_name.t -> Packet.t ->
  ((Rr.t * Domain_name.t * Udns_resolver_cache.rank * Udns_resolver_cache.res) list,
   Rcode.t) result

val invalid_soa : Domain_name.t -> Soa.t
