(* (c) 2017 Hannes Mehnert, all rights reserved *)

type rank =
  | ZoneFile
  | ZoneTransfer
  | AuthoritativeAnswer
  | AuthoritativeAuthority
  | ZoneGlue
  | NonAuthoritativeAnswer
  | Additional

val compare_rank : rank -> rank -> [ `Equal | `Smaller | `Bigger ]

val pp_rank : rank Fmt.t

type res =
  | NoErr of Udns.Map.b
  | NoData of Domain_name.t * (int32 * Udns.Soa.t)
  | NoDom of Domain_name.t * (int32 * Udns.Soa.t)
  | ServFail of Domain_name.t * (int32 * Udns.Soa.t)

val pp_res : res Fmt.t

val decrease_ttl : int32 -> res -> res option

val smooth_ttl : int32 -> res -> res

val to_map : res -> Udns.Map.t Domain_name.Map.t
