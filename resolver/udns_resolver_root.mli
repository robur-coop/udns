(* (c) 2018 Hannes Mehnert, all rights reserved *)

val root_servers : (Domain_name.t * Ipaddr.V4.t) list

val ns_records : Udns.Map.b

val a_records : (Domain_name.t * Udns.Map.b) list

val reserved_zones : (Domain_name.t * Udns.Map.b) list
