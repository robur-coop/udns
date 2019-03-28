(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Udns

val root_servers : (Domain_name.t * Ipaddr.V4.t) list

val ns_records : Umap.b

val a_records : (Domain_name.t * Umap.b) list

val reserved_zones : (Domain_name.t * Umap.b) list
