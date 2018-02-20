(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage

let address =
  let network = Ipaddr.V4.Prefix.of_address_string_exn "10.0.0.2/24"
  and gateway = Ipaddr.V4.of_string "10.0.0.1"
  in
  { network ; gateway }

let net =
  if_impl Key.is_unix
    (socket_stackv4 [Ipaddr.V4.any])
    (static_ipv4_stack ~config:address ~arp:farp default_network)

let disk = generic_kv_ro "data"

let dns_handler =
  let packages = [
    package "logs" ;
    package ~sublibs:["server" ; "crypto" ; "zonefile" ; "mirage" ] "udns" ;
    package "nocrypto"
  ] in
  foreign
    ~deps:[abstract nocrypto]
    ~packages
    "Unikernel.Main"
    (random @-> pclock @-> mclock @-> time @-> stackv4 @-> kv_ro @-> job)

let () =
  register "primary"
    [dns_handler $ default_random $ default_posix_clock $ default_monotonic_clock $ default_time $ net $ disk ]