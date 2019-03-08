(* odns client utility. *)
(* RFC 768  DNS over UDP *)
(* RFC 7766 DNS over TCP: https://tools.ietf.org/html/rfc7766 *)
(* RFC 6698 DANE: https://tools.ietf.org/html/rfc6698*)

let pp_zone ppf (domain,query_type,query_value) =
  Fmt.string ppf
    (Dns_map.text domain (Dns_map.B (query_type, query_value)))

let pp_zone_tlsa ppf (domain,ttl,(tlsa:Dns_packet.tlsa)) =
  (* TODO this implementation differs a bit from Dns_map.text and tries to
     follow the `dig` output to make it easier to port existing scripts *)
  Fmt.pf ppf "%a.\t%ld\tIN\t%d\t%d\t%d\t%s"
    Domain_name.pp domain
    ttl
    (Dns_enum.tlsa_cert_usage_to_int tlsa.tlsa_cert_usage)
    (Dns_enum.tlsa_selector_to_int tlsa.tlsa_selector)
    (Dns_enum.tlsa_matching_type_to_int tlsa.tlsa_matching_type)
    ( (* this produces output similar to `dig`, splitting the hex string
         in chunks of 56 chars (28 bytes): *)
      let `Hex hex = Hex.of_cstruct tlsa.tlsa_data in
      let hlen = String.length hex in
      let rec loop acc = function
        | n when n + 56 >= hlen ->
          String.concat " " (List.rev @@ String.sub hex n (hlen-n)::acc)
          |> String.uppercase_ascii
        | n -> loop ((String.sub hex n 56)::acc) (n+56)
      in loop [] 0)

let do_a ((_,(ns_ip,_)) as ns) domains _ =
  Logs.info (fun m -> m "querying NS %s for A records of %a"
                (Unix.string_of_inet_addr ns_ip)
                Fmt.(list ~sep:(unit", ") Domain_name.pp) domains);
  let job =
    Lwt_list.iter_p (fun domain ->
        let open Lwt in
        Logs.debug (fun m -> m "looking up %a" Domain_name.pp domain);
        Udns_client_lwt.(getaddrinfo ns Dns_map.A domain)
        >|= function
        | Ok (_ttl, addrs) when Dns_map.Ipv4Set.is_empty addrs ->
          (* handle empty response? *)
          Logs.app (fun m -> m ";%a. IN %a"
                       Domain_name.pp domain
                       Dns_enum.pp_rr_typ (Dns_map.k_to_rr_typ Dns_map.A))
        | Ok resp ->
          Logs.app (fun m -> m "%a" pp_zone
                       (domain, Dns_map.A, resp))
        | Error (`Msg msg) ->
          Logs.err (fun m -> m "Failed to lookup %a: %s\n"
                       Domain_name.pp domain msg)
      ) domains
  in
  match Lwt_main.run job with
  | () -> Ok () (* TODO handle errors *)

let do_tlsa ((_,(ns_ip,_)) as ns) domains _ =
  Logs.info (fun m -> m "NS: %s" @@ Unix.string_of_inet_addr ns_ip);
  let job =
    Lwt_list.iter_p (fun domain ->
        let open Lwt in
        Udns_client_lwt.getaddrinfo ns Dns_map.Tlsa domain
        >>= function
        | Ok (ttl, tlsa_resp) ->
          Dns_map.TlsaSet.iter (fun tlsa ->
              Logs.app (fun m -> m "%a" pp_zone_tlsa (domain,ttl,tlsa))
            ) tlsa_resp ;
          Lwt.return_unit
        | Error (`Msg msg) ->
          Logs.err (fun m -> m "Failed to lookup %a: %s\n%!"
                       Domain_name.pp domain msg) ;
          Lwt.return_unit
      ) domains
  in
  match Lwt_main.run job with
  | () -> Ok () (* TODO catch failed jobs *)

open Cmdliner

let sdocs = Manpage.s_common_options

let setup_log =
  let _setup_log (style_renderer:Fmt.style_renderer option) level : unit =
    Fmt_tty.setup_std_outputs ?style_renderer () ;
    Logs.set_level level ;
    Logs.set_reporter (Logs_fmt.reporter ())
  in
  Term.(const _setup_log $ Fmt_cli.style_renderer ~docs:sdocs ()
        $ Logs_cli.level ~docs:sdocs ())

let parse_ns : ('a * (Lwt_unix.inet_addr * int)) Arg.conv =
  ( fun ns ->
      try `Ok (`TCP, (Unix.inet_addr_of_string ns, 53)) with
      | _ -> `Error "NS must be an IPv4 address"),
  ( fun ppf (typ, (ns, port)) ->
      Fmt.pf ppf "%s:%d(%s)" (Unix.string_of_inet_addr ns) port
        (match typ with `UDP -> "udp" | `TCP -> "tcp"))

let arg_ns : 'a Term.t =
  let doc = "IP of nameserver to use" in
  Arg.(value & opt parse_ns Udns_client_lwt.default_ns
       & info ~docv:"NS-IP" ~doc ["ns"])

let parse_domain : Domain_name.t Arg.conv =
  ( fun name ->
      Domain_name.of_string ~hostname:false name
      |> Rresult.R.reword_error
        (fun (`Msg m) -> Fmt.strf "Invalid domain: %S: %s" name m)
      |> Rresult.R.to_presult) ,
  Domain_name.pp

let arg_domains : Domain_name.t list Term.t =
  let doc = "Domain names to operate on" in
  Arg.(non_empty & pos_all parse_domain []
       & info [] ~docv:"DOMAIN(s)" ~doc)

let cmd_a : unit Term.t * Term.info =
  let doc = "Query a NS for A records" in
  let man = [
  ] in
  Term.(term_result (const do_a $ arg_ns $ arg_domains $ setup_log)),
  Term.info "a" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_tlsa : unit Term.t * Term.info =
  let doc = "Query a NS for TLSA records (see DANE / RFC 7671)" in
  let man = [
    `S Manpage.s_arguments ;
    `S Manpage.s_description ;
    `P {|Note that you must specify which $(b,service name)
you want to retrieve the key(s) of.
To retrieve the $(b,HTTPS) cert of $(i,www.example.com), you would query the NS: $(mname) $(tname) $(b,_443._tcp.)$(i,www.example.com)|} ;
    `P {|Brief list of other handy service name prefixes:
$(b,_5222._tcp) (XMPP); $(b,_853._tcp) (DNS-over-TLS); $(b,_25._tcp) (SMTP with STARTTLS); $(b,_465._tcp)(SMTP);
 $(b,_993._tcp) (IMAP)
|} ;
    `S Manpage.s_options ;
  ] in
  Term.(term_result (const do_tlsa $ arg_ns $ arg_domains $ setup_log)),
  Term.info "tlsa" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_help : 'a Term.t * Term.info =
  let doc = "OCaml uDns alternative to `dig`" in
  let man = [
    `P {|For more information about the available subcommands,
run them while passing the help flag: $(tname) $(i,SUBCOMMAND) $(b,--help)
|}
  ] in
  let help _ = `Help (`Pager, None) in
  Term.(ret (const help $ setup_log)),
  Term.info "odns" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmds =
  [ cmd_a ; cmd_tlsa ]

let () =
  Term.(exit @@ eval_choice cmd_help cmds)