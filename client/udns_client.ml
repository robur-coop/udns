open Udns

type 'key query_state =
  { protocol : Udns.proto ;
    key: 'key ;
    header : Udns.Header.t ;
    question : Udns.Question.t ; (* we only handle one *)
  } constraint 'key = 'a Umap.key

let make_query protocol hostname
    : 'xy  ->
      Cstruct.t * 'xy query_state =
  (* SRV records: Service + Protocol are case-insensitive, see RFC2728 pg2. *)
  fun record_type ->
  let question = (hostname, Umap.k_to_rr_typ record_type) in
  let query : Packet.Query.t = Packet.Query.create question in
  let header = {
    Udns.Header.id = Random.int 0xffff ; (* TODO *)
    query = true ; operation = Udns_enum.Query; rcode = Udns_enum.NoError ;
    flags = Udns.Header.FS.singleton `Recursion_desired }
  in
  (*let max_size, edns = Udns_packet.size_edns None None proto query in*)
  let cs , _ =
    Packet.encode ~max_size:1200 ?edns:None
      protocol header (`Query query) in
  begin match protocol with
    | `Udp -> cs
    | `Tcp ->
      let len_field = Cstruct.create 2 in
      Cstruct.BE.set_uint16 len_field 0 (Cstruct.len cs) ;
      Cstruct.concat [len_field ; cs]
  end, { protocol ; header; question ; key = record_type }

let parse_response (type requested)
  : requested Umap.k query_state -> Cstruct.t ->
    (requested, [< `Partial | `Msg of string]) result =
  fun state buf ->
  let open Rresult in
  begin match state.protocol with (* consume TCP two-byte length prefix: *)
    | `Udp -> Ok buf
    | `Tcp ->
      begin match Cstruct.BE.get_uint16 buf 0 with
        | exception Invalid_argument _ -> Error `Partial (* TODO *)
        | pkt_len when pkt_len > Cstruct.len buf -2 ->
          Logs.debug (fun m -> m "Partial: %d >= %d-2"
                         pkt_len (Cstruct.len buf));
          Error `Partial (* TODO return remaining # *)
        | pkt_len ->
          if 2 + pkt_len < Cstruct.len buf then
            Logs.warn (fun m -> m "Extraneous data in DNS response");
          Ok (Cstruct.sub buf 2 pkt_len)
      end
  end >>= fun buf ->
  match Packet.decode buf with
  | Ok ({Header.rcode = NoError ; operation = Query ; id = hdr_id;
          query = false; _ },
         `Query resp, _edns (* what is flags? *), _tsig)
    when hdr_id = state.header.id
      && Udns.Question.compare resp.question state.question = 0
    ->
    let rec follow_cname counter q_name =
      if counter <= 0 then Error (`Msg "CNAME recursion too deep")
      else
        Domain_name.Map.find_opt q_name resp.answer
        |> R.of_option ~none:(fun () ->
            R.error_msgf "Can't find relevant map in response:@ \
                          %a in [%a]"
              Domain_name.pp q_name
              Packet.pp_data resp.answer
          ) >>= fun relevant_map ->
        begin match Umap.find state.key relevant_map with
          | Some response -> Ok response
          | None ->
            begin match Umap.(find Cname relevant_map) with
              | None -> Error (`Msg "Invalid DNS response")
              | Some (_ttl, redirected_host) ->
                follow_cname (pred counter) redirected_host
            end
        end
    in
    follow_cname 20 (fst state.question)
  | Ok (h, `Query q, edns, tsig) ->
    R.error_msgf
      "QUERY: @[<v>hdr:%a (id: %d = %d) (q=q: %B)@ query:%a  opt:%a tsig:%B@,@]"
      Udns.Header.pp h
      h.id state.header.id
      (Udns.Question.compare q.question state.question = 0)
      Packet.Query.pp q
      (Fmt.option Udns.Edns.pp) edns
      (match tsig with None -> false | Some _ -> true)
  | Ok (_, `Notify _, _, _)-> Error (`Msg "Ok _ Notify _")
  | Ok (_, `Update _, _, _) -> Error (`Msg "Ok _ Update todo")
  | Ok (_, `Axfr _, _, _) -> Error (`Msg "Ok _ Axfr todo")
  | Error `Partial as err -> err
  | Error err -> R.error_msgf "Error parsing response: %a" Packet.pp_err err
