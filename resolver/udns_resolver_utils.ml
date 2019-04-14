(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns
open Udns_resolver_cache

open Rresult.R.Infix

let invalid_soa name =
  let p pre =
    match Domain_name.(prepend name "invalid" >>= fun n -> prepend n pre) with
    | Ok name -> name
    | Error _ -> name
  in
  {
    Soa.nameserver = p "ns" ; hostmaster = p "hostmaster" ;
    serial = 1l ; refresh = 16384l ; retry = 2048l ;
    expiry = 1048576l ; minimum = 300l
  }

let soa_map name soa =
  Domain_name.Map.singleton name Rr_map.(singleton Soa soa)

let _invalid_soa_map name =
  let soa = invalid_soa name in
  soa_map name soa

let noerror bailiwick (_, flags) (q_name, q_type) (answer, authority) additional =
  (* maybe should be passed explicitly (when we don't do qname minimisation) *)
  let in_bailiwick name = Domain_name.sub ~domain:bailiwick ~subdomain:name in
  (* ANSWER *)
  let answers, anames =
    match Domain_name.Map.find q_name answer with
    | None ->
      (* NODATA (no answer, but SOA (or not) in authority) *)
      begin
        (* RFC2308, Sec 2.2 "No data":
           - answer is empty
           - authority has a) SOA + NS, b) SOA, or c) nothing *)
        (* an example for this behaviour is NS:
           asking for AAAA www.soup.io, get empty answer + SOA in authority
           asking for AAAA coffee.soup.io, get empty answer + authority *)
        let rank = if Packet.Header.FS.mem `Authoritative flags then AuthoritativeAuthority else Additional in
        match
          Domain_name.Map.fold (fun name rr_map acc ->
              if Domain_name.sub ~subdomain:q_name ~domain:name then
                match Rr_map.find Soa rr_map with
                | Some soa -> (name, soa) :: acc
                | None -> acc
              else
                acc)
            authority []
        with
        | (name, soa)::_ -> [ q_type, q_name, rank, `No_data (name, soa) ]
        | [] when not (Packet.Header.FS.mem `Truncation flags) ->
          Logs.warn (fun m -> m "noerror answer, but nothing in authority whose sub is %a in %a, invalid_soa!"
                        Packet.Question.pp (q_name, q_type) Name_rr_map.pp authority) ;
          [ q_type, q_name, Additional, `No_data (q_name, invalid_soa q_name) ]
        | [] -> [] (* general case when we get an answer from root server *)
      end, Domain_name.Set.empty
    | Some rr_map ->
      let rank = if Packet.Header.FS.mem `Authoritative flags then AuthoritativeAnswer else NonAuthoritativeAnswer in
      (* collect those rrsets which are of interest depending on q_type! *)
      if q_type = Rr.ANY then
        Rr_map.fold (fun b (acc, names) ->
            (Rr_map.to_rr_typ b, q_name, rank, `Entry b) :: acc,
            Domain_name.Set.union names (Rr_map.names_b b))
          rr_map ([], Domain_name.Set.empty)
      else
        match Rr_map.lookup_rr q_type rr_map with
        | Some b -> [ q_type, q_name, rank, `Entry b ], Rr_map.names_b b
        | None -> match Rr_map.find Cname rr_map with
          | None ->
            (* case neither TYP nor cname *)
            Logs.warn (fun m -> m "noerror answer with right name, but not TYP nor cname in %a, invalid soa for %a"
                          Name_rr_map.pp answer Packet.Question.pp (q_name, q_type));
            [ q_type, q_name, rank, `No_data (q_name, invalid_soa q_name) ],
            Domain_name.Set.empty
          | Some cname ->
            (* explicitly register as CNAME so it'll be found *)
            (* should we try to find further records for the new alias? *)
            [ Rr.CNAME, q_name, rank, `Alias cname ],
            Domain_name.Set.singleton (snd cname)
  in

  (* AUTHORITY - NS records *)
  let ns, nsnames =
    (* authority points us to NS of q_name! *)
    (* we collect a list of NS records and the ns names *)
    (* TODO need to be more careful, q: foo.com a: foo.com a 1.2.3.4 au: foo.com ns blablubb.com ad: blablubb.com A 1.2.3.4 *)
    let nm, names =
      Domain_name.Map.fold (fun name map (acc, s) ->
          if in_bailiwick name then
            match Rr_map.find Ns map with
            | None -> acc, s
            | Some (ns : int32 * Domain_name.Set.t) ->
              (name, ns) :: acc, Domain_name.Set.union s (snd ns)
          else
            acc, s)
        authority
        ([], Domain_name.Set.empty)
    in
    let rank = if Packet.Header.FS.mem `Authoritative flags then AuthoritativeAuthority else Additional in
    List.fold_left (fun acc (name, ns) ->
        (Rr.NS, name, rank, `Entry Rr_map.(B (Ns, ns))) :: acc)
      [] nm, names
  in

  (* ADDITIONAL *)
  (* maybe only these thingies which are subdomains of q_name? *)
  (* preserve A/AAAA records only for NS lookups? *)
  (* now we have processed:
     - answer (filtered to where name = q_name)
     - authority with SOA and NS entries
     - names from these answers, and authority
     - additional section can contain glue records if needed
     - only A and AAAA records are of interest for glue *)
  let glues =
    let names = Domain_name.Set.union anames nsnames in
    let names = Domain_name.Set.filter in_bailiwick names in
    Domain_name.Set.fold (fun name acc ->
        match Domain_name.Map.find name additional with
        | None -> acc
        | Some map ->
          let a = match Rr_map.lookup_rr Rr.A map with
            | None -> acc
            | Some b -> (Rr.A, name, Additional, `Entry b) :: acc
          in
          match Rr_map.lookup_rr Rr.AAAA map with
          | None -> a
            | Some b -> (Rr.AAAA, name, Additional, `Entry b) :: a)
      names []
  in
  (* This is defined in RFC2181, Sec9 -- answer is unique if authority or
     additional is non-empty *)
  let answer_complete =
    not (Domain_name.Map.is_empty authority && Domain_name.Map.is_empty additional)
  in
  match answers, ns with
  | [], [] when not answer_complete && Packet.Header.FS.mem `Truncation flags ->
    (* special handling for truncated replies.. better not add anything *)
    Logs.warn (fun m -> m "truncated reply for %a, ignoring completely"
                  Packet.Question.pp (q_name, q_type));
    []
  | [], [] ->
    (* not sure if this can happen, maybe discard everything? *)
    Logs.warn (fun m -> m "reply without answers or ns invalid so for %a"
                  Packet.Question.pp (q_name, q_type));
    [ q_type, q_name, Additional, `No_data (q_name, invalid_soa q_name) ]
  | _, _ -> answers @ ns @ glues

let find_soa name authority =
  let rec go name =
    match Domain_name.Map.find name authority with
    | None -> go (Domain_name.drop_labels_exn name)
    | Some rrmap -> match Rr_map.(find Soa rrmap) with
      | None -> go (Domain_name.drop_labels_exn name)
      | Some soa -> name, soa
  in
  try Some (go name) with Invalid_argument _ -> None

let nxdomain (_, flags) (name, _typ) data =
  (* we can't do much if authoritiative is not set (some auth dns do so) *)
  (* There are cases where answer is non-empty, but contains a CNAME *)
  (* RFC 2308 Sec 1 + 2.1 show that NXDomain is for the last QNAME! *)
  (* -> need to potentially extract CNAME(s) *)
  let answer, authority = match data with
    | None -> Name_rr_map.empty, Name_rr_map.empty
    | Some x -> x
  in
  let cname_opt =
    let rec go acc name =
      match Domain_name.Map.find name answer with
      | None -> acc
      | Some rrmap -> match Rr_map.(find Cname rrmap) with
        | None -> acc
        | Some (ttl, alias) -> go ((name, (ttl, alias)) :: acc) alias
    in
    go [] name
  in
  let soa = find_soa name authority in
  (* since NXDomain have CNAME semantics, we store them as CNAME *)
  let rank = if Packet.Header.FS.mem `Authoritative flags then AuthoritativeAnswer else NonAuthoritativeAnswer in
  (* we conclude NXDomain, there are 3 cases we care about:
     no soa in authority and no cname answer -> inject an invalid_soa (avoid loops)
     a matching soa, no cname -> NoDom q_name
     _, a matching cname -> NoErr q_name with cname
  *)
  let entries =
    match soa, cname_opt with
    | None, [] ->
      let soa = invalid_soa name in
      [ name, `No_domain (name, soa) ]
    | Some (name, soa), [] ->
      [ name, `No_domain (name, soa) ]
    | _, rrs ->
      List.map (fun (name, cname) ->
          name, `Alias cname)
        rrs
  in
  (* the cname does not matter *)
  List.map (fun (name, res) -> Rr.CNAME, name, rank, res) entries

let noerror_stub (name, typ) (answer, authority) =
  (* no glue, just answers - but get all the cnames *)
  let find_entry_or_cname name =
    match Domain_name.Map.find name answer with
    | None -> None
    | Some rrmap -> match typ with
      | Rr.ANY -> Some (`Entries rrmap)
      | _ -> match Rr_map.lookup_rr typ rrmap with
        | Some b -> Some (`Entry b)
        | None -> match Rr_map.(find Cname rrmap) with
          | None -> None
          | Some (ttl, alias) -> Some (`Cname (ttl, alias))
  in
  let rec go acc name = match find_entry_or_cname name with
    | None ->
      let name, soa = match find_soa name authority with
        | Some (name, soa) -> (name, soa)
        | None -> name, invalid_soa name
      in
      (typ, name, NonAuthoritativeAnswer, `No_data (name, soa)) :: acc
    | Some (`Cname (ttl, alias)) ->
      go ((Rr.CNAME, name, NonAuthoritativeAnswer, `Alias (ttl, alias)) :: acc) alias
    | Some (`Entry b) ->
      (typ, name, NonAuthoritativeAnswer, `Entry b) :: acc
    | Some (`Entries map) ->
      Rr_map.fold (fun Rr_map.(B (k, _) as b) acc ->
          (Rr_map.k_to_rr_typ k, name, NonAuthoritativeAnswer, `Entry b) :: acc)
        map acc
  in
  go [] name

(* stub vs recursive: maybe sufficient to look into *)
let scrub ?(mode = `Recursive) zone p =
  Logs.debug (fun m -> m "scrubbing (bailiwick %a) data %a"
                 Domain_name.pp zone Packet.pp p);
  match mode, p.Packet.data with
  | `Recursive, `Answer data -> Ok (noerror zone p.header p.question data p.additional)
  | `Stub, `Answer data -> Ok (noerror_stub p.question data)
  | _, `Rcode_error (Rcode.NXDomain, _, data) ->
    Ok (nxdomain p.Packet.header p.Packet.question data)
  | `Stub, `Rcode_error (Rcode.ServFail, _, _) ->
    let name = fst p.question in
    let soa = invalid_soa name in
    Ok [ Rr.CNAME, name, NonAuthoritativeAnswer, `Serv_fail (name, soa) ]
  | _, e -> Error (Packet.rcode_data e)
