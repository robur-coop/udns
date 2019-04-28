(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_mirage_server" ~doc:"effectful DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (P : Mirage_clock_lwt.PCLOCK) (M : Mirage_clock_lwt.MCLOCK) (TIME : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) = struct

  module Dns = Udns_mirage.Make(S)

  module T = S.TCPV4

  let primary ?(on_update = fun ~old:_ _ -> Lwt.return_unit) ?(on_notify = fun _ _ -> Lwt.return None) ?(timer = 2) ?(port = 53) stack t =
    let state = ref t in
    let tcp_out = ref Dns.IM.empty in

    let drop ip =
      tcp_out := Dns.IM.remove ip !tcp_out ;
      state := Udns_server.Primary.closed !state ip
    in
    let send_notify (ip, data) =
      let dport = 53 in
      let connect ip =
        Log.info (fun m -> m "creating connection to %a:%d" Ipaddr.V4.pp ip dport) ;
        T.create_connection (S.tcpv4 stack) (ip, dport) >>= function
        | Error e ->
          Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                      T.pp_error e Ipaddr.V4.pp ip port) ;
          Lwt.return (Error ())
        | Ok flow ->
          tcp_out := Dns.IM.add ip flow !tcp_out;
          Lwt.return (Ok flow)
      in
      let connect_and_send ip =
        connect ip >>= function
        | Ok flow -> Dns.send_tcp flow data
        | Error () -> Lwt.return (Error ())
      in
      (match Dns.IM.find ip !tcp_out with
       | None -> connect_and_send ip
       | Some f -> Dns.send_tcp f data >>= function
         | Ok () -> Lwt.return (Ok ())
         | Error () -> drop ip ; connect_and_send ip) >>= function
      | Ok () -> Lwt.return_unit
      | Error () ->
        drop ip ; Dns.send_udp stack port ip dport data
    in

    let maybe_update_state t =
      let old = !state in
      let trie server = Udns_server.Primary.data server in
      state := t;
      if Udns_trie.equal (trie t) (trie old) then
        Lwt.return_unit
      else
        on_update ~old:(trie old) t
    and maybe_notify t now ts = function
      | None -> Lwt.return_unit
      | Some n -> on_notify n t >>= function
        | None -> Lwt.return_unit
        | Some trie ->
          let state', outs = Udns_server.Primary.with_data t now ts trie in
          state := state';
          Lwt_list.iter_p send_notify outs
    in

    let udp_cb ~src ~dst:_ ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp src src_port) ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, answer, notify, n = Udns_server.Primary.handle_buf !state now elapsed `Udp src src_port buf in
      maybe_update_state t >>= fun () ->
      maybe_notify t now elapsed n >>= fun () ->
      (match answer with
       | None -> Log.warn (fun m -> m "empty answer") ; Lwt.return_unit
       | Some answer -> Dns.send_udp stack port src src_port answer) >>= fun () ->
      Lwt_list.iter_p send_notify notify
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "DNS server listening on UDP port %d" port) ;
    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp dst_ip dst_port) ;
      let f = Dns.of_flow flow in
      tcp_out := Dns.IM.add dst_ip flow !tcp_out ;
      let rec loop () =
        Dns.read_tcp f >>= function
        | Error () -> drop dst_ip ; Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps ()) in
          let elapsed = M.elapsed_ns () in
          let t, answer, notify, n = Udns_server.Primary.handle_buf !state now elapsed `Tcp dst_ip dst_port data in
          maybe_update_state t >>= fun () ->
          maybe_notify t now elapsed n >>= fun () ->
          Lwt_list.iter_p send_notify notify >>= fun () ->
          match answer with
          | None -> Log.warn (fun m -> m "empty answer") ; loop ()
          | Some answer ->
            Dns.send_tcp flow answer >>= function
            | Ok () -> loop ()
            | Error () -> drop dst_ip ; Lwt.return_unit
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "DNS server listening on TCP port %d" port) ;
    let rec time () =
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, notifies = Udns_server.Primary.timer !state now elapsed in
      maybe_update_state t >>= fun () ->
      Lwt_list.iter_p send_notify notifies >>= fun () ->
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time

  let secondary ?(on_update = fun ~old:_ _trie -> Lwt.return_unit) ?(timer = 5) ?(port = 53) stack t =
    let state = ref t in
    let tcp_out = ref Dns.IM.empty in
    let tcp_packet_transit = ref Dns.IM.empty in
    let in_flight = ref Dns.IS.empty in

    let maybe_update_state t =
      let old = !state in
      let trie server = Udns_server.Secondary.data server in
      state := t ;
      if Udns_trie.equal (trie t) (trie old) then
        Lwt.return_unit
      else
        on_update ~old:(trie old) t
    in

    let rec close ip =
      (match Dns.IM.find ip !tcp_out with
       | None -> Lwt.return_unit
       | Some f -> T.close f) >>= fun () ->
      tcp_out := Dns.IM.remove ip !tcp_out ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let state', out = Udns_server.Secondary.closed !state now elapsed ip in
      state := state' ;
      Lwt_list.iter_s request out
    and read_and_handle ip f =
      Dns.read_tcp f >>= function
      | Error () ->
        Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.V4.pp ip) ;
        close ip >>= fun () ->
        (* re-send once *)
        begin match Dns.IM.find ip !tcp_packet_transit with
          | None -> Lwt.return_unit
          | Some data -> request ~record:false data
        end
      | Ok data ->
        let now = Ptime.v (P.now_d_ps ()) in
        let elapsed = M.elapsed_ns () in
        let t, answer, out =
          Udns_server.Secondary.handle_buf !state now elapsed `Tcp ip data
        in
        maybe_update_state t >>= fun () ->
        Lwt_list.iter_s request out >>= fun () ->
        match answer with
        | None -> read_and_handle ip f
        | Some x ->
          Dns.send_tcp (Dns.flow f) x >>= function
          | Error () ->
            Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.V4.pp ip) ;
            close ip
          | Ok () -> read_and_handle ip f
    and request ?(record = true) (proto, ip, data) =
      let dport = 53 in
      if record then
        tcp_packet_transit := Dns.IM.add ip (proto, ip, data) !tcp_packet_transit;
      match Dns.IM.find ip !tcp_out with
      | None ->
        begin
          if Dns.IS.mem ip !in_flight then
            Lwt.return_unit
          else begin
            Log.info (fun m -> m "creating connection to %a:%d" Ipaddr.V4.pp ip dport) ;
            in_flight := Dns.IS.add ip !in_flight ;
            T.create_connection (S.tcpv4 stack) (ip, dport) >>= function
            | Error e ->
              Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                          T.pp_error e Ipaddr.V4.pp ip dport) ;
              in_flight := Dns.IS.remove ip !in_flight ;
              Lwt.async (fun () ->
                  TIME.sleep_ns (Duration.of_sec 5) >>= fun () ->
                  close ip) ;
              Lwt.return_unit
            | Ok flow ->
              Dns.send_tcp flow data >>= function
              | Error () -> close ip
              | Ok () ->
                tcp_out := Dns.IM.add ip flow !tcp_out ;
                in_flight := Dns.IS.remove ip !in_flight ;
                Lwt.async (fun () -> read_and_handle ip (Dns.of_flow flow)) ;
                Lwt.return_unit
          end
        end
      | Some flow ->
        Dns.send_tcp flow data >>= function
        | Ok () -> Lwt.return_unit
        | Error () ->
          Log.warn (fun m -> m "closing tcp flow to %a:%d, retrying request"
                       Ipaddr.V4.pp ip dport) ;
          T.close flow >>= fun () ->
          tcp_out := Dns.IM.remove ip !tcp_out ;
          request (proto, ip, data)
    in

    let udp_cb ~src ~dst:_ ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp src src_port) ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, answer, out = Udns_server.Secondary.handle_buf !state now elapsed `Udp src buf in
      maybe_update_state t >>= fun () ->
      List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
      match answer with
      | None -> Lwt.return_unit
      | Some out -> Dns.send_udp stack port src src_port out
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "secondary DNS listening on UDP port %d" port) ;

    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp dst_ip dst_port) ;
      let f = Dns.of_flow flow in
      let rec loop () =
        Dns.read_tcp f >>= function
        | Error () -> Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps ()) in
          let elapsed = M.elapsed_ns () in
          let t, answer, out =
            Udns_server.Secondary.handle_buf !state now elapsed `Tcp dst_ip data
          in
          maybe_update_state t >>= fun () ->
          List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
          match answer with
          | None ->
            Log.warn (fun m -> m "no TCP output") ;
            loop ()
          | Some data ->
            Dns.send_tcp flow data >>= function
            | Ok () -> loop ()
            | Error () -> Lwt.return_unit
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "secondary DNS listening on TCP port %d" port) ;

    let rec time () =
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, out = Udns_server.Secondary.timer !state now elapsed in
      maybe_update_state t >>= fun () ->
      List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time
end
