(*
 * Copyright (c) 2005-2006 Tim Deegan <tjd@phlegethon.org>
 * Copyright (c) 2017 Hannes Mehnert <hannes@mehnert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * dnsloader.ml -- how to build up a DNS trie from separate RRs
 *
 *)

(* State variables for the parser & lexer *)
type parserstate = {
  mutable paren : int ;
  mutable lineno : int ;
  mutable origin : Domain_name.t ;
  mutable ttl : int32 ;
  mutable owner : Domain_name.t ;
  mutable zone : Udns.Name_rr_map.t ;
}

let state = {
  paren = 0 ;
  lineno = 1 ;
  ttl = Int32.of_int 3600 ;
  origin = Domain_name.root ;
  owner = Domain_name.root ;
  zone = Domain_name.Map.empty ;
}

exception Zone_parse_problem of string

