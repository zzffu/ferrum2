# M14 SOCKS5 UDP ASSOCIATE routing-granularity semantics

- **Status:** Planning research note
- **Date:** 2026-08-08
- **Milestone:** M14
- **Question:** May one outbound be selected from the first valid datagram for a whole SOCKS UDP
  association while later datagrams keep their own destinations?

## Conclusion

Yes. RFC 1928 explicitly puts a desired destination in **each** SOCKS UDP datagram and describes
the relay's forward/drop decision for a datagram. It does not define an outbound, route, proxy
chain, or rule-selection lifetime。Therefore both per-datagram selection and one association-wide
outbound are standards-consistent internal policies。M14 chooses the latter：the first valid datagram
selects once，while every later datagram still supplies the remote target forwarded through that
selected outbound。This is a ferrum2/sing-box-aligned policy choice，not an RFC requirement。

The control request's `DST.ADDR`/`DST.PORT` must not be used as the remote target: for
`UDP ASSOCIATE` they describe the client endpoint expected to send UDP for the association. The
remote target comes from each UDP request header.

## Source status

- The RFC Editor and IETF Datatracker classify RFC 1928 as an IETF **Proposed Standard**; neither
  lists an RFC that updates or obsoletes it. Sources: [RFC Editor record](https://www.rfc-editor.org/info/rfc1928/),
  [IETF Datatracker](https://datatracker.ietf.org/doc/rfc1928/).
- The one verified technical correction, [Erratum 3198](https://errata.rfc-editor.org/eid3198/),
  changes IPv6 UDP API headroom from 20 to 22 octets. Reported (not verified)
  [Erratum 8867](https://errata.rfc-editor.org/eid8867/) concerns only BIND wording. Neither changes
  association, target, or routing semantics.
- `draft-vance-socks5-frag-deprecation-00` proposes requiring `FRAG=0`, but Datatracker identifies it
  as an individual Internet-Draft with no formal standing. As of this note it does not update RFC
  1928. Source: [IETF Datatracker](https://datatracker.ietf.org/doc/draft-vance-socks5-frag-deprecation/).

No implementation source is needed to interpret these requirements.

## Explicit RFC 1928 requirements and permissions

| Topic | What RFC 1928 says | Source |
|---|---|---|
| Association request | `UDP ASSOCIATE` establishes an association in the UDP relay. Its `DST.ADDR`/`DST.PORT` are the address and port the client expects to use to send association datagrams. The server **MAY** use the hint to limit access. If the client does not yet know them, both must be all zero. | [§6, UDP ASSOCIATE](https://www.rfc-editor.org/rfc/rfc1928.html#section-6) |
| Relay endpoint | In the reply, `BND.ADDR`/`BND.PORT` identify where the client **MUST** send UDP request messages for relay. The RFC does not prescribe socket topology or whether associations share a relay socket. | [§6](https://www.rfc-editor.org/rfc/rfc1928.html#section-6) |
| Control lifetime | The UDP association terminates when the TCP connection carrying its `UDP ASSOCIATE` request terminates. Idle expiry, half-close interpretation, and shutdown mechanics are not specified. | [§6](https://www.rfc-editor.org/rfc/rfc1928.html#section-6) |
| Per-datagram target | Every client datagram carries `RSV[2]`, `FRAG`, `ATYP`, `DST.ADDR`, `DST.PORT`, and `DATA`; those destination fields are the desired destination of that datagram. | [§7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7) |
| Forward/drop | Relaying is silent, with no success notice. A datagram the relay cannot or will not relay is dropped; RFC 1928 defines no UDP error datagram. A remote reply must be encapsulated in the SOCKS UDP header. | [§7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7) |
| Sender filtering | The UDP relay **MUST** obtain the expected client IP from the SOCKS server and **MUST** drop datagrams from every other source IP. The RFC does not mandate source-port filtering; using the request hint to impose a stronger endpoint restriction is permitted by the §6 **MAY**. | [§6](https://www.rfc-editor.org/rfc/rfc1928.html#section-6), [§7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7) |
| Fragmentation | `FRAG=0` means standalone. Reassembly is optional. If implemented, the high bit marks the end, positions are 1–127, state is reset on timeout or a lower fragment number, and the timer is at least five seconds. If not implemented, every `FRAG != 0` datagram **MUST** be dropped. | [§7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7) |
| Reserved bytes | The wire format sets UDP `RSV` to `0x0000`. The RFC does not state a distinct receiver response for nonzero `RSV`; silently dropping it as malformed/unwilling-to-relay is a stricter fail-closed policy. | [§7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7) |

## Careful inference: variable targets and routing granularity

RFC 1928 does not literally say “targets may vary.” That conclusion follows from three explicit
facts: the association request names the client's sending endpoint, every datagram independently
contains a desired destination, and no text requires successive headers to repeat a destination.
The wire model therefore permits different targets in one association. Because a relay may decline
an individual datagram, this does not mean it must accept every target.

The RFC also never models an internal outbound or route. It neither requires per-association pinning
nor requires per-datagram route selection. Choosing a route from the validated header target (and
choosing a different route for a later datagram) is consequently an implementation policy behind an
unchanged SOCKS wire contract.

Only client **IP** filtering is an explicit MUST. Deriving that IP from the authenticated TCP peer,
pinning a source port, validating all header fields before state mutation, and dropping nonzero `RSV`
are sensible ferrum2 security rules, but must not be presented as verbatim RFC requirements.

## M14 comparison

| M14 behavior | RFC assessment |
|---|---|
| Validate source/header before first association evaluation | Consistent. It enforces the mandatory source-IP boundary and the chosen no-fragment profile before policy; the exact validation/mutation order is ferrum2's stronger contract. |
| Select one outbound from the first valid datagram | Consistent but not mandated. RFC 1928 does not prescribe route lifetime; later datagrams must still retain their own target headers. |
| Keep later destinations variable through the selected outbound | Consistent with the per-datagram target model. Outbound pinning must not become first-target pinning. |
| `reject` by silent datagram drop/association termination | Consistent with the RFC's lack of a UDP error reply; association termination is an implementation policy. |
| Borrow-inspect the first valid DNS payload before selecting an action | Internal policy is unspecified by RFC 1928 and does not alter compliance if bounds, wire behavior, and lifetime remain intact. |
| `hijack-dns` and return a locally generated response using the request target | RFC 1928 specifies encapsulation of replies received from remote hosts, but does not discuss locally synthesized replies or fully define response-header address semantics. Treat this as a ferrum2 extension requiring its own interop evidence, not as an explicit RFC guarantee. |
| Create Shadowsocks state only for a terminal route action | Entirely internal and RFC-neutral. |
| Tear down all action-specific state with the TCP control connection | Required at the association boundary by §6. |

Accordingly，M14 may make route/reject/hijack association-terminal and select at most one outbound while
remaining compatible with the RFC wire model。It must not claim that RFC 1928 requires association-level
routing or standardizes local DNS hijacking；the standards claim is only that this internal granularity
preserves each datagram's target and the required association/source/wire behavior。
