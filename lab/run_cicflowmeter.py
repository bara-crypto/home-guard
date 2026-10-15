"""HomeGuard AI - robust wrapper around cicflowmeter's flow extractor.

WHY THIS EXISTS: the installed cicflowmeter 0.5.0 CLI (`main()` in
cicflowmeter/sniffer.py) calls create_sniffer() with MISALIGNED positional
arguments -- it passes `args.fields` into the `input_directory` parameter and
`args.verbose` (a bool) into the `fields` parameter, so create_sniffer then does
`False.split(",")` and crashes with AttributeError for BOTH `-f` (file) and `-i`
(interface) modes. The CLI is therefore unusable as shipped.

This wrapper uses the SAME library (cicflowmeter.sniffer.create_sniffer) but
passes arguments by KEYWORD, which is correct. Same flags as the real CLI:

    python lab/run_cicflowmeter.py -f input.pcap -c output.csv
    python lab/run_cicflowmeter.py -i "Wi-Fi"  -u http://127.0.0.1:8001/predict

If a future cicflowmeter release fixes the CLI, callers can switch back to the
plain `cicflowmeter` binary with no other changes.
"""
import argparse
import os
import sys


def _apply_emit_threshold() -> None:
    """Lower the flow-emit idle threshold for faster live alerts.

    cicflowmeter writes a flow only once it has been idle for EXPIRED_UPDATE
    seconds (240 by default) OR has lasted >= 90s, so short attack bursts are not
    reported until ~4 minutes later. Setting HOMEGUARD_FLOW_IDLE_SECS (e.g. 8)
    makes the periodic GC flush idle flows within a few seconds. The default keeps
    upstream behavior. Use the SAME value for offline conversion (lab/convert.py)
    and the live agent so train and serve behavior match.
    """
    import cicflowmeter.flow_session as _fs

    _fs.EXPIRED_UPDATE = float(os.environ.get("HOMEGUARD_FLOW_IDLE_SECS", "240"))


def main() -> int:
    ap = argparse.ArgumentParser(description="cicflowmeter wrapper (keyword-correct call).")
    g_in = ap.add_mutually_exclusive_group(required=True)
    g_in.add_argument("-i", "--interface", dest="interface")
    g_in.add_argument("-f", "--file", dest="file")
    g_in.add_argument("-d", "--directory", dest="directory")
    g_out = ap.add_mutually_exclusive_group(required=True)
    g_out.add_argument("-c", "--csv", action="store_const", const="csv", dest="mode")
    g_out.add_argument("-u", "--url", action="store_const", const="url", dest="mode")
    ap.add_argument("output", help="csv path (csv mode) or url (url mode)")
    ap.add_argument("--fields", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    from scapy.sendrecv import AsyncSniffer

    from cicflowmeter.flow_session import FlowSession
    from cicflowmeter.sniffer import GC_INTERVAL, _start_periodic_gc, create_sniffer

    _apply_emit_threshold()

    if args.file:
        # create_sniffer() hardcodes a BPF filter ("ip and (tcp or udp)"). On an
        # OFFLINE pcap, scapy applies filters via the external `tcpdump` binary,
        # which is NOT present on a plain Windows box (Npcap only covers live
        # capture), so `-f` fails with "tcpdump is not available". Reading with
        # filter=None uses scapy's own pcap parser (no tcpdump); FlowSession.process
        # already ignores non-TCP/UDP packets, so the result is identical. Live
        # `-i` capture still goes through create_sniffer (Npcap does live BPF).
        fields = args.fields.split(",") if args.fields else None
        session = FlowSession(
            output_mode=args.mode,
            output=args.output,
            fields=fields,
            verbose=args.verbose,
        )
        _start_periodic_gc(session, interval=GC_INTERVAL)
        sniffer = AsyncSniffer(
            offline=args.file,
            filter=None,
            prn=session.process,
            store=False,
        )
    else:
        sniffer, session = create_sniffer(
            input_file=args.file,
            input_interface=args.interface,
            input_directory=args.directory,
            output_mode=args.mode,
            output=args.output,
            fields=args.fields,       # correctly placed (the broken CLI swaps this)
            verbose=args.verbose,
        )
    sniffer.start()
    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        try:
            sniffer.join()
        except Exception:
            pass
        session.flush_flows()
    return 0


if __name__ == "__main__":
    sys.exit(main())
