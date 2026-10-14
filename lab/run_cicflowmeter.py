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
import sys


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

    from cicflowmeter.sniffer import create_sniffer

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
