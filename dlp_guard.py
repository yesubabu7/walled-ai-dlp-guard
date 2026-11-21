"""Walled DLP Guard - standalone desktop DLP for ChatGPT and Perplexity.

    python dlp_guard.py --setup       # one time: create + trust the local certificate (Windows asks)
    python dlp_guard.py               # run (tray icon; Quit or Ctrl+C restores proxy settings)
    python dlp_guard.py --uninstall   # restore proxy settings and remove the certificate

Works with any browser that uses the Windows proxy settings (Chrome, Edge).
"""

import argparse
import asyncio
import atexit
import logging
import sys

from agent import __version__
from agent.logger import LOG_DIR, setup_logging
from agent.policy import pac_script
from agent.scanner import ocr_available

log = logging.getLogger("walled_dlp")


async def run_proxy(args, addon) -> None:
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster

    from agent.system import APP_DIR

    opts = options.Options(listen_host="127.0.0.1", listen_port=args.port, confdir=str(APP_DIR))
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(addon)
    run_proxy.master = master
    await master.run()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--setup", action="store_true", help="create and trust the local certificate")
    parser.add_argument("--uninstall", action="store_true", help="restore proxy settings, remove the certificate")
    parser.add_argument("--port", type=int, default=8899, help="local proxy port")
    parser.add_argument("--pac-port", type=int, default=8898, help="local PAC file port")
    parser.add_argument("--color", default="#f97316", help="colour for AI-generated responses")
    parser.add_argument("--no-system-proxy", action="store_true",
                        help="don't change Windows proxy settings (point a browser at the port manually)")
    parser.add_argument("--no-tray", action="store_true")
    args = parser.parse_args()

    setup_logging()
    from agent import system

    if args.setup:
        ok = system.install_ca()
        print("Setup complete. Now run: python dlp_guard.py" if ok else "Certificate was not installed.")
        return 0 if ok else 1
    if args.uninstall:
        system.restore_proxy()
        system.uninstall_ca()
        print("Proxy settings restored and certificate removed.")
        return 0

    system.restore_proxy()  # recover from a previous run that did not exit cleanly
    system.ensure_ca()
    if not args.no_system_proxy and not system.ca_installed():
        print("The certificate is not trusted yet. Run:  python dlp_guard.py --setup")
        return 1

    from agent.dlp_proxy import DlpAddon

    tray = None

    def stop() -> None:
        master = getattr(run_proxy, "master", None)
        if master is not None:
            master.event_loop.call_soon_threadsafe(master.shutdown)

    if not args.no_tray:
        try:
            from agent.tray import Tray

            tray = Tray(LOG_DIR / "agent.log", on_quit=stop)
            tray.start()
        except Exception as exc:
            log.warning("tray icon unavailable: %s", exc)

    addon = DlpAddon(color=args.color, on_check=tray.record if tray else None)
    system.start_pac_server(args.pac_port, pac_script(args.port))
    if not args.no_system_proxy:
        system.enable_pac(system.pac_url(args.pac_port))
        atexit.register(system.restore_proxy)

    log.info("Walled DLP Guard %s running on 127.0.0.1:%d (OCR %s)", __version__, args.port,
             "available" if ocr_available() else "NOT installed")
    print(f"Walled DLP Guard is running. Protecting ChatGPT and Perplexity. Press Ctrl+C or use the tray icon to quit.")
    try:
        asyncio.run(run_proxy(args, addon))
    except KeyboardInterrupt:
        pass
    finally:
        if not args.no_system_proxy:
            system.restore_proxy()
        if tray is not None:
            tray.stop()
        log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
