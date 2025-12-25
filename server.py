#!/usr/bin/env python3

import argparse
import logging
import uvicorn

from cf_bypasser.server.app import create_app


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Cloudflare Bypasser Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    parser.add_argument("--log-level", type=str, default="info", help="Log level")
    parser.add_argument("--proxy-port", type=int, default=8080, help="HTTP proxy server port")
    parser.add_argument("--no-proxy", action="store_true", help="Disable HTTP proxy server")

    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))

    logger = logging.getLogger(__name__)
    logger.info(f"Starting server on {args.host}:{args.port}")

    if not args.no_proxy:
        logger.info(f"HTTP proxy server will start on port {args.proxy_port}")

    app = create_app(enable_proxy=not args.no_proxy, proxy_port=args.proxy_port)

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=args.log_level
    )


if __name__ == "__main__":
    main()