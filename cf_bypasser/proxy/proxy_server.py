"""
HTTP/HTTPS Proxy Server with MITM support and Cloudflare bypass.
"""

import asyncio
import logging
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse

from cf_bypasser.core.bypasser import CamoufoxBypasser
from cf_bypasser.utils.misc import md5_hash
from cf_bypasser.utils.config import BrowserConfig

logger = logging.getLogger(__name__)


class ProxyServer:
    """HTTP/HTTPS proxy server with Cloudflare bypass integration."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        bypasser: Optional[CamoufoxBypasser] = None
    ):
        self.host = host
        self.port = port
        self.bypasser = bypasser or CamoufoxBypasser(max_retries=5, log=True)
        self.server = None
        self.running = False

    async def start(self):
        """Start the proxy server."""
        if self.running:
            logger.warning("Proxy server is already running")
            return

        logger.info(f"Starting HTTP proxy server on {self.host}:{self.port}")

        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        self.running = True
        logger.info(f"Proxy server started successfully on {self.host}:{self.port}")
        
    async def stop(self):
        """Stop the proxy server."""
        if not self.running:
            return
            
        logger.info("Stopping proxy server...")
        self.running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            
        logger.info("Proxy server stopped")
        
    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        """Handle incoming client connection."""
        try:
            # Read the first line of the request
            request_line = await client_reader.readline()
            if not request_line:
                client_writer.close()
                await client_writer.wait_closed()
                return
                
            request_line = request_line.decode('utf-8', errors='ignore').strip()
            logger.info(f"Received request: {request_line}")
            
            # Parse request method and URL
            parts = request_line.split(' ')
            if len(parts) < 3:
                await self.send_error(client_writer, 400, "Bad Request")
                return
                
            method, url, version = parts[0], parts[1], parts[2]
            
            # Handle CONNECT method (HTTPS tunneling)
            if method == 'CONNECT':
                await self.handle_connect(client_reader, client_writer, url)
            else:
                # Handle regular HTTP request
                await self.handle_http(client_reader, client_writer, method, url, request_line)
                
        except Exception as e:
            logger.error(f"Error handling client: {e}", exc_info=True)
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except:
                pass
                
    async def handle_connect(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, url: str):
        """Handle HTTPS CONNECT tunnel."""
        try:
            # Parse host and port
            host_port = url.split(':')
            if len(host_port) != 2:
                await self.send_error(client_writer, 400, "Bad Request")
                return
                
            target_host, target_port = host_port[0], int(host_port[1])
            
            # Read and discard remaining headers
            while True:
                line = await client_reader.readline()
                if not line or line == b'\r\n':
                    break

            # MITM mode: intercept and modify traffic
            logger.info(f"MITM CONNECT to {target_host}:{target_port}")
            await self.handle_mitm_connect(client_reader, client_writer, target_host, target_port)
                
        except Exception as e:
            logger.error(f"Error in CONNECT handler: {e}", exc_info=True)
            await self.send_error(client_writer, 502, "Bad Gateway")

    async def handle_mitm_connect(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int
    ):
        """Handle CONNECT with MITM (currently uses tunnel mode)."""
        # Note: Full MITM requires SSL certificate generation
        # For now, we use tunnel mode (transparent forwarding)
        try:
            # Connect to target server
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)

            # Send 200 Connection Established to client
            client_writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await client_writer.drain()

            # Forward traffic bidirectionally
            await asyncio.gather(
                self.forward_data(client_reader, target_writer, "client->target"),
                self.forward_data(target_reader, client_writer, "target->client")
            )

        except Exception as e:
            logger.error(f"Error in MITM tunnel: {e}")
        finally:
            try:
                target_writer.close()
                await target_writer.wait_closed()
            except:
                pass

    async def handle_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        method: str,
        url: str,
        request_line: str
    ):
        """Handle regular HTTP request with Cloudflare bypass."""
        try:
            # Parse URL
            parsed = urlparse(url)
            if not parsed.scheme:
                # Relative URL, construct full URL
                url = f"http://{url}"
                parsed = urlparse(url)

            hostname = parsed.netloc
            path = parsed.path or '/'
            if parsed.query:
                path += f'?{parsed.query}'

            # Read request headers
            headers = {}
            while True:
                line = await client_reader.readline()
                if not line or line == b'\r\n':
                    break
                line = line.decode('utf-8', errors='ignore').strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            # Read request body if present
            body = b''
            if 'content-length' in headers:
                content_length = int(headers['content-length'])
                body = await client_reader.read(content_length)

            logger.info(f"Proxying {method} {url}")

            # Get or generate Cloudflare cookies
            target_url = f"{parsed.scheme}://{hostname}/"
            cf_data = await self.bypasser.get_or_generate_cookies(target_url)

            if not cf_data:
                logger.warning(f"Failed to get CF cookies for {hostname}, proceeding without bypass")
                cf_cookies = {}
                user_agent = headers.get('user-agent', 'Mozilla/5.0')
            else:
                cf_cookies = cf_data['cookies']
                user_agent = cf_data['user_agent']
                logger.info(f"Using CF cookies for {hostname}")

            # Prepare request headers
            request_headers = {
                'User-Agent': user_agent,
                'Accept': headers.get('accept', '*/*'),
                'Accept-Language': headers.get('accept-language', 'en-US,en;q=0.9'),
                'Accept-Encoding': headers.get('accept-encoding', 'gzip, deflate'),
            }

            # Merge cookies
            existing_cookies = headers.get('cookie', '')
            merged_cookies = self.merge_cookies(existing_cookies, cf_cookies)
            if merged_cookies:
                request_headers['Cookie'] = merged_cookies

            # Add other headers
            for key, value in headers.items():
                if key not in ['host', 'connection', 'proxy-connection', 'cookie', 'user-agent']:
                    request_headers[key.title()] = value

            # Make request using curl_cffi
            from curl_cffi.requests import AsyncSession

            async with AsyncSession(impersonate="firefox") as session:
                response = await session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    data=body if body else None,
                    allow_redirects=False
                )

                # Send response to client
                status_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
                client_writer.write(status_line.encode())

                # Send response headers
                for key, value in response.headers.items():
                    if key.lower() not in ['transfer-encoding', 'connection']:
                        client_writer.write(f"{key}: {value}\r\n".encode())

                client_writer.write(b"Connection: close\r\n")
                client_writer.write(b"\r\n")

                # Send response body
                client_writer.write(response.content)
                await client_writer.drain()

                logger.info(f"Response sent: {response.status_code} for {url}")

        except Exception as e:
            logger.error(f"Error handling HTTP request: {e}", exc_info=True)
            await self.send_error(client_writer, 502, "Bad Gateway")

    async def forward_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str):
        """Forward data from reader to writer."""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logger.debug(f"Forward {direction} ended: {e}")

    def merge_cookies(self, existing: str, new_cookies: Dict[str, str]) -> str:
        """Merge existing cookies with new CF cookies."""
        cookies = {}

        # Parse existing cookies
        if existing:
            for cookie in existing.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[key.strip()] = value.strip()

        # Add new cookies (overwrite if exists)
        cookies.update(new_cookies)

        # Build cookie string
        return '; '.join([f"{k}={v}" for k, v in cookies.items()])

    async def send_error(self, writer: asyncio.StreamWriter, code: int, message: str):
        """Send HTTP error response."""
        try:
            response = f"HTTP/1.1 {code} {message}\r\n"
            response += "Content-Type: text/plain\r\n"
            response += "Connection: close\r\n"
            response += "\r\n"
            response += f"{code} {message}\n"

            writer.write(response.encode())
            await writer.drain()
        except:
            pass

