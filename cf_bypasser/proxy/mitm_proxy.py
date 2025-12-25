"""
MITM HTTPS Proxy with SSL interception and Cloudflare bypass.
"""

import asyncio
import logging
import ssl
from typing import Optional
from urllib.parse import urlparse

from cf_bypasser.core.bypasser import CamoufoxBypasser
from cf_bypasser.proxy.cert_manager import CertificateManager

logger = logging.getLogger(__name__)


class MITMProxyServer:
    """MITM HTTPS Proxy with SSL interception and CF bypass."""
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        bypasser: Optional[CamoufoxBypasser] = None
    ):
        """Initialize MITM proxy server."""
        self.host = host
        self.port = port
        self.bypasser = bypasser or CamoufoxBypasser(log=True)
        self.cert_manager = CertificateManager()
        self.server = None
        self.running = False

        logger.info(f"MITM Proxy initialized on {host}:{port}")
    
    async def start(self):
        """Start the MITM proxy server."""
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )

        self.running = True
        logger.info(f"🚀 MITM Proxy server started on {self.host}:{self.port}")
        logger.info(f"📜 CA Certificate: {self.cert_manager.get_ca_certificate_path()}")
        logger.info(f"⚠️  Install this certificate in your browser to enable HTTPS interception")

        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        """Stop the MITM proxy server."""
        if self.server:
            self.running = False
            self.server.close()
            await self.server.wait_closed()
        logger.info("MITM Proxy server stopped")
    
    async def handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter
    ):
        """Handle incoming client connection."""
        try:
            # Read the first line of the request
            request_line = await client_reader.readline()
            if not request_line:
                client_writer.close()
                await client_writer.wait_closed()
                return
            
            request_line = request_line.decode('utf-8', errors='ignore').strip()
            logger.info(f"📨 Received: {request_line}")
            
            # Parse request
            parts = request_line.split(' ')
            if len(parts) < 3:
                await self.send_error(client_writer, 400, "Bad Request")
                return
            
            method, url, version = parts[0], parts[1], parts[2]
            
            # Handle CONNECT method (HTTPS)
            if method == 'CONNECT':
                await self.handle_mitm_connect(client_reader, client_writer, url)
            else:
                # Handle regular HTTP/HTTPS request
                await self.handle_http_request(client_reader, client_writer, method, url, request_line)
        
        except Exception as e:
            logger.error(f"Error handling client: {e}", exc_info=True)
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except:
                pass
    
    async def handle_mitm_connect(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        url: str
    ):
        """Handle CONNECT request with SSL interception."""
        try:
            # Parse host and port
            host_port = url.split(':')
            if len(host_port) != 2:
                await self.send_error(client_writer, 400, "Bad Request")
                return
            
            target_host, target_port = host_port[0], int(host_port[1])
            
            logger.info(f"🔐 MITM CONNECT to {target_host}:{target_port}")
            
            # Read and discard client headers
            while True:
                line = await client_reader.readline()
                if not line or line == b'\r\n':
                    break
            
            # Send 200 Connection Established
            client_writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await client_writer.drain()

            logger.info(f"🔒 Performing SSL handshake with client for {target_host}")

            # Generate SSL certificate for this domain
            cert_pem, key_pem = self.cert_manager.generate_domain_certificate(target_host)

            # Create SSL context for client connection
            from cryptography.hazmat.primitives import serialization

            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            # Load certificate and key from memory using a temporary file approach
            # (Python's ssl module requires file paths, so we still need temp files)
            import tempfile
            import os

            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as key_file:
                key_file.write(key_pem)
                key_path = key_file.name

            try:
                ssl_context.load_cert_chain(cert_path, key_path)
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                # Get the transport and upgrade to TLS
                loop = asyncio.get_event_loop()
                transport = client_writer.transport
                protocol = transport.get_protocol()

                # Perform TLS upgrade
                new_transport = await loop.start_tls(
                    transport,
                    protocol,
                    ssl_context,
                    server_side=True,
                    server_hostname=None
                )

                logger.info(f"✅ SSL handshake completed for {target_host}")

                # Create new reader/writer for the TLS connection
                ssl_reader = asyncio.StreamReader(loop=loop)
                ssl_protocol = asyncio.StreamReaderProtocol(ssl_reader, loop=loop)
                new_transport.set_protocol(ssl_protocol)
                ssl_writer = asyncio.StreamWriter(new_transport, ssl_protocol, ssl_reader, loop)

                # Now read the actual HTTP request from the SSL connection
                await self.handle_ssl_request(ssl_reader, ssl_writer, target_host, target_port)

            finally:
                # Cleanup temp files
                try:
                    os.unlink(cert_path)
                    os.unlink(key_path)
                except:
                    pass

        except Exception as e:
            logger.error(f"Error in MITM CONNECT: {e}", exc_info=True)
            await self.send_error(client_writer, 502, "Bad Gateway")

    async def handle_ssl_request(
        self,
        ssl_reader: asyncio.StreamReader,
        ssl_writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int
    ):
        """Handle decrypted HTTPS request."""
        try:
            # Read HTTP request from SSL connection
            request_line = await ssl_reader.readline()
            if not request_line:
                return

            request_line = request_line.decode('utf-8', errors='ignore').strip()
            logger.info(f"🔓 Decrypted request: {request_line}")

            # Parse request
            parts = request_line.split(' ')
            if len(parts) < 3:
                return

            method, path, version = parts[0], parts[1], parts[2]

            # Read headers and body
            headers = await self.read_headers(ssl_reader)
            body = await self.read_body(ssl_reader, headers)

            # Construct full URL
            scheme = 'https' if target_port == 443 else 'http'
            url = f"{scheme}://{target_host}{path}"

            logger.info(f"🌐 Proxying {method} {url}")

            # Get CF cookies and user agent
            target_url = f"{scheme}://{target_host}/"
            cf_cookies, user_agent = await self.get_cf_data(target_url, headers)

            # Prepare request headers
            request_headers = self.prepare_request_headers(headers, user_agent, cf_cookies)

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

                # Send response back through SSL connection
                await self.send_response(ssl_writer, response)
                logger.info(f"✅ Response sent: {response.status_code} for {url}")

        except Exception as e:
            logger.error(f"Error handling SSL request: {e}", exc_info=True)

    async def handle_http_request(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        method: str,
        url: str,
        request_line: str
    ):
        """Handle regular HTTP request (or HTTPS URL via HTTP proxy)."""
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

            # Read headers and body
            headers = await self.read_headers(client_reader)
            body = await self.read_body(client_reader, headers)

            logger.info(f"🌐 Proxying {method} {url}")

            # Get CF cookies and user agent
            target_url = f"{parsed.scheme}://{hostname}/"
            cf_cookies, user_agent = await self.get_cf_data(target_url, headers)

            # Prepare request headers
            request_headers = self.prepare_request_headers(headers, user_agent, cf_cookies)

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
                await self.send_response(client_writer, response)
                logger.info(f"✅ Response sent: {response.status_code} for {url}")

        except Exception as e:
            logger.error(f"Error handling HTTP request: {e}", exc_info=True)
            await self.send_error(client_writer, 502, "Bad Gateway")

    async def read_headers(self, reader: asyncio.StreamReader) -> dict:
        """Read HTTP headers from stream."""
        headers = {}
        while True:
            line = await reader.readline()
            if not line or line == b'\r\n':
                break
            line = line.decode('utf-8', errors='ignore').strip()
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        return headers

    async def read_body(self, reader: asyncio.StreamReader, headers: dict) -> bytes:
        """Read HTTP body from stream based on Content-Length header."""
        body = b''
        if 'content-length' in headers:
            content_length = int(headers['content-length'])
            body = await reader.read(content_length)
        return body

    async def get_cf_data(self, target_url: str, headers: dict) -> tuple:
        """Get Cloudflare cookies and user agent for target URL."""
        cf_data = await self.bypasser.get_or_generate_cookies(target_url)

        if not cf_data:
            hostname = urlparse(target_url).netloc
            logger.warning(f"Failed to get CF cookies for {hostname}")
            return {}, headers.get('user-agent', 'Mozilla/5.0')

        logger.info(f"✅ Using CF cookies: {list(cf_data['cookies'].keys())}")
        return cf_data['cookies'], cf_data['user_agent']

    def prepare_request_headers(self, headers: dict, user_agent: str, cf_cookies: dict) -> dict:
        """Prepare request headers with CF cookies merged."""
        request_headers = {
            'User-Agent': user_agent,
            'Accept': headers.get('accept', '*/*'),
            'Accept-Language': headers.get('accept-language', 'en-US,en;q=0.9'),
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

        return request_headers

    async def send_response(self, writer: asyncio.StreamWriter, response) -> None:
        """Send HTTP response to client."""
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
        writer.write(status_line.encode())

        # Send response headers
        for key, value in response.headers.items():
            if key.lower() not in ['transfer-encoding', 'connection']:
                writer.write(f"{key}: {value}\r\n".encode())

        writer.write(b"Connection: close\r\n")
        writer.write(b"\r\n")

        # Send response body
        writer.write(response.content)
        await writer.drain()

    def merge_cookies(self, existing: str, new_cookies: dict) -> str:
        """Merge existing cookies with new CF cookies."""
        cookies = {}

        # Parse existing cookies
        if existing:
            for cookie in existing.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    cookies[name.strip()] = value.strip()

        # Add new cookies (overwrite if exists)
        cookies.update(new_cookies)

        # Return merged cookies
        return '; '.join([f"{k}={v}" for k, v in cookies.items()])

    async def send_error(self, writer: asyncio.StreamWriter, code: int, message: str, body: str = ""):
        """Send HTTP error response."""
        try:
            response = f"HTTP/1.1 {code} {message}\r\n"
            response += "Content-Type: text/plain\r\n"
            response += "Connection: close\r\n"
            response += f"Content-Length: {len(body)}\r\n"
            response += "\r\n"
            if body:
                response += body

            writer.write(response.encode())
            await writer.drain()
        except:
            pass

