"""
MITM HTTPS Proxy with SSL interception and Cloudflare bypass.
"""

import asyncio
import logging
import os
import re
import ssl
import tempfile
from typing import Optional
from urllib.parse import urlparse

from cf_bypasser.core.bypasser import CamoufoxBypasser
from cf_bypasser.core.mirror import RequestMirror
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
        self.mirror = RequestMirror(self.bypasser)
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

        # Cleanup mirror resources
        if self.mirror:
            await self.mirror.cleanup()

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

                # Upgrade the existing connection to TLS using the high-level API
                # This is the correct way - it reuses the existing reader/writer
                await client_writer.start_tls(ssl_context, server_hostname=target_host)

                logger.info(f"✅ SSL handshake completed for {target_host}")

                # Now read the actual HTTP request from the SSL connection
                # Use the SAME reader/writer - they are now TLS-encrypted
                await self.handle_ssl_request(client_reader, client_writer, target_host, target_port)

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
        """Handle decrypted HTTPS request using RequestMirror."""
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

            # Extract query string from path
            query_string = ""
            if '?' in path:
                path, query_string = path.split('?', 1)

            # Prepare headers for RequestMirror (add x-hostname)
            mirror_headers = dict(headers)
            mirror_headers['x-hostname'] = target_host

            logger.info(f"🌐 Proxying {method} to {target_host}{path}")
            if 'x-proxy' in mirror_headers:
                logger.info(f"🔌 x-proxy header detected: {mirror_headers['x-proxy']}")
            if mirror_headers.get('x-bypass-cache', '').lower() in ('true', '1', 'yes', 'on'):
                logger.info(f"🔄 x-bypass-cache header detected")

            # Use RequestMirror to handle the request
            status_code, response_headers, response_content = await self.mirror.mirror_request(
                method=method,
                path=path,
                query_string=query_string,
                headers=mirror_headers,
                body=body
            )

            # Send response back through SSL connection
            await self.send_response_from_mirror(ssl_writer, status_code, response_headers, response_content)
            logger.info(f"✅ Response sent: {status_code} for {target_host}{path}")

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
        """Handle regular HTTP request using RequestMirror."""
        try:
            # Parse URL
            parsed = urlparse(url)
            if not parsed.scheme:
                # Relative URL, construct full URL
                url = f"http://{url}"
                parsed = urlparse(url)

            hostname = parsed.netloc
            path = parsed.path or '/'
            query_string = parsed.query or ''

            # Read headers and body
            headers = await self.read_headers(client_reader)
            body = await self.read_body(client_reader, headers)

            # Prepare headers for RequestMirror (add x-hostname)
            mirror_headers = dict(headers)
            mirror_headers['x-hostname'] = hostname

            logger.info(f"🌐 Proxying {method} to {hostname}{path}")
            if 'x-proxy' in mirror_headers:
                logger.info(f"🔌 x-proxy header detected: {mirror_headers['x-proxy']}")
            if mirror_headers.get('x-bypass-cache', '').lower() in ('true', '1', 'yes', 'on'):
                logger.info(f"🔄 x-bypass-cache header detected")

            # Use RequestMirror to handle the request
            status_code, response_headers, response_content = await self.mirror.mirror_request(
                method=method,
                path=path,
                query_string=query_string,
                headers=mirror_headers,
                body=body
            )

            # Send response to client
            await self.send_response_from_mirror(client_writer, status_code, response_headers, response_content)
            logger.info(f"✅ Response sent: {status_code} for {hostname}{path}")

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

    async def send_response_from_mirror(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        response_headers: list,
        response_content: bytes
    ) -> None:
        """Send HTTP response from RequestMirror (list of tuples format)."""
        status_line = f"HTTP/1.1 {status_code} OK\r\n"
        writer.write(status_line.encode())

        # response_headers is a list of (key, value) tuples from RequestMirror
        for key, value in response_headers:
            writer.write(f"{key}: {value}\r\n".encode())

        writer.write(b"Connection: close\r\n")
        writer.write(b"\r\n")

        # Send response body
        writer.write(response_content)
        await writer.drain()

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

