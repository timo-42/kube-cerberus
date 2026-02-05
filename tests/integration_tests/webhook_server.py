"""
Test webhook server for integration tests.
Implements a complete HTTPS admission webhook server.
"""
import json
import ssl
import threading
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

from kube_cerberus.registry import REGISTRY


logger = logging.getLogger(__name__)


class AdmissionWebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler for Kubernetes admission webhook requests."""
    
    def log_message(self, format, *args):
        """Override to use proper logging."""
        logger.info(format % args)
    
    def do_POST(self):
        """Handle POST requests with AdmissionReview."""
        try:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            admission_review = json.loads(body)
            
            request_uid = admission_review.get('request', {}).get('uid', 'unknown')
            logger.info(f"Received admission request: {request_uid}")
            
            # Process with registry
            response = REGISTRY.process_admission_review(admission_review)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
            allowed = response['response']['allowed']
            logger.info(f"Sent response for {request_uid}: allowed={allowed}")
            
        except Exception as e:
            logger.error(f"Error processing request: {e}", exc_info=True)
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            error_response = {
                "error": str(e)
            }
            self.wfile.write(json.dumps(error_response).encode())


class WebhookServer:
    """Manages the webhook server lifecycle."""
    
    def __init__(
        self, 
        host: str = '0.0.0.0', 
        port: int = 8443, 
        cert_file: Optional[str] = None, 
        key_file: Optional[str] = None
    ):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start the webhook server in a background thread."""
        self.server = HTTPServer((self.host, self.port), AdmissionWebhookHandler)
        
        # Setup SSL if certificates provided
        if self.cert_file and self.key_file:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.cert_file, self.key_file)
            self.server.socket = context.wrap_socket(
                self.server.socket, 
                server_side=True
            )
            logger.info(f"Webhook server configured with SSL")
        
        self.thread = threading.Thread(
            target=self.server.serve_forever, 
            daemon=True
        )
        self.thread.start()
        logger.info(f"Webhook server started on {self.host}:{self.port}")
    
    def stop(self):
        """Stop the webhook server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Webhook server stopped")
    
    @property
    def url(self) -> str:
        """Get the server URL."""
        protocol = "https" if self.cert_file else "http"
        return f"{protocol}://{self.host}:{self.port}"
