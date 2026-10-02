from flask import Flask, jsonify, request
from flask_cors import CORS
from .keys import KeyManager
from .discovery import OIDCDiscovery


class OIDCServer:
    
    def __init__(self, host="0.0.0.0", port=8080, key_dir="./keys", issuer=None):
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        CORS(self.app)  # Allow CORS for Entra to fetch metadata
        
        # Initialize key manager
        self.key_manager = KeyManager(key_dir=key_dir)
        self.private_key, self.public_key = self.key_manager.load_keys()
        
        # Initialize discovery
        # Use provided issuer or default to http://host:port
        self.issuer_url = issuer if issuer else f"http://{host}:{port}"
        self.discovery = OIDCDiscovery(self.issuer_url)
        
        # Setup routes
        self._setup_routes()
    
    def _setup_routes(self):
        
        @self.app.route('/')
        def index():
            return jsonify({
                "name": "FedForge OIDC Provider",
                "issuer": self.discovery.get_issuer(),
                "discovery": f"{self.discovery.get_issuer()}/.well-known/openid-configuration",
                "jwks": f"{self.discovery.get_issuer()}/jwks",
                "note": "Minimal OIDC provider for Workload Identity Federation exploitation"
            })
        
        @self.app.route('/.well-known/openid-configuration')
        def openid_configuration():
            return jsonify(self.discovery.get_discovery_document())
        
        @self.app.route('/jwks')
        def jwks():
            jwks_data = self.key_manager.get_jwks(self.public_key)
            return jsonify(jwks_data)
        
        @self.app.route('/token', methods=['POST'])
        def token():
            return jsonify({
                "error": "not_implemented",
                "error_description": "FedForge doesn't implement standard OAuth flows. Use the CLI to forge tokens."
            }), 501
        
        @self.app.route('/health')
        def health():
            """Health check endpoint"""
            return jsonify({"status": "ok", "issuer": self.discovery.get_issuer()})
    
    def run(self, debug=False):
        print("\n" + "="*60)
        print("FedForge OIDC Provider")
        print("="*60)
        print(f"[+] Issuer: {self.issuer_url}")
        print(f"[+] Discovery: {self.issuer_url}/.well-known/openid-configuration")
        print(f"[+] JWKS: {self.issuer_url}/jwks")
        print(f"[+] Key ID: {self.key_manager.kid}")
        print("="*60)
        print(f"\n[*] Starting server on {self.host}:{self.port}...")
        print("[*] Press Ctrl+C to stop\n")
        
        self.app.run(host=self.host, port=self.port, debug=debug)
    
    def get_private_key(self):
        return self.private_key
    
    def get_kid(self):
        return self.key_manager.kid


def create_server(host="0.0.0.0", port=8080, key_dir="./keys", issuer=None):
    return OIDCServer(host=host, port=port, key_dir=key_dir, issuer=issuer)