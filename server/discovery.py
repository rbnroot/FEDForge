"""
FedForge - OIDC Discovery
Generates OIDC discovery document for the provider
"""


class OIDCDiscovery:
    """Generates OIDC discovery metadata"""
    
    def __init__(self, issuer_url):
        self.issuer_url = issuer_url.rstrip('/')
    
    def get_discovery_document(self):
        """
        Generate OpenID Connect discovery document
        This is what clients fetch from /.well-known/openid-configuration
        
        We only implement the bare minimum needed for Entra WIF to work
        """
        return {
            "issuer": self.issuer_url,
            "jwks_uri": f"{self.issuer_url}/jwks",
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            # Optional but helpful for compatibility
            "token_endpoint": f"{self.issuer_url}/token",
            "authorization_endpoint": f"{self.issuer_url}/authorize",
        }
    
    def get_issuer(self):
        """Get the issuer URL"""
        return self.issuer_url