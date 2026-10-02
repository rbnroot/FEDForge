import jwt
import time
from datetime import datetime, timedelta


class TokenForge:
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
    
    def decode_token(self, token, verify=False, public_key=None):
        if verify:
            # Check the signature without requiring audience or time claims
            key = public_key if public_key is not None else self.private_key.public_key()
            decoded = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_sub": False,
                    "verify_jti": False
                }
            )
        else:
            # Just decode without verification
            decoded = jwt.decode(
                token,
                options={"verify_signature": False}
            )
        
        return decoded
    
    def print_token_info(self, token):
        try:
            decoded = self.decode_token(token, verify=False)
            
            print("\n" + "="*60)
            print("Token Information")
            print("="*60)
            print(f"Issuer (iss):     {decoded.get('iss')}")
            print(f"Subject (sub):    {decoded.get('sub')}")
            print(f"Audience (aud):   {decoded.get('aud')}")
            
            if 'iat' in decoded:
                iat = datetime.fromtimestamp(decoded['iat'])
                print(f"Issued At (iat):  {iat.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if 'exp' in decoded:
                exp = datetime.fromtimestamp(decoded['exp'])
                print(f"Expires (exp):    {exp.strftime('%Y-%m-%d %H:%M:%S')}")
                
                now = datetime.now()
                if exp > now:
                    remaining = exp - now
                    print(f"Time Remaining:   {remaining}")
                else:
                    print(f"Status:           EXPIRED")
            
            standard_claims = {'iss', 'sub', 'aud', 'exp', 'iat', 'nbf'}
            additional = {k: v for k, v in decoded.items() if k not in standard_claims}
            
            if additional:
                print("\nAdditional Claims:")
                for key, value in additional.items():
                    print(f"  {key}: {value}")
            
            print("="*60 + "\n")
            
        except Exception as e:
            print(f"[!] Error decoding token: {e}")
