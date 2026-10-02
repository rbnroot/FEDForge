import requests
import json
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree


class TokenExchangeEntra:
    
    def __init__(self):
        self.token_endpoint_template = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    
    def exchange(
        self,
        federated_token,
        tenant_id,
        client_id,
        scope="https://graph.microsoft.com/.default"
    ):
        token_url = self.token_endpoint_template.format(tenant_id=tenant_id)
        
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
                print("Token Exchange Successful!")
                print("="*60)
                
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
                print(" Token Exchange Failed")
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
    
    def save_token(self, token_data, filename="entra-access-token.json"):
        try:
            with open(filename, 'w') as f:
                json.dump(token_data, f, indent=2)
            print(f"[+] Token saved to {filename}")
            return True
        except Exception as e:
            print(f"[!] Error saving token: {e}")
            return False
    
    def load_token(self, filename="entra-access-token.json"):
        try:
            with open(filename, 'r') as f:
                token_data = json.load(f)
            
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

class TokenExchangeGCP:
    
    def __init__(self):
        self.sts_endpoint = "https://sts.googleapis.com/v1/token"
        self.sa_endpoint = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account}:generateAccessToken"
    
    def exchange(
        self,
        federated_token,
        project_number,
        pool_id,
        provider_id,
        service_account,
        scope="https://www.googleapis.com/auth/cloud-platform"
    ):
        print(f"[*] Starting GCP token exchange...")
        print(f"[*] Project Number: {project_number}")
        print(f"[*] Pool ID: {pool_id}")
        print(f"[*] Provider ID: {provider_id}")
        print(f"[*] Service Account: {service_account}")
        
        print(f"\n[*] Step 1: Exchanging federated token for STS token...")
        sts_result = self.exchange_for_sts_token(
            federated_token,
            project_number,
            pool_id,
            provider_id
        )
        
        if not sts_result["success"]:
            return sts_result
        
        sts_token = sts_result["access_token"]
        print(f"[+] STS token obtained successfully")
        
        print(f"\n[*] Step 2: Exchanging STS token for Service Account token...")
        sa_result = self.exchange_for_sa_token(
            sts_token,
            service_account,
            scope
        )
        
        if not sa_result["success"]:
            return sa_result
        
        print("\n" + "="*60)
        print("Token Exchange Successful!")
        print("="*60)
        print(f"Token Type:    {sa_result.get('token_type', 'Bearer')}")
        print(f"Expires In:    {sa_result.get('expires_in')} seconds ({sa_result.get('expires_in', 0)//60} minutes)")
        print(f"Expires At:    {sa_result.get('expires_at')}")
        print("="*60 + "\n")
        
        return sa_result
    
    def exchange_for_sts_token(self, federated_token, project_number, pool_id, provider_id):
        audience = f"//iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}"
        
        data = {
            "audience": audience,
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
            "subjectToken": federated_token
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(self.sts_endpoint, json=data, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "access_token": result.get("access_token"),
                    "token_type": result.get("token_type"),
                    "expires_in": result.get("expires_in")
                }
            else:
                error_data = response.json() if response.text else {}
                print("\n" + "="*60)
                print("STS Token Exchange Failed")
                print("="*60)
                print(f"Status Code:   {response.status_code}")
                print(f"Error:         {error_data.get('error', 'Unknown')}")
                print(f"Description:   {error_data.get('error_description', response.text)}")
                print("="*60 + "\n")
                
                return {
                    "success": False,
                    "error": error_data.get("error", "sts_exchange_failed"),
                    "error_description": error_data.get("error_description", response.text),
                    "status_code": response.status_code
                }
        
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Network error during STS exchange: {e}")
            return {
                "success": False,
                "error": "network_error",
                "error_description": str(e)
            }
        except Exception as e:
            print(f"\n[!] Unexpected error during STS exchange: {e}")
            return {
                "success": False,
                "error": "unexpected_error",
                "error_description": str(e)
            }
    
    def exchange_for_sa_token(self, sts_token, service_account, scope):
        sa_url = self.sa_endpoint.format(service_account=service_account)
        
        data = {
            "scope": [scope]
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {sts_token}"
        }
        
        try:
            response = requests.post(sa_url, json=data, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                
                expires_at_str = result.get('expireTime')
                if expires_at_str:
                    expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    expires_in = int((expires_at - now).total_seconds())
                else:
                    expires_in = 3600
                    now = datetime.now(timezone.utc)
                    expires_at = now + timedelta(seconds=3600)
                
                return {
                    "success": True,
                    "access_token": result.get("accessToken"),
                    "token_type": "Bearer",
                    "expires_in": expires_in,
                    "expires_at": expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                    "scope": scope
                }
            else:
                error_data = response.json() if response.text else {}
                print("\n" + "="*60)
                print("✗ Service Account Token Exchange Failed")
                print("="*60)
                print(f"Status Code:   {response.status_code}")
                print(f"Error:         {error_data.get('error', {}).get('code', 'Unknown')}")
                print(f"Message:       {error_data.get('error', {}).get('message', response.text)}")
                print("="*60 + "\n")
                
                return {
                    "success": False,
                    "error": error_data.get("error", {}).get("code", "sa_exchange_failed"),
                    "error_description": error_data.get("error", {}).get("message", response.text),
                    "status_code": response.status_code
                }
        
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Network error during SA token exchange: {e}")
            return {
                "success": False,
                "error": "network_error",
                "error_description": str(e)
            }
        except Exception as e:
            print(f"\n[!] Unexpected error during SA token exchange: {e}")
            return {
                "success": False,
                "error": "unexpected_error",
                "error_description": str(e)
            }
    
    def save_token(self, token_data, filename="gcp-access-token.json"):
        try:
            with open(filename, 'w') as f:
                json.dump(token_data, f, indent=2)
            print(f"[+] Token saved to {filename}")
            return True
        except Exception as e:
            print(f"[!] Error saving token: {e}")
            return False
    
    def load_token(self, filename="gcp-access-token.json"):
        try:
            with open(filename, 'r') as f:
                token_data = json.load(f)
            
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

class TokenExchangeAWS:
    
    def __init__(self):
        self.sts_endpoint = "https://sts.amazonaws.com/"
    
    def exchange(
        self,
        federated_token,
        role_arn,
        session_name="fedforge-session"
    ):
        print("[*] Starting AWS token exchange...")
        print(f"[*] Role ARN: {role_arn}")
        print(f"[*] Session Name: {session_name}")

        # AWS STS accepts form-encoded Query API parameters and returns XML
        data = {
            "Action": "AssumeRoleWithWebIdentity",
            "Version": "2011-06-15",
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "WebIdentityToken": federated_token
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            response = requests.post(self.sts_endpoint, data=data, headers=headers, timeout=30)
            root = ElementTree.fromstring(response.content)

            if response.status_code == 200:
                result = root.find(".//{*}AssumeRoleWithWebIdentityResult")
                credentials = result.find("{*}Credentials") if result is not None else None

                if credentials is None:
                    raise ValueError("AWS STS response did not include credentials")

                access_key_id = credentials.findtext("{*}AccessKeyId")
                secret_access_key = credentials.findtext("{*}SecretAccessKey")
                session_token = credentials.findtext("{*}SessionToken")
                expiration = credentials.findtext("{*}Expiration")

                if not all((access_key_id, secret_access_key, session_token, expiration)):
                    raise ValueError("AWS STS response contained incomplete credentials")

                assumed_role_user = result.find("{*}AssumedRoleUser")
                assumed_role_arn = assumed_role_user.findtext("{*}Arn") if assumed_role_user is not None else None

                print("\n" + "="*60)
                print("AWS Token Exchange Successful!")
                print("="*60)
                print(f"Assumed Role:  {assumed_role_arn or role_arn}")
                print(f"Expires At:    {expiration}")
                print("="*60 + "\n")

                return {
                    "success": True,
                    "AccessKeyId": access_key_id,
                    "SecretAccessKey": secret_access_key,
                    "SessionToken": session_token,
                    "Expiration": expiration,
                    "AssumedRoleArn": assumed_role_arn
                }
            else:
                error_data = root.find(".//{*}Error")
                error = error_data.findtext("{*}Code") if error_data is not None else "sts_exchange_failed"
                error_description = error_data.findtext("{*}Message") if error_data is not None else "AWS STS request failed"

                print("\n" + "="*60)
                print("AWS Token Exchange Failed")
                print("="*60)
                print(f"Status Code:   {response.status_code}")
                print(f"Error:         {error}")
                print(f"Description:   {error_description}")
                print("="*60 + "\n")

                return {
                    "success": False,
                    "error": error,
                    "error_description": error_description,
                    "status_code": response.status_code
                }

        except requests.exceptions.RequestException as e:
            print(f"\n[!] Network error during AWS token exchange: {e}")
            return {
                "success": False,
                "error": "network_error",
                "error_description": str(e)
            }
        except (ElementTree.ParseError, ValueError) as e:
            print(f"\n[!] Invalid AWS STS response: {e}")
            return {
                "success": False,
                "error": "invalid_response",
                "error_description": str(e)
            }
    
    def save_token(self, token_data, filename="aws-credentials.json"):
        try:
            with open(filename, 'w') as f:
                json.dump(token_data, f, indent=2)
            print(f"[+] Credentials saved to {filename}")
            return True
        except Exception as e:
            print(f"[!] Error saving credentials: {e}")
            return False
    
    def load_token(self, filename="aws-credentials.json"):
        try:
            with open(filename, 'r') as f:
                token_data = json.load(f)
            
            if 'Expiration' in token_data:
                expiration = datetime.fromisoformat(token_data['Expiration'].replace('Z', '+00:00'))
                now = datetime.now(expiration.tzinfo)
                if now > expiration:
                    print(f"[!] Warning: Credentials expired at {expiration}")
                else:
                    remaining = expiration - now
                    print(f"[+] Credentials valid for {remaining}")
            
            return token_data
        except FileNotFoundError:
            print(f"[!] Credentials file not found: {filename}")
            return None
        except Exception as e:
            print(f"[!] Error loading credentials: {e}")
            return None
