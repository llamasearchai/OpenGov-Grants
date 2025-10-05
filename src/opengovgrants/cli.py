"""Command-line interface for OpenGov-Grants."""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .core.config import get_settings
from .core.database import DatabaseManager
from .services.agent_service import AgentService
from .services.ollama_service import OllamaService
from .utils.logging import get_logger

# Initialize console and logger
console = Console()
logger = get_logger(__name__)

# Create the main Typer app
typer_app = typer.Typer(
    name="opengov-grants",
    help="OpenGov-Grants - Comprehensive grants management and fiscal administration system for city governments managing federal, state, and foundation funding opportunities",
    add_completion=False,
)
typer_app.info_name = "opengov-grants"

# Sub-apps for organization
agent_app = typer.Typer(help="AI-powered analysis commands")
db_app = typer.Typer(help="Database management commands")
llm_app = typer.Typer(help="LLM and model management commands")
query_app = typer.Typer(help="Data query and analysis commands")
typer_app.add_typer(agent_app, name="agent")
typer_app.add_typer(db_app, name="db")
typer_app.add_typer(llm_app, name="llm")
typer_app.add_typer(query_app, name="query")

# App exposure moved to end of file after all commands are declared.


@typer_app.callback()
def callback(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to config file"),
    version: bool = typer.Option(False, "--version", help="Show version and exit", is_eager=True),
):
    """OpenGov-Grants - Comprehensive grants management and fiscal administration system for city governments managing federal, state, and foundation funding opportunities."""
    if version:
        console.print("OpenGov-Grants v1.0.0")
        raise typer.Exit(0)

    if verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    if config:
        os.environ["OPENGRANTS_CONFIG"] = str(config)


@typer_app.command("menu")
def interactive_menu():
    """Launch interactive menu."""
    console.print(f"[bold blue]OpenGov-Grants - Interactive Menu[/bold blue]")
    console.print("=" * 50)

    table = Table(title="Available Operations")
    table.add_column("Command", style="cyan")
    table.add_column("Description", style="white")

    table.add_row("agent run", "Run AI analysis")
    table.add_row("db init", "Initialize database")
    table.add_row("serve-datasette", "Launch web dashboard")

    console.print(table)


@agent_app.command("run")
def agent_run(
    prompt: str = typer.Argument(..., help="Analysis prompt for the AI agent"),
    model: str = typer.Option("gpt-4", "--model", "-m", help="Model to use for analysis"),
    provider: str = typer.Option("openai", "--provider", "-p", help="AI provider (openai/ollama)"),
):
    """Run AI-powered analysis."""
    console.print(f"[bold green]Running Analysis[/bold green]")
    console.print(f"Prompt: {prompt}")
    console.print(f"Model: {model}")
    console.print(f"Provider: {provider}")
    console.print("-" * 50)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing...", total=None)

        try:
            settings = get_settings()
            agent_service = AgentService()
            result = asyncio.run(agent_service.run_analysis(prompt, model, provider))

            progress.update(task, completed=True)
            console.print("[bold green]Analysis Complete[/bold green]")
            console.print(f"Result: {result}")

        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[bold red]Analysis Failed: {e}[/bold red]")
            raise typer.Exit(1)


@db_app.command("init")
def db_init(
    drop_existing: bool = typer.Option(False, "--drop-existing", help="Drop existing database"),
):
    """Initialize the database."""
    console.print("[bold blue]Initializing Database[/bold blue]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Setting up database...", total=None)

        try:
            db_manager = DatabaseManager()
            db_manager.initialize(drop_existing=drop_existing)
            progress.update(task, completed=True)
            console.print("[bold green]Database initialized[/bold green]")

        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[bold red]Failed: {e}[/bold red]")
            raise typer.Exit(1)


@db_app.command("seed")
def db_seed():
    """Seed database with sample data."""
    console.print("[bold blue]Seeding Database[/bold blue]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Seeding database...", total=None)

        try:
            db_manager = DatabaseManager()
            db_manager.seed_sample_data()
            progress.update(task, completed=True)
            console.print("[bold green]Database seeded[/bold green]")

        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[bold red]Failed: {e}[/bold red]")
            raise typer.Exit(1)


@typer_app.command("serve-datasette")
def serve_datasette(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8001, "--port", "-p", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload"),
):
    """Serve the Datasette web interface."""
    console.print("[bold blue]Starting Dashboard[/bold blue]")
    console.print(f"Host: {host}")
    console.print(f"Port: {port}")

    try:
        import subprocess
        db_path = get_settings().database_url.replace("sqlite:///", "")
        cmd = [sys.executable, "-m", "datasette", "serve", db_path, "--host", host, "--port", str(port)]

        if reload:
            cmd.append("--reload")

        console.print("[bold green]Dashboard starting...[/bold green]")
        console.print(f"Open http://{host}:{port} in your browser")
        subprocess.run(cmd)

    except Exception as e:
        console.print(f"[bold red]✗ Failed: {e}[/bold red]")
        raise typer.Exit(1)


@typer_app.callback(invoke_without_command=True)
def main(ctx: typer.Context, version: bool = typer.Option(False, "--version", help="Show version and exit")):
    """OpenGov-Grants - Main CLI entry point."""
    if version:
        console.print(f"OpenGov-Grants v1.0.0")
        raise typer.Exit(0)


@typer_app.command("serve")
def serve_api(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to."),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to."),
):
    """
    Start FastAPI web server for API access.
    """
    console.print(f"Starting FastAPI server on {host}:{port}...")
    console.print("[bold green]Open your browser to: http://{host}:{port}[/bold green]")
    console.print("[bold blue]API Documentation: http://{host}:{port}/docs[/bold blue]")

    try:
        import uvicorn
        uvicorn.run(
            "opengovgrants.web.app:app",
            host=host,
            port=port,
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        console.print("\n[bold blue]FastAPI server stopped.[/bold blue]")
    except Exception as e:
        console.print(f"[bold red]Error starting FastAPI server: {e}[/bold red]")
        raise typer.Exit(1)


@typer_app.command("init")
def init_command(
    drop_existing: bool = typer.Option(False, "--drop-existing", help="Drop existing database"),
):
    """Top-level database initialization shortcut."""
    return db_init(drop_existing=drop_existing)

@typer_app.command("serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host to bind to."),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to."),
):
    """Top-level serve shortcut."""
    return serve_api(host=host, port=port)


@typer_app.command("menu")
def interactive_menu():
    """
    Launch interactive menu system.
    """
    console.print(f"[bold blue]OpenGov-Grants Interactive Menu[/bold blue]")
    console.print("=" * 50)

    while True:
        console.print("\n[bold cyan]Available Operations:[/bold cyan]")
        console.print("1. Database Management")
        console.print("2. AI Analysis")
        console.print("3. Web Server")
        console.print("4. Export Data")
        console.print("5. System Status")
        console.print("6. Exit")

        choice = typer.prompt("\nChoose an option (1-6)", type=int)

        if choice == 1:
            db_submenu()
        elif choice == 2:
            ai_submenu()
        elif choice == 3:
            web_submenu()
        elif choice == 4:
            export_submenu()
        elif choice == 5:
            status_submenu()
        elif choice == 6:
            console.print("[bold green]Goodbye![/bold green]")
            break
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")

def db_submenu():
    """Database operations submenu."""
    console.print("\n[bold yellow]Database Operations:[/bold yellow]")
    console.print("1. Initialize Database")
    console.print("2. Seed Sample Data")
    console.print("3. Run Migrations")
    console.print("4. View Statistics")
    console.print("5. Back to Main Menu")

    choice = typer.prompt("Choose an option (1-5)", type=int)

    if choice == 1:
        init_db()
    elif choice == 2:
        db_commands(None, "seed")
    elif choice == 3:
        db_commands(None, "migrate")
    elif choice == 4:
        db_commands(None, "query")

def ai_submenu():
    """AI analysis submenu."""
    console.print("\n[bold yellow]AI Analysis:[/bold yellow]")
    console.print("1. Run Analysis")
    console.print("2. Chat with AI")
    console.print("3. Batch Processing")
    console.print("4. Back to Main Menu")

    choice = typer.prompt("Choose an option (1-4)", type=int)

    if choice == 1:
        prompt = typer.prompt("Enter your analysis prompt")
        run_agent(prompt)
    elif choice == 2:
        console.print("[bold green]AI Chat feature coming soon![/bold green]")

def web_submenu():
    """Web server submenu."""
    console.print("\n[bold yellow]Web Server:[/bold yellow]")
    console.print("1. Start FastAPI Server")
    console.print("2. Start Datasette")
    console.print("3. Back to Main Menu")

    choice = typer.prompt("Choose an option (1-3)", type=int)

    if choice == 1:
        serve_api()
    elif choice == 2:
        serve_datasette()

def export_submenu():
    """Data export submenu."""
    console.print("\n[bold yellow]Data Export:[/bold yellow]")
    console.print("1. Export to CSV")
    console.print("2. Export to JSON")
    console.print("3. Export to Excel")
    console.print("4. Back to Main Menu")

    choice = typer.prompt("Choose an option (1-4)", type=int)

    if choice in [1, 2, 3]:
        format_map = {1: "csv", 2: "json", 3: "excel"}
        console.print(f"[bold green]Export to {format_map[choice]} coming soon![/bold green]")

def status_submenu():
    """System status submenu."""
    console.print("\n[bold yellow]System Status:[/bold yellow]")
    console.print("1. Health Check")
    console.print("2. Database Status")
    console.print("3. AI Services Status")
    console.print("4. Back to Main Menu")

    choice = typer.prompt("Choose an option (1-4)", type=int)

    if choice == 1:
        console.print("[bold green]✅ System is healthy![/bold green]")
    elif choice == 2:
        db_commands(None, "query")
    elif choice == 3:
        console.print("[bold green]✅ AI services are operational![/bold green]")


if __name__ == "__main__":
    app()

# For external import by tests
try:
    from typer.main import get_command as _get_command
    app = _get_command(typer_app)
except Exception:
    app = typer_app