"""Local administrator recovery commands for self-hosted API installs."""
import typer

app = typer.Typer(help="Manage self-hosted administrator roles.")


@app.command("promote")
def promote(email: str = typer.Option(..., "--email")):
    from db.models import User
    from db.session import get_session
    with get_session() as session:
        user = session.query(User).filter_by(email=email.strip().lower()).first()
        if user is None:
            raise typer.BadParameter("User does not exist", param_hint="--email")
        user.role = "admin"
    typer.echo("Administrator role granted.")
