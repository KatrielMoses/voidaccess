"""Local administrator recovery: python -m scripts.promote_admin --email EMAIL."""
import argparse
from db.models import User
from db.session import get_session


def main():
    parser = argparse.ArgumentParser(description="Promote a self-hosted account to admin")
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    with get_session() as session:
        user = session.query(User).filter_by(email=args.email.strip().lower()).first()
        if user is None:
            parser.error("User does not exist")
        user.role = "admin"
    print("Administrator role granted.")


if __name__ == "__main__":
    main()
