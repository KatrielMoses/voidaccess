"""Idempotent legacy YAML/vector ownership import after alembic upgrade head."""
from db.models import User, ActorNote
from db.session import get_session
from monitor.migration import import_legacy_watches
from vector.store import backfill_owners


def main():
    with get_session() as session:
        admin = session.query(User).filter_by(role="admin").order_by(User.id).first()
        if admin is None:
            raise RuntimeError("Create or promote the first administrator before importing legacy data")
        owner = admin.id
        session.query(ActorNote).filter_by(user_id=None).update({ActorNote.user_id: owner})
        monitors = import_legacy_watches(session)
    vectors = backfill_owners(owner)
    print(f"Imported {monitors} monitors; assigned {vectors} vectors.")


if __name__ == "__main__":
    main()
