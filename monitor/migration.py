"""Idempotent read-only import of legacy monitor definitions."""
from db.models import Monitor, User
from monitor.config import load_yaml_watches


def import_legacy_watches(session):
    admin = session.query(User).filter_by(role="admin").order_by(User.id).first()
    if admin is None:
        return 0
    count = 0
    for watch in load_yaml_watches():
        exists = session.query(Monitor.id).filter_by(user_id=admin.id, name=watch["name"]).first()
        if exists:
            continue
        session.add(Monitor(user_id=admin.id, name=watch["name"], config=watch, enabled=watch["enabled"]))
        session.flush()
        count += 1
    return count
