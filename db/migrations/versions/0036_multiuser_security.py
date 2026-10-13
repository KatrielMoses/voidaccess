"""E2 multi-user roles, owned monitors/annotations, and entity link context."""
import uuid
from alembic import op
import sqlalchemy as sa

revision = "0036_multiuser_security"
down_revision = "0035_add_ges_contributor"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    op.add_column("users", sa.Column("role", sa.String(10), nullable=False, server_default="user"))
    conn.execute(sa.text("UPDATE users SET role = 'admin' WHERE id = (SELECT MIN(id) FROM users)"))
    admin = conn.execute(sa.text("SELECT MIN(id) FROM users WHERE role = 'admin'")).scalar()
    op.add_column("pages", sa.Column("investigation_id", sa.UUID, sa.ForeignKey("investigations.id"), nullable=True))
    if conn.dialect.name == "postgresql":
        for c in sa.inspect(conn).get_unique_constraints("pages"):
            if c["column_names"] == ["url"]:
                op.drop_constraint(c["name"], "pages", type_="unique")
        op.create_unique_constraint("uq_page_investigation_url", "pages", ["url", "investigation_id"])
    else:
        with op.batch_alter_table("pages", naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"}) as batch:
            for c in sa.inspect(conn).get_unique_constraints("pages"):
                if c["column_names"] == ["url"]:
                    batch.drop_constraint(c["name"] or "uq_pages_url", type_="unique")
            batch.create_unique_constraint("uq_page_investigation_url", ["url", "investigation_id"])
    op.create_index("uq_pages_cli_url", "pages", ["url"], unique=True, postgresql_where=sa.text("investigation_id IS NULL"), sqlite_where=sa.text("investigation_id IS NULL"))
    for column in (sa.Column("context_snippet", sa.Text), sa.Column("confidence", sa.Float),
                   sa.Column("page_id", sa.UUID), sa.Column("extraction_method", sa.String(10))):
        op.add_column("investigation_entity_links", column)
    links = sa.Table("investigation_entity_links", sa.MetaData(), autoload_with=conn)
    entities = sa.Table("entities", sa.MetaData(), autoload_with=conn)
    for e in conn.execute(sa.select(entities)).mappings():
        if e["investigation_id"] and not conn.execute(sa.select(links.c.id).where(
            links.c.entity_id == e["id"], links.c.investigation_id == e["investigation_id"])).first():
            conn.execute(links.insert().values(id=uuid.uuid4(), entity_id=e["id"], investigation_id=e["investigation_id"], linked_at=e["created_at"]))
        # Origin context can be recovered; legacy links to other owners must not
        # inherit the last writer's snippet/page. Keep original shared rows intact.
        conn.execute(links.update().where(links.c.entity_id == e["id"], links.c.investigation_id == e["investigation_id"]).values(
            context_snippet=e["context_snippet"], confidence=e["confidence"], page_id=e["page_id"], extraction_method=e["extraction_method"]))
    for table in ("actor_aliases", "monitor_alerts"):
        op.add_column(table, sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=True))
        if admin is not None:
            conn.execute(sa.text(f"UPDATE {table} SET user_id = :owner WHERE user_id IS NULL"), {"owner": admin})
    if conn.dialect.name == "postgresql":
        constraints = sa.inspect(conn).get_unique_constraints("actor_aliases")
        for c in constraints:
            if set(c["column_names"]) == {"actor_id", "alias_value"}:
                op.drop_constraint(c["name"], "actor_aliases", type_="unique")
        op.create_unique_constraint("uq_actor_alias_owner", "actor_aliases", ["actor_id", "alias_value", "user_id"])
    else:
        with op.batch_alter_table("actor_aliases", naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"}) as batch:
            for c in sa.inspect(conn).get_unique_constraints("actor_aliases"):
                if set(c["column_names"]) == {"actor_id", "alias_value"}:
                    batch.drop_constraint(c["name"] or "uq_actor_aliases_actor_id", type_="unique")
            batch.create_unique_constraint("uq_actor_alias_owner", ["actor_id", "alias_value", "user_id"])
    if conn.dialect.name == "postgresql":
        for c in sa.inspect(conn).get_unique_constraints("actor_infrastructure"):
            if set(c["column_names"]) == {"actor_id", "entity_type", "entity_value"}:
                op.drop_constraint(c["name"], "actor_infrastructure", type_="unique")
        op.create_unique_constraint("uq_actor_infra_investigation", "actor_infrastructure", ["actor_id", "entity_type", "entity_value", "source_investigation_id"])
    else:
        with op.batch_alter_table("actor_infrastructure", naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"}) as batch:
            for c in sa.inspect(conn).get_unique_constraints("actor_infrastructure"):
                if set(c["column_names"]) == {"actor_id", "entity_type", "entity_value"}:
                    batch.drop_constraint(c["name"] or "uq_actor_infrastructure_actor_id", type_="unique")
            batch.create_unique_constraint("uq_actor_infra_investigation", ["actor_id", "entity_type", "entity_value", "source_investigation_id"])
    op.create_table("actor_notes", sa.Column("id", sa.UUID, primary_key=True),
                    sa.Column("actor_id", sa.UUID, sa.ForeignKey("actor_profiles.id"), nullable=False),
                    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id")),
                    sa.Column("text", sa.Text, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True)))
    notes = sa.Table("actor_notes", sa.MetaData(), autoload_with=conn)
    profiles = sa.Table("actor_profiles", sa.MetaData(), autoload_with=conn)
    for row in conn.execute(sa.select(profiles)).mappings():
        if row["notes"]:
            conn.execute(notes.insert().values(id=uuid.uuid4(), actor_id=row["id"], user_id=admin, text=row["notes"], created_at=row["created_at"]))
    op.create_table("monitors", sa.Column("id", sa.UUID, primary_key=True),
                    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id")),
                    sa.Column("name", sa.String(255), nullable=False), sa.Column("config", sa.JSON, nullable=False),
                    sa.Column("enabled", sa.Boolean, nullable=False), sa.Column("deleted", sa.Boolean, nullable=False, server_default=sa.false()),
                    sa.UniqueConstraint("user_id", "name"))


def downgrade():
    raise RuntimeError("Ownership migration cannot be downgraded without discarding annotations. Restore a backup instead.")
