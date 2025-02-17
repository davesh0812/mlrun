# Copyright 2024 Iguazio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from logging.config import fileConfig

import sqlalchemy
import sqlalchemy.exc
from alembic import context
from sqlalchemy import engine_from_config, pool

from mlrun import mlconf
from mlrun.utils import logger

from framework.db.sqldb import models

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name, disable_existing_loggers=False)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = models.Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

# this will overwrite the ini-file sqlalchemy.url path
# with the path given in the mlconf
config.set_main_option("sqlalchemy.url", mlconf.httpdb.dsn)


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = context.config.attributes.get("connection", None)

    if connectable is None:
        connectable = engine_from_config(
            config.get_section(config.config_ini_section),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )

    with connectable.connect() as connection:
        # This query retrieves information about database connections that have acquired
        # locks on objects in the 'mlrun' schema,
        # excluding the current connection and the 'alembic_version' table.
        # This is order to find and kill connections that might be blocking the migration.
        connection_ids = connection.execute(
            sqlalchemy.sql.text(
                """SELECT
                t.PROCESSLIST_ID,
                t.PROCESSLIST_USER,
                t.PROCESSLIST_HOST,
                GROUP_CONCAT(DISTINCT ml.OBJECT_NAME ORDER BY ml.OBJECT_NAME SEPARATOR ', ') AS locked_objects
            FROM
                performance_schema.metadata_locks AS ml
            INNER JOIN
                performance_schema.threads AS t
                ON ml.OWNER_THREAD_ID = t.THREAD_ID
            WHERE
                t.PROCESSLIST_ID <> CONNECTION_ID()
                AND ml.OBJECT_SCHEMA = 'mlrun'
                AND ml.OBJECT_NAME != 'alembic_version'
                AND ml.LOCK_STATUS = 'GRANTED'
            GROUP BY
                t.PROCESSLIST_ID,
                t.PROCESSLIST_USER,
                t.PROCESSLIST_HOST
            ORDER BY
                t.PROCESSLIST_ID;
            """
            )
        ).fetchall()
        for connection_id, user, host, locked_objects in connection_ids:
            logger.warning(
                "Killing DB connection with acquired lock.",
                connection_id=connection_id,
                user=user,
                host=host,
                locked_objects=locked_objects,
                db="mlrun",
            )
            try:
                connection.execute(sqlalchemy.sql.text(f"KILL {connection_id};"))
            except sqlalchemy.exc.OperationalError as exc:
                if "Unknown thread id" in str(exc):
                    logger.warning(
                        "DB connection already closed.",
                        connection_id=connection_id,
                        user=user,
                        host=host,
                        db="mlrun",
                    )
                else:
                    raise exc

        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
