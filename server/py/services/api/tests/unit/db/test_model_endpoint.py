# Copyright 2023 Iguazio
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
#

import pytest
from black import datetime
from sqlalchemy.orm import Session

import mlrun
import mlrun.common.schemas
from mlrun.common.schemas import EndpointType, ModelMonitoringMode

import services.api.tests.unit.db.test_functions
from framework.db.base import DBInterface
from framework.db.sqldb.db import unversioned_tagged_object_uid_prefix
from framework.db.sqldb.models import ModelEndpoint


def _store_function(
    db: DBInterface,
    db_session: Session,
    function_name: str = "function-1",
    project: str = "project-1",
) -> str:
    function = services.api.tests.unit.db.test_functions._generate_function(
        function_name=function_name, project=project
    )
    function_hash_key = db.store_function(
        db_session,
        function.to_dict(),
        function.metadata.name,
        function.metadata.project,
    )
    return function_hash_key


def _store_artifact(db: DBInterface, db_session: Session, key: str) -> str:
    artifact = {
        "metadata": {"tree": "artifact_tree", "tag": "latest"},
        "spec": {"src_path": "/some/path"},
        "kind": "model",
        "status": {"bla": "blabla"},
    }
    model_uid = db.store_artifact(
        db_session,
        key,
        artifact,
        tag="latest",
        project="project-1",
    )
    return model_uid


def test_sanity(db: DBInterface, db_session: Session) -> None:
    uids = []
    model_uids = []
    # store artifact
    for i in range(2):
        model_uids.append(_store_artifact(db, db_session, f"model-{i}"))
    print(model_uids)
    # store function
    function_hash_key = _store_function(db, db_session)
    model_endpoint = mlrun.common.schemas.ModelEndpoint(
        metadata={"name": "model-endpoint-1", "project": "project-1"},
        spec={
            "function_name": "function-1",
            "function_uid": f"{unversioned_tagged_object_uid_prefix}latest",
            "model_uid": model_uids[1],
            "model_name": "model-1",
        },
        status={"monitoring_mode": "enabled", "last_request": str(datetime.now())},
    )
    for i in range(2):
        mep = db.store_model_endpoint(
            db_session,
            model_endpoint,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )
        model_endpoint_from_db = db.get_model_endpoint(
            db_session,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )
        assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
        assert model_endpoint_from_db.metadata.project == "project-1"
        assert model_endpoint_from_db.metadata.uid == mep.metadata.uid
        assert (
            model_endpoint_from_db.spec.function_uri
            == f"project-1/function-1@{function_hash_key}"
        )
        assert model_endpoint_from_db.spec.model_name == "model-1"
        uids.append(mep.metadata.uid)

    model_endpoint_from_db = db.get_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        uid=uids[0],
        function_name="function-1",
    )

    assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
    assert model_endpoint_from_db.metadata.project == "project-1"
    assert model_endpoint_from_db.metadata.uid == uids[0]

    list_mep = db.list_model_endpoints(
        db_session,
        project=model_endpoint.metadata.project,
    )
    assert len(list_mep.endpoints) == 2

    db.delete_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
        uid="*",
    )
    with pytest.raises(mlrun.errors.MLRunNotFoundError):
        db.get_model_endpoint(
            db_session,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )
    for uid in uids:
        with pytest.raises(mlrun.errors.MLRunNotFoundError):
            db.get_model_endpoint(
                db_session,
                name=model_endpoint.metadata.name,
                project=model_endpoint.metadata.project,
                uid=uid,
                function_name="function-1",
            )


def test_list_filters(db: DBInterface, db_session: Session) -> None:
    uids = []
    model_uids = []
    # store artifact
    for i in range(2):
        model_uids.append(_store_artifact(db, db_session, f"model-{i}"))
    # store function
    _ = _store_function(db, db_session)
    model_endpoint = mlrun.common.schemas.ModelEndpoint(
        metadata={"name": "model-endpoint-1", "project": "project-1"},
        spec={
            "function_name": "function-1",
            "function_uid": f"{unversioned_tagged_object_uid_prefix}latest",
            "model_uid": model_uids[1],
            "model_name": "model-1",
        },
        status={"monitoring_mode": "enabled"},
    )
    for i in range(2):
        model_endpoint.metadata.labels = {
            "label1": f"value_{i}",
            "label2": f"value_{i+1}",
            "label": "value",
        }
        mep = db.store_model_endpoint(
            db_session,
            model_endpoint,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )
        uids.append(mep.metadata.uid)

    list_mep = db.list_model_endpoints(
        db_session, project=model_endpoint.metadata.project, model_name="model-1"
    ).endpoints
    assert len(list_mep) == 2

    list_mep = db.list_model_endpoints(
        db_session, project=model_endpoint.metadata.project, model_name="model-2"
    ).endpoints
    assert len(list_mep) == 0

    list_mep = db.list_model_endpoints(
        db_session, project=model_endpoint.metadata.project, latest_only=True
    ).endpoints
    assert len(list_mep) == 1

    list_mep = db.list_model_endpoints(
        db_session, project=model_endpoint.metadata.project, labels=["label=value"]
    ).endpoints
    assert len(list_mep) == 2

    list_mep = db.list_model_endpoints(
        db_session, project=model_endpoint.metadata.project, labels=["label1=value_0"]
    ).endpoints
    assert len(list_mep) == 1

    list_mep = db.list_model_endpoints(
        db_session, project=model_endpoint.metadata.project, uids=uids
    ).endpoints
    assert len(list_mep) == 2

    list_mep = db.list_model_endpoints(
        db_session, project=model_endpoint.metadata.project, uids=["uids"]
    ).endpoints
    assert len(list_mep) == 0

    list_mep = db.list_model_endpoints(
        db_session, project=model_endpoint.metadata.project, function_name="function-1"
    ).endpoints
    assert len(list_mep) == 2

    model_endpoint.metadata.endpoint_type = EndpointType.LEAF_EP
    db.store_model_endpoint(
        db_session,
        model_endpoint,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
    )

    list_mep = db.list_model_endpoints(
        db_session, project=model_endpoint.metadata.project, top_level=True
    ).endpoints

    assert len(list_mep) == 2

    db.delete_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
        uid="*",
    )


def test_update_automatically_after_function_update(
    db: DBInterface, db_session: Session
) -> None:
    model_uids = []
    # store artifact
    for i in range(2):
        model_uids.append(_store_artifact(db, db_session, f"model-{i}"))
    # store function
    function_hash_key = _store_function(db, db_session)
    model_endpoint = mlrun.common.schemas.ModelEndpoint(
        metadata={"name": "model-endpoint-1", "project": "project-1"},
        spec={
            "function_name": "function-1",
            "function_uid": f"{unversioned_tagged_object_uid_prefix}" f"latest",
            "model_uid": model_uids[1],
            "model_name": "model-1",
        },
        status={"monitoring_mode": "enabled"},
    )
    for i in range(2):
        db.store_model_endpoint(
            db_session,
            model_endpoint,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )
        db.update_function(
            db_session,
            "function-1",
            updates={"status": {"state": "error"}},
            project="project-1",
            tag="latest",
        )
        model_endpoint_from_db = db.get_model_endpoint(
            db_session,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )
        assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
        assert model_endpoint_from_db.metadata.project == "project-1"
        assert model_endpoint_from_db.metadata.labels == model_endpoint.metadata.labels
        assert (
            model_endpoint_from_db.spec.function_uri
            == f"project-1/function-1@{function_hash_key}"
        )
        assert model_endpoint_from_db.spec.model_name == "model-1"
        assert model_endpoint_from_db.status.state == "error"
    db.delete_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
        uid="*",
    )


def test_update_automatically_after_model_update(
    db: DBInterface, db_session: Session
) -> None:
    model_uids = []
    # store artifact
    for i in range(2):
        model_uids.append(_store_artifact(db, db_session, f"model-{i}"))
    # store function
    _store_function(db, db_session)
    model_endpoint = mlrun.common.schemas.ModelEndpoint(
        metadata={"name": "model-endpoint-1", "project": "project-1"},
        spec={
            "function_name": "function-1",
            "function_uid": f"{unversioned_tagged_object_uid_prefix}latest",
            "model_uid": model_uids[1],
            "model_name": "model-1",
        },
        status={"monitoring_mode": "enabled"},
    )

    db.store_model_endpoint(
        db_session,
        model_endpoint,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
    )
    model_endpoint_from_db = db.get_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
    )
    assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
    assert model_endpoint_from_db.metadata.project == "project-1"
    assert model_endpoint_from_db.spec.model_name == "model-1"
    assert model_endpoint_from_db.spec.model_tag == ["latest"]

    artifact = {
        "metadata": {"tree": "artifact_tree"},
        "spec": {"src_path": "/some/new/path"},
        "kind": "model",
        "status": {"bla": "blablasdvcfs"},
    }
    db.store_artifact(
        db_session,
        f"model-{1}",
        artifact,
        project="project-1",
    )

    model_endpoint_from_db = db.get_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
    )
    assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
    assert model_endpoint_from_db.metadata.project == "project-1"
    assert model_endpoint_from_db.spec.model_name == "model-1"
    assert model_endpoint_from_db.spec.model_tag == []

    db.delete_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
        uid="*",
    )


def test_update(db: DBInterface, db_session: Session) -> None:
    model_uids = []
    # store artifact
    for i in range(2):
        model_uids.append(_store_artifact(db, db_session, f"model-{i}"))
    # store function
    _store_function(db, db_session)
    model_endpoint = mlrun.common.schemas.ModelEndpoint(
        metadata={"name": "model-endpoint-1", "project": "project-1"},
        spec={
            "function_name": "function-1",
            "function_uid": f"{unversioned_tagged_object_uid_prefix}latest",
            "model_uid": model_uids[1],
            "model_name": "model-1",
        },
        status={"monitoring_mode": "enabled"},
    )
    uids = []
    for i in range(2):
        mep = db.store_model_endpoint(
            db_session,
            model_endpoint,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )
        uids.append(mep.metadata.uid)

    db.update_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
        attributes={"monitoring_mode": ModelMonitoringMode.disabled},
    )

    model_endpoint_from_db = db.get_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
    )
    # check that the monitoring mode was updated for the latest model endpoint
    assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
    assert model_endpoint_from_db.metadata.project == "project-1"
    assert model_endpoint_from_db.metadata.uid == uids[1]
    assert model_endpoint_from_db.status.monitoring_mode == "disabled"

    model_endpoint_from_db = db.get_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        uid=uids[0],
        function_name="function-1",
    )
    # check that the monitoring mode was not updated for the old model endpoint
    assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
    assert model_endpoint_from_db.metadata.project == "project-1"
    assert model_endpoint_from_db.metadata.uid == uids[0]
    assert model_endpoint_from_db.status.monitoring_mode == "enabled"

    db.update_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        uid=uids[0],
        attributes={"feature_names": ["a", "b"]},
        function_name="function-1",
    )

    model_endpoint_from_db = db.get_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
    )
    # check that the feature_names value was not updated for the latest model endpoint
    assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
    assert model_endpoint_from_db.metadata.project == "project-1"
    assert model_endpoint_from_db.metadata.uid == uids[1]
    assert model_endpoint_from_db.spec.feature_names == []

    model_endpoint_from_db = db.get_model_endpoint(
        db_session,
        name=model_endpoint.metadata.name,
        project=model_endpoint.metadata.project,
        function_name="function-1",
        uid=uids[0],
    )
    # check that the feature_names value was updated for the old model endpoint
    assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
    assert model_endpoint_from_db.metadata.project == "project-1"
    assert model_endpoint_from_db.metadata.uid == uids[0]
    assert model_endpoint_from_db.spec.feature_names == ["a", "b"]


def test_delete_model_endpoints(db: DBInterface, db_session: Session) -> None:
    model_uids = []
    # store artifact
    for i in range(2):
        model_uids.append(_store_artifact(db, db_session, f"model-{i}"))
    # store function
    _store_function(db, db_session)
    model_endpoint = mlrun.common.schemas.ModelEndpoint(
        metadata={"name": "model-endpoint-1", "project": "project-1"},
        spec={
            "function_name": "function-1",
            "function_uid": f"{unversioned_tagged_object_uid_prefix}latest",
            "model_uid": model_uids[1],
            "model_name": "model-1",
        },
        status={"monitoring_mode": "enabled"},
    )
    for i in range(4):
        db.store_model_endpoint(
            db_session,
            model_endpoint,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )

    assert db_session.query(ModelEndpoint.Label).count() == 0
    assert db_session.query(ModelEndpoint.Tag).count() == 1
    assert db_session.query(ModelEndpoint).count() == 4

    db.delete_model_endpoints(
        session=db_session, project=model_endpoint.metadata.project
    )

    assert db_session.query(ModelEndpoint.Label).count() == 0
    assert db_session.query(ModelEndpoint.Tag).count() == 0
    assert db_session.query(ModelEndpoint).count() == 0


def test_insert_non_model(db: DBInterface, db_session: Session) -> None:
    uids = []
    function_hash_key = _store_function(db, db_session)
    model_endpoint = mlrun.common.schemas.ModelEndpoint(
        metadata={"name": "model-endpoint-1", "project": "project-1"},
        spec={
            "function_name": "function-1",
            "function_uid": f"{unversioned_tagged_object_uid_prefix}latest",
        },
        status={"monitoring_mode": "enabled", "last_request": str(datetime.now())},
    )
    for i in range(2):
        mep = db.store_model_endpoint(
            db_session,
            model_endpoint,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )
        model_endpoint_from_db = db.get_model_endpoint(
            db_session,
            name=model_endpoint.metadata.name,
            project=model_endpoint.metadata.project,
            function_name="function-1",
        )
        assert model_endpoint_from_db.metadata.name == "model-endpoint-1"
        assert model_endpoint_from_db.metadata.project == "project-1"
        assert model_endpoint_from_db.metadata.uid == mep.metadata.uid
        assert (
            model_endpoint_from_db.spec.function_uri
            == f"project-1/function-1@{function_hash_key}"
        )
        assert model_endpoint_from_db.spec.model_name == ""
        uids.append(mep.metadata.uid)
