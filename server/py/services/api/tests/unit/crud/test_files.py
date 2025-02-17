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

import unittest.mock

import fastapi.testclient
import pytest
import sqlalchemy.orm

import mlrun.common.schemas

import services.api.crud


@pytest.mark.parametrize(
    "user_secrets, expected_secrets",
    [
        (
            None,
            {
                "secret1": "value1",
                "secret2": "value2",
                "V3IO_ACCESS_KEY": "auth-info-secret",
            },
        ),
        (
            {"V3IO_ACCESS_KEY": "user-access-key", "secret1": "user-secret"},
            {
                "secret1": "user-secret",
                "secret2": "value2",
                "V3IO_ACCESS_KEY": "user-access-key",
            },
        ),
    ],
)
def test_delete_artifact_data(
    db: sqlalchemy.orm.Session,
    client: fastapi.testclient.TestClient,
    k8s_secrets_mock,
    user_secrets,
    expected_secrets,
) -> None:
    path = "s3://somebucket/some/path/file"
    project = "proj1"

    auth_info = mlrun.common.schemas.AuthInfo(data_session="auth-info-secret")
    user_access_key = "user-access-key"
    env_secrets = {"V3IO_ACCESS_KEY": user_access_key}
    project_secrets = {"secret1": "value1", "secret2": "value2"}
    full_secrets = project_secrets.copy()
    full_secrets.update(env_secrets)
    k8s_secrets_mock.store_project_secrets(project, project_secrets)

    with unittest.mock.patch(
        "mlrun.datastore.store_manager.object"
    ) as store_manager_object_mock:
        services.api.crud.Files().delete_artifact_data(
            auth_info, project, path, secrets=user_secrets
        )
        store_manager_object_mock.assert_called_once_with(
            url=path, secrets=expected_secrets, project=project
        )
        store_manager_object_mock.reset_mock()


def test_delete_artifact_data_internal_secret(
    db: sqlalchemy.orm.Session,
    client: fastapi.testclient.TestClient,
    k8s_secrets_mock,
) -> None:
    path = "s3://somebucket/some/path/file"
    project = "proj1"
    user_secrets = {"mlrun.secret1": "user-secret"}

    with pytest.raises(mlrun.errors.MLRunAccessDeniedError) as exc:
        services.api.crud.Files().delete_artifact_data(
            mlrun.common.schemas.AuthInfo(), project, path, secrets=user_secrets
        )
    assert (
        str(exc.value)
        == "Not allowed to create/update internal secrets (key starts with mlrun.)"
    )


def test_delete_artifact_data_local_path(
    db: sqlalchemy.orm.Session,
    client: fastapi.testclient.TestClient,
    k8s_secrets_mock,
) -> None:
    path = "/some-local-path"
    project = "proj1"

    with pytest.raises(mlrun.errors.MLRunAccessDeniedError) as exc:
        services.api.crud.Files().delete_artifact_data(
            mlrun.common.schemas.AuthInfo(), project, path
        )
    assert str(exc.value) == "Unauthorized path"
