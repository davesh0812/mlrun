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
import http
from unittest import mock

import pytest
from aiohttp import ClientResponse

import mlrun.errors
from mlrun.errors import (
    MLRunHTTPError,
    err_for_status_code,
    err_to_str,
    raise_for_status,
)


def test_error_none():
    assert err_to_str(None) == ""


def test_long_error_message_truncated():
    err_msg = "a" * 16_000
    err_msg += "deleteme"
    err_msg += "b" * 16_000
    truncated_err_msg = err_to_str(Exception(err_msg))
    assert len(truncated_err_msg) == 32_000 + len("...truncated...")
    assert "deleteme" not in truncated_err_msg


def test_error_is_already_string():
    assert err_to_str("this is already a string") == "this is already a string"


def test_error_single():
    try:
        raise Exception("a")
    except Exception as ex:
        assert err_to_str(ex) == "a"


def test_error_with_no_description():
    try:
        raise AttributeError
    except Exception as ex:
        assert err_to_str(ex) == "AttributeError()"


def test_error_chain_n2():
    try:
        raise Exception("b") from Exception("a")
    except Exception as ex:
        assert err_to_str(ex) == "b, caused by: a"


def test_error_chain_n3():
    try:
        a = Exception("a")
        b = Exception("b")
        b.__cause__ = a
        raise Exception("c") from b
    except Exception as ex:
        assert err_to_str(ex) == "c, caused by: b, caused by: a"


def test_error_circular_chain():
    a = Exception("a")
    b = Exception("b")
    a.__cause__ = b
    b.__cause__ = a
    assert err_to_str(b) == "b, caused by: a"


def test_raise_for_aiohttp_client_response_status():
    # import locally to avoid confusion with mlrun requirements sorting
    from yarl import URL

    response = ClientResponse(
        method="GET",
        url=URL(),
        writer=mock.MagicMock(),
        continue100=None,
        timer=mock.MagicMock(),
        request_info=mock.MagicMock(),
        traces=mock.MagicMock(),
        loop=mock.MagicMock(),
        session=mock.MagicMock(),
    )
    response.status = 503
    response.reason = "Service Unavailable"
    with pytest.raises(MLRunHTTPError) as exc:
        raise_for_status(response)
    assert (
        exc.value.response.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE
    ), "should have raised 503"
    assert isinstance(
        exc.value.response, ClientResponse
    ), "should have aiohttp client response in exception"


class TestErrToStatusCodeError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message


@pytest.mark.parametrize(
    "status_code, exc, message",
    [
        (404, mlrun.errors.MLRunNotFoundError, "message not found"),
        ("404", mlrun.errors.MLRunNotFoundError, "message not found"),
        (500, mlrun.errors.MLRunInternalServerError, "message internal server error"),
        (0, mlrun.errors.MLRunHTTPError, "message http error"),
    ],
)
def test_err_to_status_code(status_code, exc, message):
    with pytest.raises(exc) as _exc:
        try:
            raise TestErrToStatusCodeError(status_code, message)
        except TestErrToStatusCodeError as test_exc:
            raise err_for_status_code(
                test_exc.status_code, test_exc.message
            ) from test_exc

    if exc != mlrun.errors.MLRunHTTPError:
        assert _exc.value.error_status_code == int(status_code)
    assert message in str(_exc.value)
