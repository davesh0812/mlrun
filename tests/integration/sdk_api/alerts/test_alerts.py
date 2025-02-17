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
from datetime import timezone

import pytest

import mlrun
import mlrun.alerts
import mlrun.common.schemas
import mlrun.common.schemas.alert as alert_objects
import mlrun.utils
import tests.integration.sdk_api.base
from mlrun.utils import logger

import framework.constants


class TestAlerts(tests.integration.sdk_api.base.TestMLRunIntegration):
    def test_alert_operations(self):
        project_name = "my-project"

        # Define parameters for alert 1
        alert1 = {
            "name": "drift",
            "entity": {
                "kind": alert_objects.EventEntityKind.MODEL_ENDPOINT_RESULT,
                "project": project_name,
            },
            "summary": "Model {{project}}/{{entity}} is drifting.",
            "event_name": alert_objects.EventKind.DATA_DRIFT_DETECTED,
            "state": alert_objects.AlertActiveState.INACTIVE,
        }

        # Define parameters for alert 2
        alert2 = {
            "name": "jobs",
            "entity": {
                "kind": alert_objects.EventEntityKind.JOB,
                "project": project_name,
            },
            "summary": "Job {{project}}/{{entity}} failed.",
            "event_name": alert_objects.EventKind.FAILED,
            "state": alert_objects.AlertActiveState.INACTIVE,
            "criteria": alert_objects.AlertCriteria(period="1h", count=3),
        }

        mlrun.new_project(project_name)

        # validate get alerts on empty system
        alerts = self._get_alerts(project_name)
        assert len(alerts) == 0
        alerts_activations = self._get_alert_activations(project_name)
        assert len(alerts_activations) == 0

        # validate create alert operation
        created_alert, created_alert2 = self._create_alerts_test(
            project_name, alert1, alert2
        )

        # validate get alerts on the created alerts
        alerts = self._get_alerts(project_name)
        assert len(alerts) == 2
        self._validate_alert(alerts[0], project_name, alert1["name"])
        self._validate_alert(alerts[1], project_name, alert2["name"])

        # get alert and validate params
        alert = self._get_alerts(project_name, created_alert.name)
        self._validate_alert(alert, project_name, alert1["name"])
        assert alert.criteria.count == 1
        assert alert.criteria.period is None

        # try to get non existent alert ID
        with pytest.raises(mlrun.errors.MLRunNotFoundError):
            self._get_alerts(project_name, name="666")

        # post event with invalid entity type
        with pytest.raises(mlrun.errors.MLRunBadRequestError):
            self._post_event(
                project_name, alert1["event_name"], alert2["entity"]["kind"]
            )

        # post event for alert 1
        self._post_event(project_name, alert1["event_name"], alert1["entity"]["kind"])

        # validate alert activation for alert 1
        alerts_activations = self._get_alert_activations(project_name, alert1["name"])
        self._validate_alert_activation(
            alerts_activations[0], project_name, alert1["name"], number_of_events=1
        )
        # validate through the alert config
        alerts_activations = alert.list_activations()
        self._validate_alert_activation(
            alerts_activations[0], project_name, alert1["name"], number_of_events=1
        )

        # check get alert activation by id
        alert_activation_by_id = mlrun.get_run_db().get_alert_activation(
            project_name, alerts_activations[0].id
        )
        self._validate_alert_activation(
            alert_activation_by_id, project_name, alert1["name"]
        )

        # negative test for get alert activation by id
        with pytest.raises(mlrun.errors.MLRunNotFoundError):
            mlrun.get_run_db().get_alert_activation(
                project_name,
                100000,
            )

        # post event for alert 2
        for _ in range(alert2["criteria"].count):
            self._post_event(
                project_name, alert2["event_name"], alert2["entity"]["kind"]
            )

        # since the reset_policy of the alert is "manual", the state now should be active
        alert = self._get_alerts(project_name, created_alert2.name)
        self._validate_alert(
            alert, alert_state=alert_objects.AlertActiveState.ACTIVE, alert_count=1
        )

        alerts_activations = self._get_alert_activations(project_name, alert2["name"])
        self._validate_alert_activation(
            alerts_activations[0],
            project_name,
            alert2["name"],
            number_of_events=alert2["criteria"].count,
        )
        # validate through the alert config
        alerts_activations = alert.list_activations()
        self._validate_alert_activation(
            alerts_activations[0],
            project_name,
            alert2["name"],
            number_of_events=alert2["criteria"].count,
        )

        # send events again to make sure alert does not trigger, since it is active already
        for _ in range(alert2["criteria"].count):
            self._post_event(
                project_name, alert2["event_name"], alert2["entity"]["kind"]
            )
        alert = self._get_alerts(project_name, created_alert2.name)
        self._validate_alert(
            alert, alert_state=alert_objects.AlertActiveState.ACTIVE, alert_count=1
        )

        # reset the alert and trigger the event again and validate that the state is inactive
        self._reset_alert(project_name, created_alert2.name)
        # reset again to ensure that it's possible
        self._reset_alert(project_name, created_alert2.name)

        alerts_activations = self._get_alert_activations(project_name, alert2["name"])
        self._validate_alert_activation(
            alerts_activations[0],
            project_name,
            alert2["name"],
            number_of_events=alert2["criteria"].count * 2,
        )

        self._post_event(project_name, alert2["event_name"], alert2["entity"]["kind"])
        alert = self._get_alerts(project_name, created_alert2.name)
        self._validate_alert(
            alert, alert_state=alert_objects.AlertActiveState.INACTIVE, alert_count=1
        )

        # create an alert with reset_policy = "auto"
        self._create_alert(
            alert2["entity"]["project"],
            alert2["name"],
            alert2["entity"]["kind"],
            alert2["entity"]["project"],
            alert2["summary"],
            alert2["event_name"],
            criteria=alert2["criteria"],
            reset_policy=alert_objects.ResetPolicy.AUTO,
        )

        for _ in range(alert2["criteria"].count):
            self._post_event(
                project_name, alert2["event_name"], alert2["entity"]["kind"]
            )

        # since the reset_policy of the alert now is "auto", after sending 3 events the state should be inactive
        alert = self._get_alerts(project_name, created_alert2.name)

        self._validate_alert(
            alert,
            alert_state=alert_objects.AlertActiveState.INACTIVE,
            alert_count=2,
            alert_updated=True,
        )

        alerts_activations = self._get_alert_activations(project_name, alert2["name"])
        assert len(alerts_activations) == 2

        alert_config_activations = alert.list_activations()
        assert len(alert_config_activations) == 2

        # get alert config paginated activations
        activations, token = alert.paginated_list_activations()
        assert len(activations) == 2
        assert token is None

        # get the activations of alert2 after the last update was made to the alert
        alert_config_activations = alert.list_activations(from_last_update=True)
        assert len(alert_config_activations) == 1
        self._validate_alert_activation(
            alert_config_activations[0],
            project_name,
            alert2["name"],
        )

        # get alert2 config paginated activations from the last update
        activations, token = alert.paginated_list_activations(from_last_update=True)
        assert len(activations) == 1
        assert token is None

        new_event_name = alert_objects.EventKind.DATA_DRIFT_SUSPECTED
        modified_alert = self._modify_alert_test(
            project_name, alert1, created_alert.name, new_event_name
        )

        # post new event to make sure the modified alert handles it
        self._post_event(project_name, new_event_name, alert1["entity"]["kind"])

        alert = self._get_alerts(project_name, modified_alert.name)
        self._validate_alert(
            alert, alert_state=alert_objects.AlertActiveState.ACTIVE, alert_updated=True
        )

        alerts_activations = self._get_alert_activations(
            project_name, modified_alert.name
        )
        self._validate_alert_activation(
            alerts_activations[0],
            project_name,
            modified_alert.name,
            number_of_events=modified_alert.criteria.count,
        )

        # reset alert
        self._reset_alert(project_name, created_alert.name)

        alert = self._get_alerts(project_name, created_alert.name)
        self._validate_alert(alert, alert_state=alert_objects.AlertActiveState.INACTIVE)

        # reset the alert again, and validate that the state is still inactive
        self._reset_alert(project_name, created_alert.name)

        alert = self._get_alerts(project_name, created_alert.name)
        self._validate_alert(alert, alert_state=alert_objects.AlertActiveState.INACTIVE)

        # delete alert
        self._delete_alert(project_name, created_alert.name)

        alerts = self._get_alerts(project_name)
        assert len(alerts) == 1

        # try to delete invalid alert
        self._delete_alert(project_name, name="666")

        self._delete_alert(project_name, created_alert2.name)

        # validate get alerts on empty system after deletes
        alerts = self._get_alerts(project_name)
        assert len(alerts) == 0

        mlrun.get_run_db().delete_project(project_name)

        # make sure we can't get alert activations for deleted project
        with pytest.raises(mlrun.errors.MLRunNotFoundError):
            alerts_activations = self._get_alert_activations(project_name)
            assert len(alerts_activations) == 0

    def test_alert_activations_sdk(self):
        project_name = "my-new-project"
        project = mlrun.new_project(project_name)

        activations = project.list_alert_activations()
        assert len(activations) == 0

        activations, token = project.paginated_list_alert_activations()
        assert len(activations) == 0
        assert token is None

        event_name_entity_list = [
            (
                "alert1",
                alert_objects.EventKind.DATA_DRIFT_DETECTED,
                alert_objects.EventEntityKind.MODEL_ENDPOINT_RESULT,
            ),
            (
                "alert2",
                alert_objects.EventKind.FAILED,
                alert_objects.EventEntityKind.JOB,
            ),
        ]

        alert_summary = "Alert summary"

        for alert_name, event_name, alert_entity in event_name_entity_list:
            self._create_alert(
                project_name,
                alert_name,
                alert_entity,
                project_name,
                alert_summary,
                event_name,
                reset_policy=mlrun.common.schemas.alert.ResetPolicy.AUTO,
            )

        iterations = 5
        for i in range(iterations):
            for alert_name, event_name, alert_entity in event_name_entity_list:
                self._post_event(project_name, event_name, alert_entity)

        # check regular SDK without filters
        activations = project.list_alert_activations()
        assert len(activations) == 2 * iterations

        activations, token = project.paginated_list_alert_activations(
            page_size=iterations
        )
        assert len(activations) == iterations
        assert token is not None

        activations, token = project.paginated_list_alert_activations(page_token=token)
        assert len(activations) == iterations
        assert token is None

        # check SDK with filter by event_name and entity_kind
        for _, event_name, alert_entity in event_name_entity_list:
            activations = project.list_alert_activations(
                event_kind=event_name, entity_kind=alert_entity
            )
            assert len(activations) == iterations

            activations, token = project.paginated_list_alert_activations(
                event_kind=event_name, entity_kind=alert_entity, page_size=1
            )
            assert len(activations) == 1
            assert token is not None

            for i in range(iterations - 2):
                activations, token = project.paginated_list_alert_activations(
                    page_token=token
                )
                assert len(activations) == 1
                assert token is not None

            activations, token = project.paginated_list_alert_activations(
                page_token=token
            )
            assert len(activations) == 1
            assert token is None

    def test_alert_activations_cross_project(self):
        project_names = []
        for i in range(3):
            project_name = f"my-new-project{i}"
            mlrun.new_project(f"my-new-project{i}")
            project_names.append(project_name)

        activations = self._get_alert_activations()
        assert len(activations) == 0

        alert_name = "alert1"
        alert_entity = alert_objects.EventEntityKind.JOB
        event_name = alert_objects.EventKind.FAILED
        for project_name in project_names:
            self._create_alert(
                project_name,
                alert_name,
                alert_entity,
                project_name,
                "Alert summary",
                event_name,
                reset_policy=mlrun.common.schemas.alert.ResetPolicy.AUTO,
            )
            self._post_event(project_name, event_name, alert_entity)

        activations = self._get_alert_activations()
        assert len(activations) == 3
        for activation in activations:
            self._validate_alert_activation(
                activation,
                alert_event_kind=event_name,
                alert_entity_kind=alert_entity,
                number_of_events=1,
                alert_name=alert_name,
            )
            # verify that each alert activation is on different project
            project_names.remove(activation.project)
        assert len(project_names) == 0

    def test_alert_after_project_deletion(self):
        # this test checks create alert and post event operations after deleting a project and creating it again
        # with the same alert and event names

        project_name = "my-new-project"
        event_name = alert_objects.EventKind.DATA_DRIFT_DETECTED
        alert_name = "drift"
        alert_summary = "Model {{project}}/{{entity}} is drifting."
        alert_entity_kind = alert_objects.EventEntityKind.MODEL_ENDPOINT_RESULT
        alert_entity_project = project_name

        mlrun.new_project(alert_entity_project)
        self._create_alert(
            alert_entity_project,
            alert_name,
            alert_entity_kind,
            alert_entity_project,
            alert_summary,
            event_name,
        )
        self._post_event(alert_entity_project, event_name, alert_entity_kind)
        mlrun.get_run_db().delete_project(alert_entity_project, "cascade")
        mlrun.new_project(alert_entity_project)

        alerts_activations = self._get_alert_activations(project_name, alert_name)
        # ensure that we can't get activations from previous project entity with the same project name
        assert len(alerts_activations) == 0

        self._create_alert(
            alert_entity_project,
            alert_name,
            alert_entity_kind,
            alert_entity_project,
            alert_summary,
            event_name,
        )
        self._post_event(alert_entity_project, event_name, alert_entity_kind)

        alerts_activations = self._get_alert_activations(project_name, alert_name)
        assert len(alerts_activations) == 1
        self._validate_alert_activation(
            alerts_activations[0],
            project_name,
            alert_name,
            number_of_events=1,
        )

    def test_list_alert_activations_by_severity(self):
        project_name = "my-new-project"
        event_name = alert_objects.EventKind.DATA_DRIFT_DETECTED
        alert_name = "drift"
        alert_summary = "Model {{project}}/{{entity}} is drifting."
        alert_entity_kind = alert_objects.EventEntityKind.MODEL_ENDPOINT_RESULT
        alert_entity_project = project_name

        project = mlrun.new_project(alert_entity_project)
        alert = self._create_alert(
            alert_entity_project,
            alert_name,
            alert_entity_kind,
            alert_entity_project,
            alert_summary,
            event_name,
            reset_policy=mlrun.common.schemas.alert.ResetPolicy.AUTO,
        )
        self._post_event(alert_entity_project, event_name, alert_entity_kind)
        self._modify_alert(
            project_name=project_name,
            alert=alert,
            severity=mlrun.common.schemas.alert.AlertSeverity.HIGH,
            event_name=event_name,
        )
        self._post_event(alert_entity_project, event_name, alert_entity_kind)

        activations = project.list_alert_activations(name=alert_name)
        assert len(activations) == 2

        severity_list = [
            mlrun.common.schemas.alert.AlertSeverity.LOW,
            mlrun.common.schemas.alert.AlertSeverity.HIGH,
        ]

        activations = project.list_alert_activations(
            name=alert_name, severity=severity_list
        )
        assert len(activations) == 2

        for severity in severity_list:
            activations = project.list_alert_activations(
                name=alert_name,
                severity=severity,
            )
            assert len(activations) == 1
            self._validate_alert_activation(
                activations[0],
                project_name,
                alert_name,
                alert_severity=severity,
            )
        mlrun.get_run_db().delete_project(project_name, "cascade")

    def test_alert_templates(self):
        project_name = "my-project"
        project = mlrun.new_project(project_name)

        # one of the pre-defined system templates
        drift_system_template = self._get_template_by_name(
            framework.constants.pre_defined_templates, "DataDriftDetected"
        )

        drift_template = project.get_alert_template("DataDriftDetected")
        assert not drift_template.templates_differ(
            drift_system_template
        ), "Templates are different"

        all_system_templates = project.list_alert_templates()
        assert len(all_system_templates) == 3
        assert all_system_templates[0].template_name == "JobFailed"
        assert all_system_templates[1].template_name == "DataDriftDetected"
        assert all_system_templates[2].template_name == "DataDriftSuspected"

        # generate an alert from a template
        alert_name = "new-alert"
        alert_from_template = mlrun.alerts.alert.AlertConfig(
            name=alert_name,
            template=drift_template,
        )

        # test modifiers on the alert config
        entities = alert_objects.EventEntities(
            kind=alert_objects.EventEntityKind.MODEL_ENDPOINT_RESULT,
            project=project_name,
            ids=[1234],
        )
        alert_from_template.with_entities(entities=entities)

        notification = mlrun.model.Notification(
            kind="slack",
            name="slack_drift",
            secret_params={
                "webhook": "https://hooks.slack.com/services/",
            },
            condition="oops",
        )
        notifications = [
            alert_objects.AlertNotification(notification=notification.to_dict())
        ]

        alert_from_template.with_notifications(notifications=notifications)

        self._validate_alert(
            alert_from_template,
            alert_name=alert_name,
            alert_summary=drift_template.summary,
            alert_severity=drift_template.severity,
            alert_trigger=drift_template.trigger,
            alert_reset_policy=drift_template.reset_policy,
            alert_entity=entities,
            alert_notifications=notifications,
        )

        project.store_alert_config(alert_from_template)
        alerts = project.list_alerts_configs()
        assert len(alerts) == 1
        self._validate_alert(
            alerts[0], project_name=project_name, alert_name=alert_name
        )

        # create an alert from template with a different summary, severity, criteria,reset policy than the default ones
        # defined in the "DataDriftDetected" template
        alert_summary = "My drift detection alert"
        alert_severity = alert_objects.AlertSeverity.LOW
        alert_reset_policy = alert_objects.ResetPolicy.MANUAL
        alert_criteria = alert_objects.AlertCriteria(period="10m", count=3)
        alert_trigger = alert_objects.AlertTrigger(
            events=[alert_objects.EventKind.CONCEPT_DRIFT_DETECTED]
        )
        alert_from_template = mlrun.alerts.alert.AlertConfig(
            name=alert_name,
            template=drift_template,
            summary=alert_summary,
            severity=alert_severity,
            trigger=alert_trigger,
            reset_policy=alert_reset_policy,
            criteria=alert_criteria,
            entities=entities,
            notifications=notifications,
        )
        project.store_alert_config(alert_from_template)

        # validate that we have the right params after storing the alert config
        alert = project.get_alert_config(alert_name)
        self._validate_alert(
            alert,
            project_name=project_name,
            alert_name=alert_name,
            alert_summary=alert_summary,
            alert_severity=alert_severity,
            alert_trigger=alert_trigger,
            alert_reset_policy=alert_reset_policy,
            alert_criteria=alert_criteria,
        )

    def test_alert_activation_notification_state(self):
        project_name = "my-new-project"
        project = mlrun.new_project(project_name)

        alert_name = "alert1"
        alert_entity = alert_objects.EventEntityKind.JOB
        event_name = alert_objects.EventKind.FAILED

        failure_webhook_notification = mlrun.common.schemas.Notification(
            name="webhook1",
            kind="webhook",
            params={"url": "incorrect-url"},
            when=["error"],
            message="fail",
            condition="",
        )
        self._create_alert(
            project_name,
            alert_name,
            alert_entity,
            project_name,
            "Alert summary",
            event_name,
            reset_policy=mlrun.common.schemas.alert.ResetPolicy.AUTO,
            notifications=[
                mlrun.common.schemas.AlertNotification(
                    notification=failure_webhook_notification
                )
            ],
        )
        for i in range(1, 4):
            self._post_event(project_name, event_name, alert_entity)
            # we ensure that activation already has its notification state updated right after the event was posted
            activations = project.list_alert_activations(name=alert_name)

            # if fails, it means that the notification state was not updated fast enough and adding sleep is needed
            # or some performance optimisation required (for sending notifications)
            assert (
                activations[0].notifications[0].err
                == "All webhook notifications failed. Errors: incorrect-url"
            )
            assert activations[0].notifications[0].summary.failed == 1
            assert activations[0].notifications[0].summary.succeeded == 0

    def _create_alerts_test(self, project_name, alert1, alert2):
        invalid_notification = [
            {
                "notification": {
                    "kind": "invalid",
                    "name": "invalid_notification",
                    "message": "Ay ay ay!",
                    "severity": "warning",
                    "when": ["now"],
                    "condition": "failed",
                    "secret_params": {
                        "webhook": "https://hooks.slack.com/services/",
                    },
                },
            }
        ]
        duplicated_names_notifications = [
            {
                "notification": {
                    "kind": "slack",
                    "name": "slack_jobs",
                    "message": "Ay ay ay!",
                    "severity": "warning",
                    "when": ["now"],
                    "condition": "failed",
                    "secret_params": {
                        "webhook": "https://hooks.slack.com/services/",
                    },
                },
            },
            {
                "notification": {
                    "kind": "git",
                    "name": "slack_jobs",
                    "message": "Ay ay ay!",
                    "severity": "warning",
                    "when": ["now"],
                    "condition": "failed",
                    "secret_params": {
                        "webhook": "https://hooks.slack.com/services/",
                    },
                },
            },
        ]

        expectations = [
            {
                "param_name": "alert_name",
                "param_value": "",
                "exception": mlrun.errors.MLRunInvalidArgumentError,
                "case": "testing create alert without passing alert name",
            },
            {
                "param_name": "project_name",
                "param_value": "no_such_project",
                "exception": mlrun.errors.MLRunNotFoundError,
                "case": "testing create alert with non-existent project",
            },
            {
                "param_name": "alert_entity_kind",
                "param_value": "endpoint",
                "exception": mlrun.errors.MLRunHTTPError,
                "case": "testing create alert with invalid entity kind",
            },
            {
                "param_name": "alert_entity_project",
                "param_value": "no_such_project",
                "exception": mlrun.errors.MLRunBadRequestError,
                "case": "testing create alert with invalid entity project",
            },
            {
                "param_name": "severity",
                "param_value": "critical",
                "exception": mlrun.errors.MLRunHTTPError,
                "case": "testing create alert with invalid severity",
            },
            {
                "param_name": "criteria",
                "param_value": {"period": "abc"},
                "exception": mlrun.errors.MLRunBadRequestError,
                "case": "testing create alert with invalid criteria period",
            },
            {
                "param_name": "reset_policy",
                "param_value": "scheduled",
                "exception": mlrun.errors.MLRunHTTPError,
                "case": "testing create alert with invalid reset policy",
            },
            {
                "param_name": "notifications",
                "param_value": invalid_notification,
                "exception": mlrun.errors.MLRunHTTPError,
                "case": "testing create alert with invalid notification kind",
            },
            {
                "param_name": "notifications",
                "param_value": duplicated_names_notifications,
                "exception": mlrun.errors.MLRunHTTPError,
                "case": "testing create alert with two notifications with the same name",
            },
            {
                "param_name": "criteria",
                "param_value": alert_objects.AlertCriteria(count=10000000).dict(),
                "exception": mlrun.errors.MLRunPreconditionFailedError,
                "case": "testing create alert criteria counter more than max allowed",
            },
        ]
        args = {
            "project_name": project_name,
            "alert_name": alert1["name"],
            "alert_entity_kind": alert1["entity"]["kind"],
            "alert_entity_project": alert1["entity"]["project"],
            "alert_summary": alert1["summary"],
            "event_name": alert1["event_name"],
            "severity": alert_objects.AlertSeverity.LOW,
            "criteria": None,
            "notifications": None,
            "reset_policy": alert_objects.ResetPolicy.MANUAL,
        }
        for expectation in expectations:
            name = expectation["param_name"]
            value = expectation["param_value"]
            exception = expectation["exception"]
            case = expectation["case"]
            logger.info(case)
            new_args = dict(args, **{name: value})
            with pytest.raises(exception):
                self._create_alert(**new_args)

        # create alert with no errors
        created_alert = self._create_alert(
            project_name,
            alert1["name"],
            alert1["entity"]["kind"],
            alert1["entity"]["project"],
            alert1["summary"],
            alert1["event_name"],
        )
        self._validate_alert(
            created_alert,
            project_name,
            alert1["name"],
            alert1["summary"],
            alert1["state"],
            alert1["event_name"],
        )

        # create another alert with no errors
        notifications = [
            {
                "notification": {
                    "kind": "slack",
                    "name": "slack_jobs",
                    "secret_params": {
                        "webhook": "https://hooks.slack.com/services/",
                    },
                }
            },
            {
                "notification": {
                    "kind": "git",
                    "name": "git_jobs",
                    "params": {
                        "repo": "some-repo",
                        "issue": "some-issue",
                        "token": "some-token",
                    },
                }
            },
        ]

        created_alert2 = self._create_alert(
            project_name,
            alert2["name"],
            alert2["entity"]["kind"],
            alert2["entity"]["project"],
            alert2["summary"],
            alert2["event_name"],
            criteria=alert2["criteria"],
            notifications=notifications,
        )
        self._validate_alert(
            created_alert2,
            project_name,
            alert2["name"],
            alert2["summary"],
            alert2["state"],
            alert2["event_name"],
            alert_criteria=alert2["criteria"],
        )

        return created_alert, created_alert2

    def _modify_alert_test(self, project_name, alert1, alert_name, new_event_name):
        # modify alert with invalid data
        invalid_event_name = "not_permitted_event"
        with pytest.raises(mlrun.errors.MLRunHTTPError):
            self._create_alert(
                project_name,
                alert_name,
                alert1["entity"]["kind"],
                alert1["entity"]["project"],
                alert1["summary"],
                invalid_event_name,
            )

        # modify alert with no errors
        new_summary = "Aye ya yay {{project}}"
        modified_alert = self._create_alert(
            project_name,
            alert_name,
            alert1["entity"]["kind"],
            alert1["entity"]["project"],
            new_summary,
            new_event_name,
        )

        # verify that modify alert succeeded
        alert = self._get_alerts(project_name, alert1["name"])
        self._validate_alert(
            alert,
            project_name,
            alert1["name"],
            new_summary,
            alert1["state"],
            new_event_name,
        )

        return modified_alert

    def _create_alert(
        self,
        project_name,
        alert_name,
        alert_entity_kind,
        alert_entity_project,
        alert_summary,
        event_name,
        severity=alert_objects.AlertSeverity.LOW,
        criteria=None,
        notifications=None,
        reset_policy=alert_objects.ResetPolicy.MANUAL,
    ):
        alert_data = self._generate_alert_create_request(
            project_name,
            alert_name,
            alert_entity_kind,
            alert_entity_project,
            alert_summary,
            event_name,
            severity,
            criteria,
            notifications,
            reset_policy,
        )
        return mlrun.get_run_db().store_alert_config(
            alert_name, alert_data, project_name
        )

    def _modify_alert(
        self,
        project_name,
        alert: mlrun.common.schemas.alert.AlertConfig,
        alert_entity_kind=None,
        alert_entity_project=None,
        alert_summary=None,
        event_name=None,
        severity=None,
        criteria=None,
        notifications=None,
        reset_policy=None,
    ):
        # Use provided values or fallback to the current alert's attributes
        alert_data = self._generate_alert_create_request(
            project=project_name,
            name=alert.name,
            entity_kind=alert_entity_kind or alert.entities.kind,
            entity_project=alert_entity_project or alert.project,
            summary=alert_summary or alert.summary,
            event_name=event_name or alert.trigger.events[0].name,
            severity=severity or alert.severity,
            criteria=criteria or alert.criteria,
            # notification needs to be sent every time due to not having secret params in the client side
            notifications=notifications,
            reset_policy=reset_policy or alert.reset_policy,
        )
        return mlrun.get_run_db().store_alert_config(
            alert.name, alert_data, project_name
        )

    def _post_event(self, project_name, event_name, alert_entity_kind):
        event_data = self._generate_event_request(
            project_name, event_name, alert_entity_kind
        )
        mlrun.get_run_db().generate_event(event_name, event_data, project=project_name)

    def _validate_alert_activation(
        self,
        alert_activation: mlrun.common.schemas.alert.AlertActivation,
        project_name=None,
        alert_name=None,
        alert_event_name=None,
        alert_severity=None,
        alert_criteria=None,
        alert_entity_id=None,
        alert_entity_kind=None,
        alert_event_kind=None,
        number_of_events=None,
        alert_notifications=None,
    ):
        assert alert_activation.id is not None
        if project_name:
            assert alert_activation.project == project_name
        if alert_name:
            assert alert_activation.name == alert_name
        if alert_event_name:
            assert alert_event_name in [
                notification.event_name
                for notification in alert_activation.notifications
            ]
        if alert_severity:
            assert alert_activation.severity == alert_severity
        if alert_criteria:
            assert alert_activation.criteria.period == alert_criteria.period
            assert alert_activation.criteria.count == alert_criteria.count
        if alert_entity_id:
            assert alert_activation.entity_id == alert_entity_id
        if alert_entity_kind:
            assert alert_activation.entity_kind == alert_entity_kind
        if alert_event_kind:
            assert alert_activation.event_kind == alert_event_kind
        if number_of_events:
            assert alert_activation.number_of_events == number_of_events
        if alert_notifications:
            assert alert_activation.notifications == alert_notifications

        alert = self._get_alerts(project_name, alert_name)
        if alert.reset_policy == mlrun.common.schemas.alert.ResetPolicy.AUTO:
            assert alert_activation.activation_time == alert_activation.reset_time
        elif alert.state == "active":
            assert alert_activation.reset_time is None
        else:
            assert alert_activation.reset_time > alert_activation.activation_time

    @staticmethod
    def _get_alerts(project_name, name=None):
        if name:
            response = mlrun.get_run_db().get_alert_config(name, project_name)
        else:
            response = mlrun.get_run_db().list_alerts_configs(project_name)
        return response

    @staticmethod
    def _get_alert_activations(project_name="*", alert_name=None):
        return mlrun.get_run_db().list_alert_activations(
            project=project_name, name=alert_name
        )

    @staticmethod
    def _reset_alert(project_name, name):
        mlrun.get_run_db().reset_alert_config(name, project_name)

    @staticmethod
    def _delete_alert(project_name, name):
        mlrun.get_run_db().delete_alert_config(name, project_name)

    @staticmethod
    def _validate_alert(
        alert,
        project_name=None,
        alert_name=None,
        alert_summary=None,
        alert_state=None,
        alert_event_name=None,
        alert_description=None,
        alert_severity=None,
        alert_trigger=None,
        alert_criteria=None,
        alert_reset_policy=None,
        alert_entity=None,
        alert_notifications=None,
        alert_count=None,
        alert_updated=False,
    ):
        if project_name:
            assert alert.project == project_name
        if alert_name:
            assert alert.name == alert_name
        if alert_summary:
            assert alert.summary == alert_summary
        if alert_state:
            assert alert.state == alert_state
        if alert_event_name:
            assert alert.trigger.events == [alert_event_name]
        if alert_description:
            assert alert.description == alert_description
        if alert_severity:
            assert alert.severity == alert_severity
        if alert_trigger:
            assert alert.trigger == alert_trigger
        if alert_criteria:
            assert alert.criteria.period == alert_criteria.period
            assert alert.criteria.count == alert_criteria.count
        if alert_reset_policy:
            assert alert.reset_policy == alert_reset_policy
        if alert_entity:
            assert alert.entities == alert_entity
        if alert_notifications:
            assert alert.notifications == alert_notifications
        if alert_count:
            assert alert.count == alert_count
        if alert_updated:
            assert alert.updated > alert.created.replace(tzinfo=timezone.utc)

    @staticmethod
    def _generate_event_request(project, event_kind, entity_kind):
        return mlrun.common.schemas.Event(
            kind=event_kind,
            entity={"kind": entity_kind, "project": project, "ids": [1234]},
            value_dict={"value": 0.2},
        )

    @staticmethod
    def _generate_alert_create_request(
        project,
        name,
        entity_kind,
        entity_project,
        summary,
        event_name,
        severity,
        criteria,
        notifications,
        reset_policy,
    ):
        if notifications is None:
            notifications = [
                {
                    "notification": {
                        "kind": "slack",
                        "name": "slack_drift",
                        "secret_params": {
                            "webhook": "https://hooks.slack.com/services/",
                        },
                    }
                }
            ]
        return mlrun.alerts.alert.AlertConfig(
            project=project,
            name=name,
            summary=summary,
            severity=severity,
            entities={"kind": entity_kind, "project": entity_project, "ids": [1234]},
            trigger={"events": [event_name]},
            criteria=criteria,
            notifications=notifications,
            reset_policy=reset_policy,
        )

    @staticmethod
    def _get_template_by_name(templates, name):
        for template in templates:
            if template.template_name == name:
                return template
        return None
