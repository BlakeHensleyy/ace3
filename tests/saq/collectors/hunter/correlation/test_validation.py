from unittest.mock import MagicMock, patch

import pytest

from saq.collectors.hunter.correlation.schema import CorrelateConfig, PredefinedCommandConfig
from saq.collectors.hunter.correlation.validation import (
    check_correlate_output_reaches_analyst,
    check_env_for_encrypted_markers,
    iter_correlate_commands,
    iter_correlate_property_names,
)
from saq.constants import F_EMAIL_ADDRESS, F_USER
from saq.observables.mapping import ObservableMapping
from saq.query.config import SummaryDetailConfig

CONFIG = {
    "rapid7": {"api_key": "encrypted:rapid7.api_key"},
    "wiz": {"client_id": "abc123"},
}


def _correlate(*commands) -> CorrelateConfig:
    return CorrelateConfig.model_validate({
        "logic": [
            {
                "transform": {
                    "type": "event",
                    "method": "property",
                    "property_name": f"p{i}",
                    "command": command,
                },
            }
            for i, command in enumerate(commands)
        ],
    })


@pytest.mark.unit
class TestIterCorrelateCommands:

    def test_walks_nested_conditions(self):
        config = CorrelateConfig.model_validate({
            "logic": [
                {
                    "when": "{{ _event.x }}",
                    "execute": [
                        {"transform": {"method": "property", "property_name": "a",
                                       "command": {"type": "defined", "name": "cmd_a"}}},
                    ],
                    "else": [
                        {"transform": {"method": "property", "property_name": "b",
                                       "command": {"type": "defined", "name": "cmd_b"}}},
                    ],
                },
                {"transform": {"method": "property", "property_name": "c",
                               "command": {"type": "defined", "name": "cmd_c"}}},
            ],
        })
        assert [c.name for c in iter_correlate_commands(config.logic)] == ["cmd_a", "cmd_b", "cmd_c"]


@pytest.mark.unit
class TestCheckEnvForEncryptedMarkers:

    def test_config_reference_to_encrypted_secret_is_rejected(self):
        """The reported rapid7 bug, caught before the hunt ever runs."""
        correlate = _correlate({
            "type": "executable",
            "path": "/x/r7.py",
            "env": {"R7_API_KEY": "{{ _config['rapid7']['api_key'] }}"},
        })
        errors = check_env_for_encrypted_markers(correlate, None, CONFIG)
        assert len(errors) == 1
        assert "R7_API_KEY" in errors[0]
        assert "_secrets" in errors[0]

    def test_predefined_command_env_is_checked(self):
        """Every real secret consumer is a predefined command in a shared include file."""
        predefined = [PredefinedCommandConfig.model_validate({
            "name": "get_r7_investigation_comments",
            "type": "executable",
            "path": "/x/r7.py",
            "env": {"R7_API_KEY": "{{ _config['rapid7']['api_key'] }}"},
        })]
        errors = check_env_for_encrypted_markers(None, predefined, CONFIG)
        assert len(errors) == 1
        assert "get_r7_investigation_comments" in errors[0]

    def test_secrets_reference_is_accepted(self):
        predefined = [PredefinedCommandConfig.model_validate({
            "name": "get_r7_investigation_comments",
            "type": "executable",
            "path": "/x/r7.py",
            "env": {"R7_API_KEY": "{{ _secrets['rapid7.api_key'] }}"},
        })]
        assert check_env_for_encrypted_markers(None, predefined, CONFIG) == []

    def test_plaintext_config_reference_is_accepted(self):
        correlate = _correlate({
            "type": "executable",
            "path": "/x/wiz.py",
            "env": {"WIZ_CLIENT_ID": "{{ _config['wiz']['client_id']}}"},
        })
        assert check_env_for_encrypted_markers(correlate, None, CONFIG) == []

    def test_marker_composed_into_a_longer_value_is_rejected(self):
        correlate = _correlate({
            "type": "executable",
            "path": "/x/a.py",
            "env": {"CERT_PATH": "/opt/ace/{{ _config['rapid7']['api_key'] }}"},
        })
        assert len(check_env_for_encrypted_markers(correlate, None, CONFIG)) == 1

    def test_hardcoded_marker_is_rejected(self):
        correlate = _correlate({
            "type": "executable",
            "path": "/x/a.py",
            "env": {"R7_API_KEY": "encrypted:rapid7.api_key"},
        })
        assert len(check_env_for_encrypted_markers(correlate, None, CONFIG)) == 1

    def test_env_referencing_event_data_is_not_reported(self):
        """The probe context has no event data, so an unresolvable event field is not an error."""
        correlate = _correlate({
            "type": "executable",
            "path": "/x/a.py",
            "env": {"USER": "{{ _event['properties.userId'] }}"},
        })
        assert check_env_for_encrypted_markers(correlate, None, CONFIG) == []

    def test_commands_without_env_are_skipped(self):
        correlate = _correlate({"type": "defined", "name": "cmd"})
        assert check_env_for_encrypted_markers(correlate, None, CONFIG) == []

    def test_non_correlate_hunt_is_a_no_op(self):
        assert check_env_for_encrypted_markers(None, None, CONFIG) == []

    def test_unparsed_config_objects_are_ignored(self):
        """A hunt type whose config exposes something other than the parsed models."""
        assert check_env_for_encrypted_markers(MagicMock(), MagicMock(), CONFIG) == []

    def test_falls_back_to_live_config_when_none_supplied(self):
        correlate = _correlate({
            "type": "executable",
            "path": "/x/r7.py",
            "env": {"R7_API_KEY": "{{ _config['rapid7']['api_key'] }}"},
        })
        mock_raw = MagicMock()
        mock_raw._data = CONFIG
        with patch("saq.collectors.hunter.correlation.validation.get_config",
                   return_value=MagicMock(raw=mock_raw)):
            assert len(check_env_for_encrypted_markers(correlate)) == 1


def _correlate_properties(*names, nested: bool = False) -> CorrelateConfig:
    """A correlate block with one property transform per name."""
    def _transform(name):
        return {
            "transform": {
                "type": "event",
                "method": "property",
                "property_name": name,
                "command": {"type": "defined", "name": f"cmd_{name}"},
            },
        }

    if nested:
        return CorrelateConfig.model_validate({
            "logic": [{"when": "{{ True }}", "execute": [_transform(n) for n in names]}],
        })
    return CorrelateConfig.model_validate({"logic": [_transform(n) for n in names]})


@pytest.mark.unit
class TestIterCorrelatePropertyNames:

    def test_walks_nested_conditions(self):
        config = CorrelateConfig.model_validate({
            "logic": [
                {
                    "when": "{{ _event.x }}",
                    "execute": [
                        {"transform": {"method": "property", "property_name": "a",
                                       "command": {"type": "defined", "name": "cmd_a"}}},
                    ],
                    "else": [
                        {"transform": {"method": "property", "property_name": "b",
                                       "command": {"type": "defined", "name": "cmd_b"}}},
                    ],
                },
                {"transform": {"method": "property", "property_name": "c",
                               "command": {"type": "defined", "name": "cmd_c"}}},
            ],
        })
        assert list(iter_correlate_property_names(config.logic)) == ["a", "b", "c"]

    def test_non_property_transforms_are_skipped(self):
        config = CorrelateConfig.model_validate({
            "logic": [
                {"transform": {"type": "stream", "method": "mutate",
                               "command": {"type": "defined", "name": "cmd"}}},
            ],
        })
        assert list(iter_correlate_property_names(config.logic)) == []


@pytest.mark.unit
class TestCheckCorrelateOutputReachesAnalyst:

    def test_unreferenced_property_is_reported(self):
        warnings = check_correlate_output_reaches_analyst(
            _correlate_properties("is_service_account"),
            [ObservableMapping(field="user", type=F_USER)],
            [SummaryDetailConfig(content="user {{ user }}")],
        )
        assert len(warnings) == 1
        assert "is_service_account" in warnings[0]

    def test_property_referenced_by_summary_detail_content_is_accepted(self):
        assert check_correlate_output_reaches_analyst(
            _correlate_properties("manager"),
            None,
            [SummaryDetailConfig(content="manager: {{ manager }}")],
        ) == []

    def test_property_referenced_by_summary_detail_header_is_accepted(self):
        assert check_correlate_output_reaches_analyst(
            _correlate_properties("manager"),
            None,
            [SummaryDetailConfig(content="static", header="{{ manager }}")],
        ) == []

    def test_property_referenced_by_observable_mapping_field_is_accepted(self):
        assert check_correlate_output_reaches_analyst(
            _correlate_properties("manager_email"),
            [ObservableMapping(field="manager_email", type=F_EMAIL_ADDRESS)],
            None,
        ) == []

    def test_property_referenced_by_dot_path_root_is_accepted(self):
        """A dot-lookup mapping walks into the property, so the root segment counts."""
        assert check_correlate_output_reaches_analyst(
            _correlate_properties("correlated_logs"),
            [ObservableMapping(
                fields=["correlated_logs.*.username"],
                field_lookup_type="dot",
                type=F_USER,
            )],
            None,
        ) == []

    def test_property_referenced_by_mapping_value_template_is_accepted(self):
        assert check_correlate_output_reaches_analyst(
            _correlate_properties("domain"),
            [ObservableMapping(field="user", type=F_USER, value="{{ user }}@{{ domain }}")],
            None,
        ) == []

    def test_property_referenced_by_extra_template_is_accepted(self):
        """Hunt tags, pivot links and the like also put the value in front of the analyst."""
        assert check_correlate_output_reaches_analyst(
            _correlate_properties("risk_score"),
            None,
            None,
            extra_templates=["risk:{{ risk_score }}"],
        ) == []

    def test_nested_properties_are_checked(self):
        warnings = check_correlate_output_reaches_analyst(
            _correlate_properties("a", "b", nested=True),
            None,
            [SummaryDetailConfig(content="{{ a }}")],
        )
        assert len(warnings) == 1
        assert "'b'" in warnings[0]

    def test_duplicate_property_names_report_once(self):
        warnings = check_correlate_output_reaches_analyst(
            _correlate_properties("dupe", "dupe"), None, None,
        )
        assert len(warnings) == 1

    def test_non_correlate_hunt_is_a_no_op(self):
        assert check_correlate_output_reaches_analyst(None, None, None) == []

    def test_unparsed_config_objects_are_ignored(self):
        assert check_correlate_output_reaches_analyst(
            _correlate_properties("x"), [MagicMock()], [MagicMock()],
        ) == [
            "correlate property 'x' is never referenced by summary_details or "
            "observable_mapping, so its output never reaches the analyst"
        ]
