"""Authoring-time checks for a hunt's correlate block.

These run in the hunt validation path (`ace hunt validate` / `POST /api/hunt/validate`), not
during normal hunt loading -- a production node should not refuse to load a hunt at startup.
The equivalent runtime guards in `commands.py` cover what gets past here.
"""

from collections.abc import Iterator
import logging
from typing import Optional, Union

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.expressions import build_jinja_context
from saq.collectors.hunter.correlation.schema import (
    CommandConfig,
    ConditionConfig,
    CorrelateConfig,
    PredefinedCommandConfig,
    StepConfig,
    TransformConfig,
)
from saq.configuration.config import get_config
from saq.configuration.yaml_parser import ENCRYPTED_PREFIX
from saq.observables.mapping import ObservableMapping
from saq.query.config import SummaryDetailConfig

_jinja_env = SandboxedEnvironment()

# stands in for a real credential while probing an env template, so a value that legitimately
# reads `_secrets` renders without needing the store.
_PROBE_SECRET = "PROBE_SECRET_VALUE"


class _ProbeSecrets(dict):
    """A `_secrets` stand-in that answers every lookup with the same placeholder."""

    def __missing__(self, key):
        return _PROBE_SECRET


def iter_correlate_commands(logic_steps: list[StepConfig]) -> Iterator[CommandConfig]:
    """Yield every command in a correlation logic tree, in document order.

    Transforms can be nested inside conditional steps, so this recurses through
    ConditionConfig.execute / else_ -- same shape as collect_correlate_steps in query_hunter.
    """
    for step_config in logic_steps:
        inner = step_config.step
        if isinstance(inner, TransformConfig):
            yield inner.command
        elif isinstance(inner, ConditionConfig):
            yield from iter_correlate_commands(inner.execute)
            if inner.else_:
                yield from iter_correlate_commands(inner.else_)


def iter_correlate_property_names(logic_steps: list[StepConfig]) -> Iterator[str]:
    """Yield the property_name of every property transform in a logic tree, in document order.

    Same traversal as iter_correlate_commands; only `method: property` transforms write a
    named value onto the event, so those are the only ones with output to account for.
    """
    for step_config in logic_steps:
        inner = step_config.step
        if isinstance(inner, TransformConfig):
            if inner.method == "property" and inner.property_name:
                yield inner.property_name
        elif isinstance(inner, ConditionConfig):
            yield from iter_correlate_property_names(inner.execute)
            if inner.else_:
                yield from iter_correlate_property_names(inner.else_)


def check_env_for_encrypted_markers(
    correlate_config: Optional[CorrelateConfig],
    predefined_commands: Optional[list[PredefinedCommandConfig]] = None,
    config: Optional[dict] = None,
) -> list[str]:
    """Return one error string per `env:` value that renders to an unresolved secret marker.

    An `encrypted:<name>` marker survives unresolved in the raw merged config dict bound as
    `_config`, so reading a credential that way hands the marker to the helper script instead
    of the credential -- which fails against the vendor with an unrelated-looking auth error.

    Each template is rendered rather than parsed: rendering handles composed strings and
    dynamic indexing that a static read of the jinja expression would miss.
    """
    if config is None:
        try:
            config = get_config().raw._data
        except Exception:
            logging.warning("unable to load config for hunt env validation", exc_info=True)
            return []

    # isinstance rather than a None check: a hunt type without a correlate block, or one whose
    # config never parsed a `commands` list, simply has nothing to check here.
    commands: list[Union[CommandConfig, PredefinedCommandConfig]] = []
    if isinstance(correlate_config, CorrelateConfig):
        commands.extend(iter_correlate_commands(correlate_config.logic))
    if isinstance(predefined_commands, list):
        commands.extend(c for c in predefined_commands if isinstance(c, PredefinedCommandConfig))
    if not commands:
        return []

    context = build_jinja_context({}, [], config)
    context["_secrets"] = _ProbeSecrets()

    errors = []
    for command in commands:
        if not command.env:
            continue
        label = getattr(command, "name", None) or command.path
        for key, value in command.env.items():
            try:
                rendered = _jinja_env.from_string(value).render(**context)
            except Exception as e:
                # a render failure here is not necessarily a hunt error -- the probe context has
                # no event data -- so it is not reported as one.
                logging.debug("unable to probe env %s of %s: %s", key, label, e)
                continue
            if ENCRYPTED_PREFIX in rendered:
                errors.append(
                    f"command {label!r}: env {key} resolves to an unresolved "
                    f"{ENCRYPTED_PREFIX!r} marker ({rendered!r}). Encrypted secrets are not "
                    f"available through _config; read the secret with _secrets['<name>'] "
                    f"instead, keyed on the encrypted-password store key name."
                )

    return errors


def _mapping_field_roots(mapping: ObservableMapping) -> Iterator[str]:
    """Yield the field names a mapping reads, plus the root segment of each.

    A `field_lookup_type: dot` mapping walks a path (`correlated_logs.*.username`), so the
    correlate property it consumes is the first segment, not the whole spec.
    """
    for field in mapping.get_fields():
        yield field
        root = field.split(".")[0].rstrip("*")
        if root:
            yield root


def _mapping_templates(mapping: ObservableMapping) -> Iterator[str]:
    """Yield every per-event template string on a mapping that renders into the alert."""
    for value in (mapping.value, mapping.type, mapping.display_value, mapping.file_name):
        if value:
            yield value
    yield from (t for t in mapping.tags if t)
    for relationship in mapping.relationships:
        if relationship.target.value:
            yield relationship.target.value


def check_correlate_output_reaches_analyst(
    correlate_config: Optional[CorrelateConfig],
    observable_mapping: Optional[list[ObservableMapping]] = None,
    summary_details: Optional[list[SummaryDetailConfig]] = None,
    extra_templates: Optional[list[str]] = None,
) -> list[str]:
    """Return one warning string per correlate property whose output never reaches the analyst.

    A `property` transform's value is added to the event, but the only ways it becomes
    visible are an observable_mapping that reads the field or a template that renders it.
    A property that neither does is computed, used to steer `when:` branching, and then
    discarded -- which is legitimate for a control-flow boolean and a silent loss of
    evidence for anything else, so this warns rather than rejects.

    Args:
        correlate_config: the hunt's correlate block.
        observable_mapping: the hunt's observable_mapping entries.
        summary_details: the hunt's summary_details entries.
        extra_templates: any other per-event template strings whose rendered output the
            analyst sees (hunt tags, pivot link url/text, description_field, ...).
    """
    if not isinstance(correlate_config, CorrelateConfig):
        return []

    property_names: list[str] = []
    for name in iter_correlate_property_names(correlate_config.logic):
        if name not in property_names:
            property_names.append(name)
    if not property_names:
        return []

    referenced_fields: set[str] = set()
    templates: list[str] = []

    if isinstance(observable_mapping, list):
        for mapping in observable_mapping:
            if not isinstance(mapping, ObservableMapping):
                continue
            referenced_fields.update(_mapping_field_roots(mapping))
            templates.extend(_mapping_templates(mapping))

    if isinstance(summary_details, list):
        for sd_config in summary_details:
            if not isinstance(sd_config, SummaryDetailConfig):
                continue
            templates.append(sd_config.content)
            if sd_config.header:
                templates.append(sd_config.header)

    if extra_templates:
        templates.extend(t for t in extra_templates if t)

    # substring match over the joined templates: a property is referenced as
    # `{{ name }}`, `_event['name']`, `events | map(attribute='name')` and more, and a
    # false negative here (no warning) is cheaper than a false positive on a hunt that
    # does surface the value in a shape a stricter parser would miss.
    template_text = "\n".join(templates)

    warnings = []
    for name in property_names:
        if name in referenced_fields or name in template_text:
            continue
        warnings.append(
            f"correlate property {name!r} is never referenced by summary_details or "
            f"observable_mapping, so its output never reaches the analyst"
        )

    return warnings
