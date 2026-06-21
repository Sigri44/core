"""Support for MQTT infrared platform."""

from base64 import b64decode, b64encode
from collections.abc import Callable
import logging
from struct import pack, unpack
from typing import TYPE_CHECKING, Any, TypedDict

import orjson
import voluptuous as vol

from homeassistant.components import infrared
from homeassistant.components.infrared import (
    InfraredCommand,
    InfraredEmitterEntity,
    InfraredReceivedSignal,
    InfraredReceiverEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME, CONF_VALUE_TEMPLATE
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.service_info.mqtt import ReceivePayloadType
from homeassistant.helpers.typing import ConfigType, VolSchemaType
from homeassistant.util.json import JSON_DECODE_EXCEPTIONS, json_loads_object

from . import subscription
from .config import MQTT_BASE_SCHEMA
from .const import (
    CONF_COMMAND_TEMPLATE,
    CONF_COMMAND_TOPIC,
    CONF_INFRARED_ENCODING,
    CONF_RETAIN,
    CONF_SCHEMA,
    CONF_STATE_TOPIC,
    DEFAULT_RETAIN,
    DOMAIN,
    PAYLOAD_NONE,
)
from .entity import MqttEntity, async_setup_entity_entry_helper
from .models import (
    MqttCommandTemplate,
    MqttValueTemplate,
    PublishPayloadType,
    ReceiveMessage,
)
from .schemas import MQTT_ENTITY_COMMON_SCHEMA
from .util import valid_publish_topic, valid_subscribe_topic

_LOGGER = logging.getLogger(__name__)

PARALLEL_UPDATES = 0

DEFAULT_EMITTER_NAME = "MQTT Infrared emitter"
DEFAULT_RECEIVER_NAME = "MQTT Infrared receiver"

MQTT_INFRARED_ATTRIBUTES_BLOCKED: frozenset[str] = frozenset()

SIGNAL_SCHEMA = vol.Schema(
    {
        vol.Required("timings"): [int],
        vol.Required("modulation"): int,
    },
    extra=vol.REMOVE_EXTRA,
)


class SignalMessage(TypedDict):
    """Represents received infrared message."""

    modulation: int
    timings: list[int]


def validate_mqtt_infrared_config(config_value: dict[str, Any]) -> ConfigType:
    """Validate MQTT infrared entity config schema."""
    schemas: dict[str, VolSchemaType] = {
        "emitter": EMITTER_SCHEMA,
        "receiver": RECEIVER_SCHEMA,
    }
    config: ConfigType = schemas[config_value[CONF_SCHEMA]](config_value)
    return config


def validate_mqtt_infrared_discovery(config_value: dict[str, Any]) -> ConfigType:
    """Validate MQTT infrared entity discovery schema."""
    schemas: dict[str, VolSchemaType] = {
        "emitter": EMITTER_SCHEMA.extend({}, extra=vol.REMOVE_EXTRA),
        "receiver": RECEIVER_SCHEMA.extend({}, extra=vol.REMOVE_EXTRA),
    }
    config: ConfigType = schemas[config_value[CONF_SCHEMA]](config_value)
    return config


INFRARED_BASE_SCHEMA = vol.Schema(
    {vol.Required(CONF_SCHEMA): vol.All(vol.Lower, vol.Any("emitter", "receiver"))},
    extra=vol.ALLOW_EXTRA,
)

EMITTER_SCHEMA = MQTT_BASE_SCHEMA.extend(
    {
        vol.Required(CONF_SCHEMA): "emitter",
        vol.Required(CONF_COMMAND_TOPIC): valid_publish_topic,
        vol.Optional(CONF_COMMAND_TEMPLATE): cv.template,
        vol.Optional(CONF_RETAIN, default=DEFAULT_RETAIN): cv.boolean,
        vol.Optional(CONF_NAME): vol.Any(cv.string, None),
        vol.Optional(CONF_INFRARED_ENCODING, default="raw"): vol.Any("raw", "tuya_b64"),
    }
).extend(MQTT_ENTITY_COMMON_SCHEMA.schema)

RECEIVER_SCHEMA = MQTT_BASE_SCHEMA.extend(
    {
        vol.Required(CONF_SCHEMA): "receiver",
        vol.Required(CONF_STATE_TOPIC): valid_subscribe_topic,
        vol.Optional(CONF_VALUE_TEMPLATE): cv.template,
        vol.Optional(CONF_NAME): vol.Any(cv.string, None),
        vol.Optional(CONF_INFRARED_ENCODING, default="raw"): vol.Any("raw", "tuya_b64"),
    }
).extend(MQTT_ENTITY_COMMON_SCHEMA.schema)

PLATFORM_SCHEMA_MODERN = vol.All(
    INFRARED_BASE_SCHEMA,
    validate_mqtt_infrared_config,
)
DISCOVERY_SCHEMA = vol.All(
    INFRARED_BASE_SCHEMA,
    validate_mqtt_infrared_discovery,
)


def decode_tuya_timings(b64_string: str) -> list[int]:
    """Decode the original Tuya Base64 code (including LZ77 compression).

    Returns raw IR timings (microseconds).
    """

    try:
        compressed_bytes = b64decode(b64_string)
    except ValueError as exc:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="bad_base64_string",
            translation_placeholders={"b64_string": b64_string},
        ) from exc

    decompressed = bytearray()
    pos = 0

    try:
        while pos < len(compressed_bytes):
            header = compressed_bytes[pos]
            pos += 1
            block_type = header >> 5

            if block_type == 0:
                # Literal block
                length = (header & 0x1F) + 1
                decompressed.extend(compressed_bytes[pos : pos + length])
                pos += length

            else:
                # Reference block
                length = block_type + 2
                if length == 9:
                    while compressed_bytes[pos] == 255:
                        length += 255
                        pos += 1
                    length += compressed_bytes[pos]
                    pos += 1

                distance = ((header & 0x1F) << 8) + compressed_bytes[pos]
                pos += 1
                offset = distance + 1

                for _ in range(length):
                    decompressed.append(decompressed[-offset])

    except IndexError:
        # Truncated or malformed compressed stream → stop decoding
        _LOGGER.debug("Partly decoded infrared code, got %s", b64_string)

    num_timings = len(decompressed) // 2
    timings = unpack(f"<{num_timings}H", decompressed[: num_timings * 2])
    return [timings[i] * -1 if i % 2 else timings[i] for i in range(len(timings))]


def encode_tuya_timings(timings: list[int]) -> str:
    """Encodes raw timings to Tuya Base64 without LZ77 compression.

    Using 'Level 0' prevents hardware crashes on cheap Tuya IR chips.
    """
    raw_bytes = pack(f"<{len(timings)}H", *(abs(t) for t in timings))
    compressed = bytearray()
    pos = 0

    while pos < len(raw_bytes):
        chunk = raw_bytes[pos : pos + 32]
        # Level 0 block header: 3 MSB = 0, 5 LSB = length - 1
        compressed.append(len(chunk) - 1)
        compressed.extend(chunk)
        pos += 32

    return b64encode(compressed).decode("utf-8")


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up MQTT infrared device through YAML and through MQTT discovery."""
    async_setup_entity_entry_helper(
        hass,
        config_entry,
        None,
        infrared.DOMAIN,
        async_add_entities,
        DISCOVERY_SCHEMA,
        PLATFORM_SCHEMA_MODERN,
        schema_class_mapping={
            "emitter": MqttInfraredEmitterEntity,
            "receiver": MqttInfraredReceiverEntity,
        },
    )


class MqttInfraredEmitterEntity(MqttEntity, InfraredEmitterEntity):
    """Representation of the MQTT infrared emitter entity."""

    _attributes_extra_blocked = MQTT_INFRARED_ATTRIBUTES_BLOCKED
    _default_name = DEFAULT_EMITTER_NAME
    _entity_id_format = infrared.ENTITY_ID_FORMAT

    _command_template: Callable[
        [PublishPayloadType, dict[str, Any]], PublishPayloadType
    ]
    _ir_encoding: str

    @staticmethod
    def config_schema() -> VolSchemaType:
        """Return the config schema."""
        return DISCOVERY_SCHEMA

    def _setup_from_config(self, config: ConfigType) -> None:
        """(Re)Setup the entity."""
        self._command_template = MqttCommandTemplate(
            config.get(CONF_COMMAND_TEMPLATE),
            entity=self,
        ).async_render
        self._ir_encoding = config[CONF_INFRARED_ENCODING]

    @callback
    def _prepare_subscribe_topics(self) -> None:
        """(Re)Subscribe to topics."""

    async def _subscribe_topics(self) -> None:
        """(Re)Subscribe to topics."""

    async def async_send_command(self, command: InfraredCommand) -> None:
        """Send an IR command via MQTT."""
        timings = command.get_raw_timings()
        command_vars: dict[str, Any] = {
            "timings": timings,
            "modulation": command.modulation,
            "repeat_count": command.repeat_count,
        }
        if self._ir_encoding == "tuya_b64":
            if command.repeat_count:
                _LOGGER.warning(
                    "Ignoring repeat count for %s when publishing infrared signal, "
                    "repeat count is not supported with this configuration",
                    self.entity_id,
                )
            if command.modulation != 38000:
                raise ServiceValidationError(
                    translation_domain=DOMAIN,
                    translation_key="modulation_not_supported",
                    translation_placeholders={"modulation": command.modulation},
                )
            payload = self._command_template(encode_tuya_timings(timings), command_vars)
        else:
            payload = self._command_template(
                orjson.dumps(command_vars).decode(), command_vars
            )
        await self.async_publish_with_config(self._config[CONF_COMMAND_TOPIC], payload)


class MqttInfraredReceiverEntity(MqttEntity, InfraredReceiverEntity):
    """Representation of the MQTT infrared receiver entity."""

    _attributes_extra_blocked = MQTT_INFRARED_ATTRIBUTES_BLOCKED
    _default_name = DEFAULT_RECEIVER_NAME
    _entity_id_format = infrared.ENTITY_ID_FORMAT

    _value_template: Callable[[ReceivePayloadType], ReceivePayloadType]
    _ir_encoding: str

    @staticmethod
    def config_schema() -> VolSchemaType:
        """Return the config schema."""
        return DISCOVERY_SCHEMA

    def _setup_from_config(self, config: ConfigType) -> None:
        """(Re)Setup the entity."""
        self._value_template = MqttValueTemplate(
            config.get(CONF_VALUE_TEMPLATE),
            entity=self,
        ).async_render_with_possible_json_value
        self._ir_encoding = config[CONF_INFRARED_ENCODING]

    @callback
    def _handle_state_message_received(self, msg: ReceiveMessage) -> None:
        """Handle receiving state message via MQTT."""
        payload = self._value_template(msg.payload)
        if not payload or payload == PAYLOAD_NONE:
            _LOGGER.debug(
                "Ignoring payload for %s on topic %s, with template %s",
                self.entity_id,
                self._config[CONF_STATE_TOPIC],
                self._config.get(CONF_VALUE_TEMPLATE),
            )
            return
        if self._ir_encoding == "tuya_b64":
            if TYPE_CHECKING:
                assert isinstance(payload, str)
            try:
                timings = decode_tuya_timings(payload)
            except HomeAssistantError as exc:
                _LOGGER.warning(
                    "Invalid message %s received for %s on topic %s, with template %s. "
                    "Message is not a valid signal base64 encoded IR message. "
                    "Error: %s",
                    msg.payload,
                    self.entity_id,
                    self._config[CONF_STATE_TOPIC],
                    self._config.get(CONF_VALUE_TEMPLATE),
                    exc,
                )
            else:
                signal_message = SignalMessage(
                    modulation=38000,
                    timings=timings,
                )
                self._handle_received_signal(InfraredReceivedSignal(**signal_message))

            return
        try:
            payload_dict = SIGNAL_SCHEMA(json_loads_object(payload))
            signal_message = SignalMessage(
                modulation=payload_dict["modulation"],
                timings=payload_dict["timings"],
            )
        except (*JSON_DECODE_EXCEPTIONS, vol.Invalid, TypeError):
            _LOGGER.warning(
                "Invalid message received for %s on topic %s, with template %s. "
                "Message is not a valid signal JSON message. Got %s",
                self.entity_id,
                self._config[CONF_STATE_TOPIC],
                self._config.get(CONF_VALUE_TEMPLATE),
                msg.payload,
            )
        else:
            self._handle_received_signal(InfraredReceivedSignal(**signal_message))

    @callback
    def _prepare_subscribe_topics(self) -> None:
        """(Re)Subscribe to topics."""
        self.add_subscription(
            CONF_STATE_TOPIC,
            self._handle_state_message_received,
            None,
        )

    async def _subscribe_topics(self) -> None:
        """(Re)Subscribe to topics."""
        subscription.async_subscribe_topics_internal(self.hass, self._sub_state)
