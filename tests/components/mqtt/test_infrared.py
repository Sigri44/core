"""The tests for the MQTT infrared platform."""

import base64
import logging
import struct
from typing import Any

from freezegun.api import FrozenDateTimeFactory
from infrared_protocols.codes.samsung.tv import SamsungTVCode
from infrared_protocols.commands import Command
from infrared_protocols.commands.nec import NECCommand
import orjson
import pytest

from homeassistant.components import infrared, mqtt
from homeassistant.components.mqtt.infrared import decode_tuya_timings
from homeassistant.const import STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.typing import ConfigType
import homeassistant.util.dt as dt_util

from .common import (
    help_custom_config,
    help_test_availability_when_connection_lost,
    help_test_availability_without_topic,
    help_test_discovery_removal,
    help_test_discovery_update_attr,
    help_test_entity_device_info_remove,
    help_test_entity_device_info_update,
    help_test_entity_device_info_with_connection,
    help_test_entity_device_info_with_identifier,
    help_test_entity_id_update_discovery_update,
    help_test_entity_id_update_subscriptions,
    help_test_reloadable,
    help_test_setting_attribute_via_mqtt_json_message,
    help_test_setting_attribute_with_template,
    help_test_setting_blocked_attribute_via_mqtt_json_message,
    help_test_unique_id,
    help_test_unload_config_entry_with_platform,
    help_test_update_with_json_attrs_bad_json,
    help_test_update_with_json_attrs_not_dict,
)

from tests.common import async_fire_mqtt_message
from tests.typing import MqttMockHAClientGenerator, MqttMockPahoClient

DEFAULT_CONFIG_EMITTER = {
    mqtt.DOMAIN: {
        infrared.DOMAIN: {
            "schema": "emitter",
            "name": "test",
            "command_topic": "test-topic",
        }
    }
}
DEFAULT_CONFIG_RECEIVER = {
    mqtt.DOMAIN: {
        infrared.DOMAIN: {
            "schema": "receiver",
            "name": "test",
            "state_topic": "test-topic",
        }
    }
}

TEST_COMMAND1 = NECCommand(address=0x04FB, command=0x08F7, modulation=38000)
TEST_COMMAND2 = SamsungTVCode.POWER.to_command(0)
TEST_COMMAND_1_TUYA_BASE64_PAYLOAD = (
    "HygjlBEyApcGMgKXBjICMgIyApcGMgKXBjIClwYyApcGHzIClwYyAjICMgIyAjIClwYyAjICMgIyAjICMg"
    "IyAjICHzICMgIyApcGMgKXBjIClwYyAjICMgKXBjIClwYyApcGHzIClwYyAjICMgIyAjICMgIyApcGMgIy"
    "AjICMgIyAjICBTICMgIyAg=="
)
TEST_COMMAND_2_TUYA_BASE64_PAYLOAD = (
    "H5QRlBEwApoGMAKaBjACmgYwAjACMAIwAjACMAIwAjACHzACMAIwApoGMAKaBjACmgYwAjACMAIwAjACMA"
    "IwAjACHzACMAIwAjACMAKaBjACMAIwAjACMAIwAjACMAIwAjACHzACMAIwApoGMAIwAjACmgYwApoGMAKa"
    "BjACmgYwApoGBTACmgYwAg=="
)

SAMSUNG_POWER_COMMAND_TUYA_BASE64_REAL_WORLD = (
    "B4gRiBE2ApAG4AED4AsB4BcfQAFAI+APAcAbQAfgCAMCBjYC"
)
SAMSUNG_POWER_COMMAND_TUYA_BASE64_REAL_WORLD_ALT = (
    "B68RrxE2Ao4G4AED4AsB4BcfQAFAI+APAcAbQAfgCwMH3bevEa8RNgLgAxvgCwHgFx9AAUAj4A8BwBtAB+"
    "AIAwIGNgI="
)
# from https://gist.github.com/mildsunrise/1d576669b63a260d2cff35fda63ec0b5
TUYA_BASE64_REAL_WORLD_ALT_2 = (
    "A/IEiwFAAwbJAfIE8gSLIAUBiwFAC+ADAwuLAfIE8gSLAckBRx9AB0ADBskB8gTyBIsgBQGLAUALA4sB8g"
    "RAB8ADBfIEiwHJAeARLwHJAeAFAwHyBOC5LwGLAeA97wOLAfIE4RcfBYsB8gTyBEAFAYsB4AcrCYsB8gTy"
    "BIsByQHgPY8DyQHyBOAHAwHyBEAX4BVfBIsB8gTJoAMF8gSLAckB4BUvAckB4AEDBfIEiwHJAQ=="
)
SAMSUNG_POWER_COMMAND_TIMINGS = TEST_COMMAND2.get_raw_timings()


class CustomCommandNot38k(Command):
    """Custom command based on TEST_COMMAND2 that has a non 38kHz modulation."""

    def get_raw_timings(self) -> list[int]:
        """Return raw timings."""
        return TEST_COMMAND2.get_raw_timings()


TEST_COMMAND3 = CustomCommandNot38k(modulation=10000, repeat_count=0)
TEST_COMMAND4 = CustomCommandNot38k(modulation=38000, repeat_count=1)


def b64_from_bytes(b: bytes) -> str:
    """Help decoding base64 string."""
    return base64.b64encode(b).decode()


def make_literal_block(payload_bytes: bytes) -> bytes:
    """Create a literal block header + payload.

    header: top 3 bits = 0, low 5 bits = length-1
    """
    length = len(payload_bytes)
    assert 1 <= length <= 32
    header = (length - 1) & 0x1F
    return bytes([header]) + payload_bytes


def make_reference_block(
    block_type: int, distance: int, extra_length_bytes: bytes = b""
) -> bytes:
    """Make a reference block.

    Create a reference block header for block_type (1..7), distance (0..65535),
    and optionally include extra bytes that the decoder expects (e.g., 255 and remainder).
    The function returns header + any extra_length_bytes + distance_low_byte.
    Note: distance is encoded as ((header & 0x1F) << 8) + next_byte.
    We'll place the high 5 bits of distance into header low bits and the low byte after.
    """
    assert 1 <= block_type <= 7
    high5 = (distance >> 8) & 0x1F
    low8 = distance & 0xFF
    header = (block_type << 5) | high5
    return bytes([header]) + extra_length_bytes + bytes([low8])


async def test_literal_block_simple_pair() -> None:
    """Test with literal block simple pair."""
    # Two 16-bit timings: 1000 (0x03E8) and 2000 (0x07D0)
    t1 = 1000
    t2 = 2000
    payload = struct.pack("<HH", t1, t2)  # little-endian 16-bit values
    compressed = make_literal_block(payload)
    b64 = b64_from_bytes(compressed)

    result = decode_tuya_timings(b64)
    assert result == [t1, -t2]


async def test_reference_block_small_and_truncation() -> None:
    "Test with small reference block and truncation."
    # Build:
    # 1) literal block with two bytes A,B (one 16-bit timing)
    # 2) reference block with block_type=1 (length=3) and distance=1 (offset=2)
    # This will produce decompressed bytes: [A,B] + [A,B,A] => 5 bytes (odd)
    # Only first 4 bytes (2 timings) are used.
    A = 0x10
    B = 0x00
    literal = make_literal_block(bytes([A, B]))  # one timing: 0x0010 = 16
    ref = make_reference_block(block_type=1, distance=1)  # length = 1+2 = 3
    compressed = literal + ref
    b64 = b64_from_bytes(compressed)

    result = decode_tuya_timings(b64)
    # Decompressed bytes -> [0x10,0x00,0x10,0x00,0x10]
    # Timings (pairs): 0x0010, 0x0010 -> [16, -16]
    assert result == [16, -16]


async def test_extended_length_reference_with_255_loop() -> None:
    """Test with an extended length reference with a 255 loop.

    This test exercises the block_type==7 path (length==9) and the while loop
    that accumulates 255 bytes per 0xFF encountered.
    Plan:
    1) literal block with two bytes [1,0] -> timing 1
    2) reference block with block_type=7 (initial length 9), then one 0xFF,
       then remainder 3 -> length = 9 + 255 + 3 = 267
       distance low5bits = 0, distance_low_byte = 1 -> distance = 1 -> offset = 2
    The reference will copy from offset 2 repeatedly, producing a repeating [1,0,1,0,..]
    Final decompressed length = 2 + 267 = 269 bytes -> 134 full timings (268 bytes)
    extra_length_bytes: first 0xFF then remainder 3.
    """
    literal = make_literal_block(bytes([0x01, 0x00]))  # timing value 1
    extra_length = bytes([255, 3])
    ref = make_reference_block(
        block_type=7, distance=1, extra_length_bytes=extra_length
    )
    compressed = literal + ref
    b64 = b64_from_bytes(compressed)

    result = decode_tuya_timings(b64)
    # Expect 134 timings (268 bytes used), pattern: even indices -> 1, odd indices -> -1
    assert len(result) == 134
    assert result[0] == 1
    assert result[1] == -1
    assert result[2] == 1
    # Check pattern across a sample
    for i, val in enumerate(result[:20]):
        if i % 2 == 0:
            assert val == 1
        else:
            assert val == -1


async def test_eof_handling_truncated_literal_block() -> None:
    """Test EOF handling in a truncated literal block.

    Create a literal header that claims length 3 but only provide 2 bytes.
    The decoder should not raise and should return any full timings available.
    header for length 3 -> header = (3-1) = 2.
    """
    header = bytes([2])
    payload = bytes([0x34, 0x12])  # one full 16-bit timing (0x1234)
    compressed = (
        header + payload
    )  # truncated: header asked for 3 bytes but only 2 provided
    b64 = b64_from_bytes(compressed)

    # Should not raise; should return one timing (0x1234)
    result = decode_tuya_timings(b64)
    assert result == [0x1234]


def test_invalid_base64_raises_homeassistant_error() -> None:
    """Invalid Base64 input must raise HomeAssistantError (bad_base64_string)."""
    with pytest.raises(HomeAssistantError):
        decode_tuya_timings("!!!not_base64!!!")


def test_truncated_literal_block_returns_empty_list() -> None:
    """Test truncates literal block returns an empty list.

    Literal header indicates more payload bytes than present.
    The decoder catches the internal IndexError and should return an empty list.
    """
    # header = 0x02 -> literal length = (0x02 & 0x1F) + 1 = 3
    # provide only one payload byte so decompression is truncated
    compressed: bytes = bytes([0x02, 0xFF])
    b64: str = base64.b64encode(compressed).decode()
    result: list[int] = decode_tuya_timings(b64)
    assert result == []
    assert all(isinstance(x, int) for x in result)


def test_decode_tuya_timings_on_truncated_reference_block() -> None:
    """Create a compressed stream with a reference block header but no distance byte.

    The decoder will try to read compressed_bytes[pos] and raise IndexError.
    Only the partly decoded timings will be returned.
    """
    # Create a header with block_type != 0 (bits 7-5 nonzero).
    # Use block_type = 1 (binary 001) -> header = (1 << 5) | lowbits
    header = (1 << 5) | 0x00
    compressed_bytes = bytes([header])  # no following byte for distance -> truncated
    b64_string = base64.b64encode(compressed_bytes).decode("ascii")

    assert decode_tuya_timings(b64_string) == []


def test_single_byte_payload_returns_empty_list() -> None:
    """Test a single byte payload returns an empty list.

    A valid Base64 that decodes to a single raw byte should not raise.
    The function will treat that as an incomplete timings buffer and return [].
    """
    compressed: bytes = bytes([0x01])  # single raw byte
    b64: str = base64.b64encode(compressed).decode()
    result: list[int] = decode_tuya_timings(b64)
    assert result == []
    assert all(isinstance(x, int) for x in result)


def validate_timings(timings_base: list[int], timings_check: list[int]) -> None:
    """Compare timings and allow 10% deviation."""
    assert len(timings_base) <= len(timings_check)
    for base, check in zip(timings_base, timings_check, strict=False):
        factor = base / check
        assert 0.9 < factor < 1.1


@pytest.mark.parametrize("hass_config", [DEFAULT_CONFIG_RECEIVER])
@pytest.mark.parametrize("command", [TEST_COMMAND1, TEST_COMMAND2])
async def test_receiving_command_success(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    freezer: FrozenDateTimeFactory,
    command: Command,
) -> None:
    """Test receiving an infrared command via subscription is successful."""
    payload_data = {
        "timings": command.get_raw_timings(),
        "modulation": command.modulation,
    }
    payload = orjson.dumps(payload_data).decode()

    now = dt_util.utcnow()
    freezer.move_to(now)

    await mqtt_mock_entry()

    received_signals: list[infrared.InfraredReceivedSignal] = []

    def _handle_received_signal(signal: infrared.InfraredReceivedSignal) -> None:
        """Handle the infrared signal."""
        received_signals.append(signal)

    unsubscribe = infrared.async_subscribe_receiver(
        hass, "infrared.test", _handle_received_signal
    )
    async_fire_mqtt_message(hass, "test-topic", payload, 0, False)
    await hass.async_block_till_done()

    assert len(received_signals) == 1
    signal = received_signals[0]
    assert signal.modulation == command.modulation
    assert signal.timings == command.get_raw_timings()

    state = hass.states.get("infrared.test")
    assert state is not None
    assert state.state == now.isoformat(timespec="milliseconds")

    unsubscribe()


@pytest.mark.parametrize(
    "hass_config",
    [
        help_custom_config(
            infrared.DOMAIN,
            DEFAULT_CONFIG_RECEIVER,
            ({"infrared_encoding": "tuya_b64"},),
        )
    ],
)
@pytest.mark.parametrize(
    ("payload", "timings"),
    [
        (SAMSUNG_POWER_COMMAND_TUYA_BASE64_REAL_WORLD, SAMSUNG_POWER_COMMAND_TIMINGS),
        (
            SAMSUNG_POWER_COMMAND_TUYA_BASE64_REAL_WORLD_ALT,
            SAMSUNG_POWER_COMMAND_TIMINGS,
        ),
    ],
)
async def test_receiving_signal_with_tuya_b64_encoding(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    freezer: FrozenDateTimeFactory,
    payload: str,
    timings: list[int,],
) -> None:
    """Test receiving an Tuya base64 infrared command."""
    now = dt_util.utcnow()
    freezer.move_to(now)

    await mqtt_mock_entry()

    received_signals: list[infrared.InfraredReceivedSignal] = []

    def _handle_received_signal(signal: infrared.InfraredReceivedSignal) -> None:
        """Handle the infrared signal."""
        received_signals.append(signal)

    unsubscribe = infrared.async_subscribe_receiver(
        hass, "infrared.test", _handle_received_signal
    )
    async_fire_mqtt_message(hass, "test-topic", payload, 0, False)
    await hass.async_block_till_done()

    assert len(received_signals) == 1
    signal = received_signals[0]
    assert signal.modulation == 38000
    validate_timings(timings, signal.timings)

    state = hass.states.get("infrared.test")
    assert state is not None
    assert state.state == now.isoformat(timespec="milliseconds")

    unsubscribe()


@pytest.mark.parametrize(
    ("payload", "log_message", "level"),
    [
        (
            "",
            "Ignoring payload for infrared.test on topic test-topic, with template None",
            logging.DEBUG,
        ),
        (
            "None",
            "Ignoring payload for infrared.test on topic test-topic, with template None",
            logging.DEBUG,
        ),
        (
            "invalid",
            "Invalid message received for infrared.test on topic test-topic, with template None",
            logging.WARNING,
        ),
        (
            '{"timings":null}',
            "Invalid message received for infrared.test on topic test-topic, with template None",
            logging.WARNING,
        ),
        (
            '{"timings":[]}',
            "Invalid message received for infrared.test on topic test-topic, with template None",
            logging.WARNING,
        ),
        (
            '{"timings":["1","2"],"modulation":38000}',
            "Invalid message received for infrared.test on topic test-topic, with template None",
            logging.WARNING,
        ),
    ],
)
@pytest.mark.parametrize("hass_config", [DEFAULT_CONFIG_RECEIVER])
async def test_receiving_command_unsuccessful(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    caplog: pytest.LogCaptureFixture,
    payload: str,
    log_message: str,
    level: int,
) -> None:
    """Test receiving an infrared command via subscription fails."""
    await mqtt_mock_entry()

    received_signals: list[infrared.InfraredReceivedSignal] = []

    def _handle_received_signal(signal: infrared.InfraredReceivedSignal) -> None:
        """Handle the infrared signal."""
        received_signals.append(signal)

    unsubscribe = infrared.async_subscribe_receiver(
        hass, "infrared.test", _handle_received_signal
    )

    with caplog.at_level(level):
        async_fire_mqtt_message(hass, "test-topic", payload, 0, False)
        await hass.async_block_till_done()
        assert log_message in caplog.text

    assert len(received_signals) == 0

    state = hass.states.get("infrared.test")
    assert state is not None
    assert state.state == STATE_UNKNOWN

    unsubscribe()


@pytest.mark.parametrize(
    ("payload", "log_message", "level"),
    [
        (
            "--invalid--",
            "Message is not a valid signal base64 encoded IR message. "
            "Error: Bad base64 string, cannot decode --invalid--",
            logging.WARNING,
        ),
    ],
)
@pytest.mark.parametrize(
    "hass_config",
    [
        help_custom_config(
            infrared.DOMAIN,
            DEFAULT_CONFIG_RECEIVER,
            ({"infrared_encoding": "tuya_b64"},),
        )
    ],
)
async def test_receiving_command_with_tuya_b64_encoding_unsuccessful(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    caplog: pytest.LogCaptureFixture,
    payload: str,
    log_message: str,
    level: int,
) -> None:
    """Test receiving an infrared command via subscription fails."""
    await mqtt_mock_entry()

    received_signals: list[infrared.InfraredReceivedSignal] = []

    def _handle_received_signal(signal: infrared.InfraredReceivedSignal) -> None:
        """Handle the infrared signal."""
        received_signals.append(signal)

    unsubscribe = infrared.async_subscribe_receiver(
        hass, "infrared.test", _handle_received_signal
    )

    with caplog.at_level(level):
        async_fire_mqtt_message(hass, "test-topic", payload, 0, False)
        await hass.async_block_till_done()
        assert log_message in caplog.text

    assert len(received_signals) == 0

    state = hass.states.get("infrared.test")
    assert state is not None
    assert state.state == STATE_UNKNOWN

    unsubscribe()


@pytest.mark.parametrize("hass_config", [DEFAULT_CONFIG_EMITTER])
@pytest.mark.parametrize("command", [TEST_COMMAND1, TEST_COMMAND2, TEST_COMMAND3])
async def test_async_send_command_success(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    freezer: FrozenDateTimeFactory,
    command: Command,
) -> None:
    """Test sending command via async_send_command helper."""
    now = dt_util.utcnow()
    freezer.move_to(now)

    mqtt_mock = await mqtt_mock_entry()

    expected_payload_data = {
        "timings": command.get_raw_timings(),
        "modulation": command.modulation,
        "repeat_count": command.repeat_count,
    }
    expected_payload = orjson.dumps(expected_payload_data).decode()

    await infrared.async_send_command(hass, "infrared.test", command)

    mqtt_mock.async_publish.assert_called_with(
        "test-topic", expected_payload, 0, False, message_expiry_interval=None
    )

    state = hass.states.get("infrared.test")
    assert state is not None
    assert state.state == now.isoformat(timespec="milliseconds")


@pytest.mark.parametrize(
    ("hass_config", "exception"),
    [
        (
            help_custom_config(
                infrared.DOMAIN,
                DEFAULT_CONFIG_EMITTER,
                ({"infrared_encoding": "tuya_b64"},),
            ),
            HomeAssistantError,
        )
    ],
)
@pytest.mark.parametrize("command", [TEST_COMMAND3])
async def test_async_send_command_fails(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    freezer: FrozenDateTimeFactory,
    command: Command,
    exception: Exception,
) -> None:
    """Test sending command fails."""
    now = dt_util.utcnow()
    freezer.move_to(now)

    mqtt_mock = await mqtt_mock_entry()

    with pytest.raises(exception):
        await infrared.async_send_command(hass, "infrared.test", command)

    mqtt_mock.async_publish.assert_not_called()

    state = hass.states.get("infrared.test")
    assert state is not None
    assert state.state == STATE_UNKNOWN


@pytest.mark.parametrize(
    ("hass_config", "expected_payload"),
    [
        (
            help_custom_config(
                infrared.DOMAIN,
                DEFAULT_CONFIG_EMITTER,
                ({"infrared_encoding": "tuya_b64"},),
            ),
            TEST_COMMAND_2_TUYA_BASE64_PAYLOAD,
        )
    ],
)
@pytest.mark.parametrize("command", [TEST_COMMAND4])
async def test_async_send_command_with_repeat_count(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    freezer: FrozenDateTimeFactory,
    caplog: pytest.LogCaptureFixture,
    command: Command,
    expected_payload: str,
) -> None:
    """Test sending command with repeat count logs warning."""
    now = dt_util.utcnow()
    freezer.move_to(now)

    mqtt_mock = await mqtt_mock_entry()

    with caplog.at_level(logging.WARNING):
        await infrared.async_send_command(hass, "infrared.test", command)
    assert (
        "Ignoring repeat count for infrared.test when publishing infrared signal, "
        "repeat count is not supported with this configuration" in caplog.text
    )

    mqtt_mock.async_publish.assert_called_with(
        "test-topic", expected_payload, 0, False, message_expiry_interval=None
    )

    state = hass.states.get("infrared.test")
    assert state is not None
    assert state.state == now.isoformat(timespec="milliseconds")


@pytest.mark.parametrize(
    "hass_config",
    [
        help_custom_config(
            infrared.DOMAIN,
            DEFAULT_CONFIG_EMITTER,
            ({"infrared_encoding": "tuya_b64"},),
        )
    ],
)
@pytest.mark.parametrize(
    ("command", "expected_payload"),
    [
        (TEST_COMMAND1, TEST_COMMAND_1_TUYA_BASE64_PAYLOAD),
        (TEST_COMMAND2, TEST_COMMAND_2_TUYA_BASE64_PAYLOAD),
    ],
)
async def test_async_send_command_with_tuya_b64_encoding(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    freezer: FrozenDateTimeFactory,
    command: Command,
    expected_payload: str,
) -> None:
    """Test sending command with tuya_b64 encoding."""
    now = dt_util.utcnow()
    freezer.move_to(now)

    mqtt_mock = await mqtt_mock_entry()

    await infrared.async_send_command(hass, "infrared.test", command)

    mqtt_mock.async_publish.assert_called_with(
        "test-topic", expected_payload, 0, False, message_expiry_interval=None
    )

    state = hass.states.get("infrared.test")
    assert state is not None
    assert state.state == now.isoformat(timespec="milliseconds")


@pytest.mark.parametrize(
    "hass_config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER]
)
async def test_availability_when_connection_lost(
    hass: HomeAssistant, mqtt_mock_entry: MqttMockHAClientGenerator
) -> None:
    """Test availability after MQTT disconnection."""
    await help_test_availability_when_connection_lost(
        hass, mqtt_mock_entry, infrared.DOMAIN
    )


@pytest.mark.parametrize(
    "hass_config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER]
)
async def test_availability_without_topic(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    hass_config: ConfigType,
) -> None:
    """Test availability without defined availability topic."""
    await help_test_availability_without_topic(
        hass, mqtt_mock_entry, infrared.DOMAIN, hass_config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_setting_attribute_via_mqtt_json_message(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test the setting of attribute via MQTT with JSON payload."""
    await help_test_setting_attribute_via_mqtt_json_message(
        hass, mqtt_mock_entry, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_setting_blocked_attribute_via_mqtt_json_message(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test the setting of attribute via MQTT with JSON payload."""
    await help_test_setting_blocked_attribute_via_mqtt_json_message(
        hass, mqtt_mock_entry, infrared.DOMAIN, config, None
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_setting_attribute_with_template(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test the setting of attribute via MQTT with JSON payload."""
    await help_test_setting_attribute_with_template(
        hass, mqtt_mock_entry, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_update_with_json_attrs_not_dict(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    caplog: pytest.LogCaptureFixture,
    config: dict[str, Any],
) -> None:
    """Test attributes get extracted from a JSON result."""
    await help_test_update_with_json_attrs_not_dict(
        hass, mqtt_mock_entry, caplog, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_update_with_json_attrs_bad_json(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    caplog: pytest.LogCaptureFixture,
    config: dict[str, Any],
) -> None:
    """Test attributes get extracted from a JSON result."""
    await help_test_update_with_json_attrs_bad_json(
        hass, mqtt_mock_entry, caplog, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_discovery_update_attr(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test update of discovered MQTTAttributes."""
    await help_test_discovery_update_attr(
        hass, mqtt_mock_entry, infrared.DOMAIN, config
    )


@pytest.mark.parametrize(
    "hass_config",
    [
        {
            mqtt.DOMAIN: {
                infrared.DOMAIN: [
                    {
                        "name": "Test 1",
                        "schema": "emitter",
                        "command_topic": "command-topic",
                        "unique_id": "TOTALLY_UNIQUE",
                    },
                    {
                        "name": "Test 2",
                        "schema": "emitter",
                        "command_topic": "command-topic",
                        "unique_id": "TOTALLY_UNIQUE",
                    },
                ]
            }
        }
    ],
)
async def test_unique_id_emitter(
    hass: HomeAssistant, mqtt_mock_entry: MqttMockHAClientGenerator
) -> None:
    """Test unique id option only creates one infrared emitter per unique_id."""
    await help_test_unique_id(hass, mqtt_mock_entry, infrared.DOMAIN)


@pytest.mark.parametrize(
    "hass_config",
    [
        {
            mqtt.DOMAIN: {
                infrared.DOMAIN: [
                    {
                        "name": "Test 1",
                        "schema": "receiver",
                        "state_topic": "test-topic",
                        "unique_id": "TOTALLY_UNIQUE",
                    },
                    {
                        "name": "Test 2",
                        "schema": "receiver",
                        "state_topic": "test-topic",
                        "unique_id": "TOTALLY_UNIQUE",
                    },
                ]
            }
        }
    ],
)
async def test_unique_id_receiver(
    hass: HomeAssistant, mqtt_mock_entry: MqttMockHAClientGenerator
) -> None:
    """Test unique id option only creates one infrared receiver per unique_id."""
    await help_test_unique_id(hass, mqtt_mock_entry, infrared.DOMAIN)


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_discovery_removal_infrared_entity(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test removal of discovered infrared entity."""
    data = orjson.dumps(config[mqtt.DOMAIN][infrared.DOMAIN])
    await help_test_discovery_removal(hass, mqtt_mock_entry, infrared.DOMAIN, data)


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_entity_device_info_with_connection(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test MQTT infrared device registry integration."""
    await help_test_entity_device_info_with_connection(
        hass, mqtt_mock_entry, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_entity_device_info_with_identifier(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test MQTT infrared device registry integration."""
    await help_test_entity_device_info_with_identifier(
        hass, mqtt_mock_entry, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_entity_device_info_update(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test device registry update."""
    await help_test_entity_device_info_update(
        hass, mqtt_mock_entry, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_entity_device_info_remove(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test device registry remove."""
    await help_test_entity_device_info_remove(
        hass, mqtt_mock_entry, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_RECEIVER])
async def test_entity_id_update_subscriptions(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test MQTT subscriptions are managed when entity_id is updated."""
    await help_test_entity_id_update_subscriptions(
        hass, mqtt_mock_entry, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_entity_id_update_discovery_update(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test MQTT discovery update when entity_id is updated."""
    await help_test_entity_id_update_discovery_update(
        hass, mqtt_mock_entry, infrared.DOMAIN, config
    )


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_reloadable(
    hass: HomeAssistant, mqtt_client_mock: MqttMockPahoClient, config: dict[str, Any]
) -> None:
    """Test reloading the MQTT platform."""
    domain = infrared.DOMAIN
    await help_test_reloadable(hass, mqtt_client_mock, domain, config)


@pytest.mark.parametrize(
    "hass_config",
    [
        DEFAULT_CONFIG_EMITTER,
        {"mqtt": [DEFAULT_CONFIG_EMITTER["mqtt"]]},
        DEFAULT_CONFIG_RECEIVER,
        {"mqtt": [DEFAULT_CONFIG_RECEIVER["mqtt"]]},
    ],
    ids=[
        "platform_key_emitter",
        "listed_emitter",
        "platform_key_receiver",
        "listed_receiver",
    ],
)
async def test_setup_manual_entity_from_yaml(
    hass: HomeAssistant, mqtt_mock_entry: MqttMockHAClientGenerator
) -> None:
    """Test setup manual configured MQTT entity."""
    await mqtt_mock_entry()
    platform = infrared.DOMAIN
    assert hass.states.get(f"{platform}.test")


@pytest.mark.parametrize("config", [DEFAULT_CONFIG_EMITTER, DEFAULT_CONFIG_RECEIVER])
async def test_unload_entry(
    hass: HomeAssistant,
    mqtt_mock_entry: MqttMockHAClientGenerator,
    config: dict[str, Any],
) -> None:
    """Test unloading the config entry."""
    domain = infrared.DOMAIN
    await help_test_unload_config_entry_with_platform(
        hass, mqtt_mock_entry, domain, config
    )
