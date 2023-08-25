from __future__ import annotations


class NetworkStat:
    """
    Represents an individual network statistic. This is used to compose the overall community statistics.

    Includes the following properties for the given statistic:
        - identifier: char
        - num_up: integer
        - num_down: integer
        - bytes_up: integer
        - bytes_down: integer
        - first_measured_up: float
        - first_measured_down: float
        - last_measured_up: float
        - last_measured_down: float
    """

    def __init__(self, identifier: int) -> None:
        """
        Create a new statistic for a single message identifier.
        """
        self.identifier: int = identifier
        """Message identifier."""

        self.num_up: int = 0
        """Number of messages sent."""

        self.num_down: int = 0
        """Number of messages received."""

        self.bytes_up: int = 0
        """Number of bytes sent."""

        self.bytes_down: int = 0
        """Number of bytes received."""

        self.first_measured_up: float = 0
        """Timestamp of the first message sent."""

        self.first_measured_down: float = 0
        """Timestamp of the first message received."""

        self.last_measured_up: float = 0
        """Timestamp of the most recent message sent."""

        self.last_measured_down: float = 0
        """Timestamp of the most recent message received."""

    def add_sent_stat(self, timestamp: float, num_bytes: int) -> None:
        """
        Callback for when a message of a given number of bytes is sent at a given timestamp.
        """
        self.num_up += 1
        self.bytes_up += num_bytes
        self.last_measured_up = timestamp

        if not self.first_measured_up:
            self.first_measured_up = timestamp

    def add_received_stat(self, timestamp: float, num_bytes: int) -> None:
        """
        Callback for when a message of a given number of bytes is received at a given timestamp.
        """
        self.num_down += 1
        self.bytes_down += num_bytes
        self.last_measured_down = timestamp

        if not self.first_measured_down:
            self.first_measured_down = timestamp

    def to_dict(self) -> dict[str, int | float]:
        """
        Convert this statistic to a plain dictionary.
        """
        return {
            "identifier": self.identifier,
            "num_up": self.num_up,
            "num_down": self.num_down,
            "bytes_up": self.bytes_up,
            "bytes_down": self.bytes_down,
            "first_measured_up": self.first_measured_up,
            "first_measured_down": self.first_measured_down,
            "last_measured_up": self.last_measured_up,
            "last_measured_down": self.last_measured_down
        }

    def __str__(self) -> str:
        """
        Create a short string representation of this statistic for debugging.
        """
        return (f"NetworkStat{{num_up:{self.num_up}, num_down:{self.num_down}, "
                f"bytes_up:{self.bytes_up}, bytes_down:{self.bytes_down}, ...}}")
