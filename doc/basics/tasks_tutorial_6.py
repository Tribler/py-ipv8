import os
from typing import Any

from ipv8.community import Community, CommunitySettings
from ipv8.test.base import TestBase
from ipv8.test.mocking.ipv8 import MockIPv8


class MyCommunity(Community):
    community_id = os.urandom(20)

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.register_task("error out :-(", self.error)

    def error(self) -> None:
        raise RuntimeError


class TestMyCommunity(TestBase):

    def create_node(self, *args: Any, **kwargs) -> MockIPv8:
        mock_ipv8 = super().create_node(*args, **kwargs)
        mock_ipv8.overlay.cancel_all_pending_tasks()
        return mock_ipv8

    async def test_something(self) -> None:
        self.initialize(MyCommunity, 1)  # Will not run tasks


if __name__ == '__main__':
    import unittest
    unittest.main()
