import os

from pyipv8.ipv8.community import Community
from pyipv8.ipv8.test.base import TestBase


class MyCommunity(Community):
    community_id = os.urandom(20)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.register_task("error out :-(", self.error)

    def error(self):
        raise RuntimeError()


class TestMyCommunity(TestBase):

    def create_node(self, *args, **kwargs):
        mock_ipv8 = super().create_node(*args, **kwargs)
        mock_ipv8.overlay.cancel_all_pending_tasks()
        return mock_ipv8

    async def test_something(self):
        self.initialize(MyCommunity, 1)  # Will not run tasks


if __name__ == '__main__':
    import unittest
    unittest.main()
