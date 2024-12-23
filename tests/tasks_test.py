import unittest

from src import tasks


class TestVolatilityWorker(unittest.TestCase):
    def test_generate_base_command(self):
        output_path = "/tmp"
        task_config = {
            "Yara rules": "rule test { condition: true }",
            "OS group": "win",
            "Output format": "txt",
        }
        plugins = {
            "windows.info": {"params": []},
            "windows.pslist": {"params": ["--dump"]},
            "windows.pstree": {"params": []},
            "windows.vadyarascan.VadYaraScan": None,
        }

        result, extra_files = tasks.generate_base_command(
            output_path, task_config, plugins
        )

        self.assertEqual(result, ["vol", "-o", output_path, "-f"])

        self.assertRegex(
            plugins["windows.vadyarascan.VadYaraScan"]["params"][1],
            r"/tmp/[0-9a-f]{32}.yar",
        )

    def test_generate_commands(self):
        base_command = ["vol", "-o", "/tmp", "-f", "input_file"]
        input_file = {"path": "input_file"}
        plugins = {
            "windows.info": {"params": []},
            "windows.pslist": {"params": ["--dump"]},
            "windows.pstree": {"params": []},
            "windows.vadyarascan.VadYaraScan": {"params": ["--yara-file", "rules.yar"]},
        }

        commands = list(tasks.generate_commands(base_command, input_file, plugins))

        self.assertEqual(
            commands,
            [
                (
                    "windows.info",
                    ["vol", "-o", "/tmp", "-f", "input_file", "windows.info"],
                ),
                (
                    "windows.pslist",
                    [
                        "vol",
                        "-o",
                        "/tmp",
                        "-f",
                        "input_file",
                        "windows.pslist",
                        "--dump",
                    ],
                ),
                (
                    "windows.pstree",
                    ["vol", "-o", "/tmp", "-f", "input_file", "windows.pstree"],
                ),
                (
                    "windows.vadyarascan.VadYaraScan",
                    [
                        "vol",
                        "-o",
                        "/tmp",
                        "-f",
                        "input_file",
                        "windows.vadyarascan.VadYaraScan",
                        "--yara-file",
                        "rules.yar",
                    ],
                ),
            ],
        )
