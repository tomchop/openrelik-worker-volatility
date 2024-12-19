# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import glob
import os
import subprocess
import logging

from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.reporting import Report
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from .app import celery

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TASK_NAME = "openrelik-worker-volatility.tasks.volatility"

# Task metadata for registration in the core system.
TASK_METADATA = {
    "display_name": "Volatility",
    "description": "Run a pre-defined set of Volatility3 plugins on a memory Image (see options).",
    "task_config": [
        {
            "name": "Yara rules",
            "label": "rule test { condition: true }",
            "description": "Run these Yara rules using the YaraScan plugin.",
            "type": "textarea",
            "required": False,
        },
        {
            "name": "OS group",
            "label": "win,lin,macos",
            "default": "win",
            "description": "OS group of plugins to run.",
            "type": "text",
            "required": True,
        },
        {
            "name": "Output format",
            "label": "txt,json,md",
            "default": "txt",
            "description": "Output format for the results.",
            "type": "text",
            "required": True,
        },
    ],
}


def add_dir_glob_to_output(source_directory: str, glob_pattern: str, output_files):
    """Run a glob pattern on a directory and add the files to the output_files list.

    Args:
        source_directory: The directory to search.
        glob: The glob pattern to use.
        output_files: The list to append the files to.

    """
    for file in glob.glob(os.path.join(source_directory, glob_pattern)):
        output_file = create_output_file(
            source_directory,
            display_name=os.path.basename(file),
        )
        with open(output_file.path, "wb") as dst:
            with open(file, "rb") as src:
                dst.write(src.read())

        output_files.append(output_file.to_dict())


def generate_report(plugin_output_map, output_path, prefix):
    report = Report("Volatility3 Plugin Execution")
    plugins_section = report.add_section()
    plugins_section.add_paragraph(
        f"The following plugins were executed: {list(plugin_output_map.keys())}"
    )

    for plugin_name, output_file_path in plugin_output_map.items():
        plugin_output_section = report.add_section()
        plugin_output_section.add_header(f"Plugin: {plugin_name}", level=2)
        with open(output_file_path, "r") as fh:
            plugin_output_section.add_code_block(fh.read())

    report_file = create_output_file(
        output_path,
        display_name=f"{prefix}-volatility-report.md",
        data_type="worker:openrelik:volatility:report",
    )
    with open(report_file.path, "w", encoding="utf-8") as fh:
        fh.write(report.to_markdown())

    return report_file


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """Run <REPLACE_WITH_COMMAND> on input files.

    Args:
        pipe_result: Base64-encoded result from the previous Celery task, if any.
        input_files: List of input file dictionaries (unused if pipe_result exists).
        output_path: Path to the output directory.
        workflow_id: ID of the workflow.
        task_config: User configuration for the task.

    Returns:
        Base64-encoded dictionary containing task results.
    """

    PLUGIN_PLATFORM_MAP = {
        "win": {
            "windows.info": {"params": []},
            "windows.pslist": {"params": ["--dump"]},
            "windows.pstree": {"params": []},
        },
    }

    input_files = get_input_files(pipe_result, input_files or [])
    output_files = []
    output_format = task_config.get("Output format") or "txt"
    if output_format in ("json", "md"):
        base_command = ["vol", "-o", output_path, "-r", "json", "-f"]
    else:
        base_command = ["vol", "-o", output_path, "-f"]

    base_command_string = " ".join(base_command)

    os_group = task_config.get("OS group") or "win"
    plugins = PLUGIN_PLATFORM_MAP.get(os_group)
    if not plugins:
        raise RuntimeError(f"No plugins found for specified OS group: {plugins}")

    yara_rule = task_config.get("Yara rules")

    if yara_rule and os_group == "win":
        yara_rules_file = create_output_file(output_path, display_name="yara_rules.yar")
        with open(yara_rules_file.path, "w") as fh:
            fh.write(yara_rule)
        plugins["windows.vadyarascan.VadYaraScan"] = {
            "params": [
                "--yara-file",
                yara_rules_file.path,
            ]
        }
        output_files.append(yara_rules_file.to_dict())

    if not input_files:
        raise RuntimeError("No input files provided")

    logger.info(f"Running Volatility3 with the following plugins: {plugins}")

    for input_file in input_files:
        command_with_file = base_command.copy()
        command_with_file.append(input_file.get("path"))

        total_plugins = len(plugins)
        completed_plugins = 0
        failed_plugins = 0

        self.send_event(
            "task-progress",
            data={
                "total_plugins": total_plugins,
                "plugins_completed": completed_plugins,
            },
        )

        processes = []
        plugin_output_map = {}

        for plugin_name, commands in plugins.items():
            logger.info(f"Running plugin: {plugin_name}")

            output_filename = (
                f"{input_file.get('display_name')}_{plugin_name}.{output_format}"
            )
            output_file = create_output_file(
                output_path,
                display_name=output_filename,
            )

            command_with_plugin = command_with_file.copy()
            command_with_plugin.append(plugin_name)

            if commands.get("params"):
                command_with_plugin.extend(commands["params"])

            logger.info(f"Running command: {command_with_plugin}")

            with open(output_file.path, "w+") as fh:
                p = subprocess.Popen(command_with_plugin, stdout=fh)
                processes.append(p)
                output_files.append(output_file.to_dict())
                plugin_output_map[plugin_name] = output_file.path

        for p in processes:
            p.wait()
            if p.returncode == 0:
                completed_plugins += 1
                self.send_event(
                    "task-progress",
                    data={
                        "total_plugins": total_plugins,
                        "plugins_completed": completed_plugins,
                    },
                )
            else:
                failed_plugins += 1
                self.send_event(
                    "task-progress",
                    data={
                        "total_plugins": total_plugins,
                        "plugins_completed": completed_plugins,
                        "plugins_failed": failed_plugins,
                    },
                )

        report_file = generate_report(
            plugin_output_map, output_path, input_file.get("display_name")
        )
        output_files.append(report_file.to_dict())

        add_dir_glob_to_output(output_path, "*.dmp", output_files)

    if not output_files:
        raise RuntimeError("No output files generated.")

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command=base_command_string,
        meta={},
    )
