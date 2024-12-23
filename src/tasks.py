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


def generate_base_command(output_path, task_config, plugins):
    output_format = task_config.get("Output format") or "txt"
    extra_files = []

    if output_format in ("json", "md"):
        base_command = ["vol", "-o", output_path, "-r", "json", "-f"]
    else:
        base_command = ["vol", "-o", output_path, "-f"]

    # Set up VadYaraScan plugin with Yara rules if provided
    yara_rule = task_config.get("Yara rules")
    if yara_rule and "windows.vadyarascan.VadYaraScan" in plugins:
        yara_rules_file = create_output_file(output_path, display_name="yara_rules.yar")
        with open(yara_rules_file.path, "w") as fh:
            fh.write(yara_rule)
        plugins["windows.vadyarascan.VadYaraScan"] = {
            "params": [
                "--yara-file",
                yara_rules_file.path,
            ]
        }
        extra_files.append(yara_rules_file)

    return base_command, extra_files


def generate_commands(base_command, input_file, plugins):
    command_with_file = base_command.copy()
    command_with_file.append(input_file.get("path"))

    for plugin_name, commands in plugins.items():
        command_with_plugin = command_with_file.copy()
        command_with_plugin.append(plugin_name)

        if commands.get("params"):
            command_with_plugin.extend(commands["params"])

        yield plugin_name, command_with_plugin


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
            "windows.vadyarascan.VadYaraScan": None,
        },
    }

    os_group = task_config.get("OS group") or "win"
    plugins = PLUGIN_PLATFORM_MAP.get(os_group)
    if not plugins:
        raise RuntimeError(f"No plugins found for specified OS group: {plugins}")

    output_files = []
    input_files = get_input_files(pipe_result, input_files or [])
    if not input_files:
        raise RuntimeError("No input files provided")

    base_command, extra_files = generate_base_command(output_path, task_config, plugins)
    for extra_file in extra_files:
        output_files.append(extra_file.to_dict())

    logger.info(f"Running Volatility3 with the following plugins: {plugins}")

    for idx, input_file in enumerate(input_files):
        total_plugins = len(plugins)
        completed_plugins = 0
        failed_plugins = 0

        self.send_event(
            "task-progress",
            data={
                "file_num": idx,
                "total_files": len(input_files),
                "total_plugins": total_plugins,
                "plugins_completed": completed_plugins,
            },
        )

        processes = []
        plugin_output_map = {}
        display_name = input_file.get("display_name")

        for plugin_name, command in generate_commands(
            base_command, input_file, plugins
        ):
            logger.info(f"Running plugin: {plugin_name}")

            output_format = task_config.get("Output format") or "txt"
            output_filename = f"{display_name}_{plugin_name}.{output_format}"
            output_file = create_output_file(
                output_path,
                display_name=output_filename,
            )

            logger.info(f"Running command: {command}")

            with open(output_file.path, "w+") as fh:
                p = subprocess.Popen(command, stdout=fh)
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
        command="vol -f",
        meta={},
    )
