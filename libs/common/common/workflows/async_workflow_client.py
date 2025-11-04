"""
Copyright 2023 The Dapr Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Modified from https://github.com/dapr/python-sdk/blob/main/ext/dapr-ext-workflow/dapr/ext/workflow/dapr_workflow_client.py
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, TypeVar

import durabletask.internal.orchestrator_service_pb2 as pb
import grpc.aio
from dapr.clients import DaprInternalError
from dapr.clients.http.client import DAPR_API_TOKEN_HEADER
from dapr.conf import settings
from dapr.conf.helpers import GrpcEndpoint
from dapr.ext.workflow.logger import Logger, LoggerOptions
from dapr.ext.workflow.util import getAddress
from dapr.ext.workflow.workflow_state import WorkflowState

from .taskhub_client import TaskHubGrpcClient

T = TypeVar("T")
TInput = TypeVar("TInput")
TOutput = TypeVar("TOutput")


class AsyncDaprWorkflowClient:
    """Defines client operations for managing Dapr Workflow instances.

    This is an alternative to the general purpose Dapr client. It uses a gRPC connection to send
    commands directly to the workflow engine, bypassing the Dapr API layer.

    This client is intended to be used by workflow application, not by general purpose
    application.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[str] = None,
        logger_options: Optional[LoggerOptions] = None,
    ):
        address = getAddress(host, port)

        try:
            uri = GrpcEndpoint(address)
        except ValueError as error:
            raise DaprInternalError(f"{error}") from error

        self._logger = Logger("AsyncDaprWorkflowClient", logger_options)
        self._logger.warning("Creating new AsyncDaprClient")

        metadata = None
        if settings.DAPR_API_TOKEN:
            metadata = [(DAPR_API_TOKEN_HEADER, settings.DAPR_API_TOKEN)]
        options = self._logger.get_options()
        self.__obj = TaskHubGrpcClient(
            host_address=uri.endpoint,
            metadata=metadata,
            secure_channel=uri.tls,
            log_handler=options.log_handler,
            log_formatter=options.log_formatter,
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb):
        """Async context manager exit - closes the underlying client."""
        await self.close()

    async def close(self):
        """Close the underlying gRPC client."""
        await self.__obj.close()

    async def schedule_new_workflow(
        self,
        workflow: Any,  # Workflow or any object with _dapr_alternate_name or __name__ attribute
        *,
        input: Optional[TInput] = None,
        instance_id: Optional[str] = None,
        start_at: Optional[datetime] = None,
        reuse_id_policy: Optional[pb.OrchestrationIdReusePolicy] = None,
    ) -> str:
        """Schedules a new workflow instance for execution.

        Args:
            workflow: The workflow to schedule.
            input: The optional input to pass to the scheduled workflow instance. This must be a
            serializable value.
            instance_id: The unique ID of the workflow instance to schedule. If not specified, a
            new GUID value is used.
            start_at: The time when the workflow instance should start executing.
            If not specified or if a date-time in the past is specified, the workflow instance will
            be scheduled immediately.
            reuse_id_policy: Optional policy to reuse the workflow id when there is a conflict with
            an existing workflow instance.

        Returns:
            The ID of the scheduled workflow instance.
        """
        if hasattr(workflow, "_dapr_alternate_name"):
            return await self.__obj.schedule_new_orchestration(
                workflow.__dict__["_dapr_alternate_name"],
                input=input,
                instance_id=instance_id,
                start_at=start_at,
                reuse_id_policy=reuse_id_policy,
            )
        return await self.__obj.schedule_new_orchestration(
            workflow.__name__,
            input=input,
            instance_id=instance_id,
            start_at=start_at,
            reuse_id_policy=reuse_id_policy,
        )

    async def get_workflow_state(self, instance_id: str, *, fetch_payloads: bool = True) -> Optional[WorkflowState]:
        """Fetches runtime state for the specified workflow instance.

        Args:
            instance_id: The unique ID of the workflow instance to fetch.
            fetch_payloads: If true, fetches the input, output payloads and custom status
            for the workflow instance. Defaults to true.

        Returns:
            The current state of the workflow instance, or None if the workflow instance does not
            exist.

        """
        try:
            state = await self.__obj.get_orchestration_state(instance_id, fetch_payloads=fetch_payloads)
            return WorkflowState(state) if state else None
        except grpc.aio.AioRpcError as error:
            if "no such instance exists" in error.details():
                self._logger.warning(f"Workflow instance not found: {instance_id}")
                return None
            self._logger.error(f"Unhandled RPC error while fetching workflow state: {error.code()} - {error.details()}")
            raise

    async def wait_for_workflow_start(
        self, instance_id: str, *, fetch_payloads: bool = False, timeout_in_seconds: int = 0
    ) -> Optional[WorkflowState]:
        """Waits for a workflow to start running and returns a WorkflowState object that contains
           metadata about the started workflow.

           A "started" workflow instance is any instance not in the WorkflowRuntimeStatus.Pending
           state. This method will return a completed task if the workflow has already started
           running or has already completed.

        Args:
            instance_id: The unique ID of the workflow instance to wait for.
            fetch_payloads: If true, fetches the input, output payloads and custom status for
            the workflow instance. Defaults to false.
            timeout_in_seconds: The maximum time to wait for the workflow instance to start running.
            Defaults to meaning no timeout.

        Returns:
            WorkflowState record that describes the workflow instance and its execution status.
            If the specified workflow isn't found, the WorkflowState.Exists value will be false.
        """
        state = await self.__obj.wait_for_orchestration_start(
            instance_id, fetch_payloads=fetch_payloads, timeout=timeout_in_seconds
        )
        return WorkflowState(state) if state else None

    async def wait_for_workflow_completion(
        self, instance_id: str, *, fetch_payloads: bool = True, timeout_in_seconds: int = 0
    ) -> Optional[WorkflowState]:
        """Waits for a workflow to complete and returns a WorkflowState object that contains
           metadata about the started instance.

           A "completed" workflow instance is any instance in one of the terminal states. For
           example, the WorkflowRuntimeStatus.Completed, WorkflowRuntimeStatus.Failed or
           WorkflowRuntimeStatus.Terminated states.

           Workflows are long-running and could take hours, days, or months before completing.
           Workflows can also be eternal, in which case they'll never complete unless terminated.
           In such cases, this call may block indefinitely, so care must be taken to ensure
           appropriate timeouts are enforced using timeout parameter.

           If a workflow instance is already complete when this method is called, the method
           will return immediately.

        Args:
            instance_id: The unique ID of the workflow instance to wait for.
            fetch_payloads: If true, fetches the input, output payloads and custom status
            for the workflow instance. Defaults to true.
            timeout_in_seconds: The maximum time in seconds to wait for the workflow instance to
            complete. Defaults to 0 seconds, meaning no timeout.

        Returns:
            WorkflowState record that describes the workflow instance and its execution status.
        """
        state = await self.__obj.wait_for_orchestration_completion(
            instance_id, fetch_payloads=fetch_payloads, timeout=timeout_in_seconds
        )
        return WorkflowState(state) if state else None

    async def raise_workflow_event(self, instance_id: str, event_name: str, *, data: Optional[Any] = None):
        """Sends an event notification message to a waiting workflow instance.
           In order to handle the event, the target workflow instance must be waiting for an
           event named value of "eventName" param using the wait_for_external_event API.
           If the target workflow instance is not yet waiting for an event named param "eventName"
           value, then the event will be saved in the workflow instance state and dispatched
           immediately when the workflow calls wait_for_external_event.
           This event saving occurs even if the workflow has canceled its wait operation before
           the event was received.

           Workflows can wait for the same event name multiple times, so sending multiple events
           with the same name is allowed. Each external event received by a workflow will complete
           just one task returned by the wait_for_external_event method.

           Raised events for a completed or non-existent workflow instance will be silently
           discarded.

        Args:
            instance_id: The ID of the workflow instance that will handle the event.
            event_name: The name of the event. Event names are case-insensitive.
            data: The serializable data payload to include with the event.
        """
        return await self.__obj.raise_orchestration_event(instance_id, event_name, data=data)

    async def terminate_workflow(self, instance_id: str, *, output: Optional[Any] = None, recursive: bool = True):
        """Terminates a running workflow instance and updates its runtime status to
           WorkflowRuntimeStatus.Terminated This method internally enqueues a "terminate" message in
           the task hub. When the task hub worker processes this message, it will update the runtime
           status of the target instance to WorkflowRuntimeStatus.Terminated. You can use
           wait_for_workflow_completion to wait for the instance to reach the terminated state.

           Terminating a workflow will terminate all child workflows that were started by
           the workflow instance.

           However, terminating a workflow has no effect on any in-flight activity function
           executions that were started by the terminated workflow instance.

           At the time of writing, there is no way to terminate an in-flight activity execution.

        Args:
            instance_id: The ID of the workflow instance to terminate.
            output: The optional output to set for the terminated workflow instance.
            recursive: The optional flag to terminate all child workflows.

        """
        return await self.__obj.terminate_orchestration(instance_id, output=output, recursive=recursive)

    async def pause_workflow(self, instance_id: str):
        """Suspends a workflow instance, halting processing of it until resume_workflow is used to
           resume the workflow.

        Args:
            instance_id: The instance ID of the workflow to suspend.
        """
        return await self.__obj.suspend_orchestration(instance_id)

    async def resume_workflow(self, instance_id: str):
        """Resumes a workflow instance that was suspended via pause_workflow.

        Args:
            instance_id: The instance ID of the workflow to resume.
        """
        return await self.__obj.resume_orchestration(instance_id)

    async def purge_workflow(self, instance_id: str, recursive: bool = True):
        """Purge data from a workflow instance.

        Args:
            instance_id: The instance ID of the workflow to purge.
            recursive: The optional flag to also purge data from all child workflows.
        """
        return await self.__obj.purge_orchestration(instance_id, recursive)
