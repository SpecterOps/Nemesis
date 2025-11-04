# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Modified from https://github.com/dapr/durabletask-python/blob/main/durabletask/client.py

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional, TypeVar, Union

import durabletask.internal.helpers as helpers
import durabletask.internal.orchestrator_service_pb2 as pb
import durabletask.internal.orchestrator_service_pb2_grpc as stubs
import durabletask.internal.shared as shared
import grpc.aio
from durabletask import task
from durabletask.internal.grpc_interceptor import DefaultClientInterceptorImpl
from google.protobuf import wrappers_pb2

TInput = TypeVar("TInput")
TOutput = TypeVar("TOutput")


class OrchestrationStatus(Enum):
    """The status of an orchestration instance."""

    RUNNING = pb.ORCHESTRATION_STATUS_RUNNING
    COMPLETED = pb.ORCHESTRATION_STATUS_COMPLETED
    FAILED = pb.ORCHESTRATION_STATUS_FAILED
    TERMINATED = pb.ORCHESTRATION_STATUS_TERMINATED
    CONTINUED_AS_NEW = pb.ORCHESTRATION_STATUS_CONTINUED_AS_NEW
    PENDING = pb.ORCHESTRATION_STATUS_PENDING
    SUSPENDED = pb.ORCHESTRATION_STATUS_SUSPENDED

    def __str__(self):
        return helpers.get_orchestration_status_str(self.value)


@dataclass
class OrchestrationState:
    instance_id: str
    name: str
    runtime_status: OrchestrationStatus
    created_at: datetime
    last_updated_at: datetime
    serialized_input: Optional[str]
    serialized_output: Optional[str]
    serialized_custom_status: Optional[str]
    failure_details: Optional[task.FailureDetails]

    def raise_if_failed(self):
        if self.failure_details is not None:
            raise OrchestrationFailedError(
                f"Orchestration '{self.instance_id}' failed: {self.failure_details.message}", self.failure_details
            )


class OrchestrationFailedError(Exception):
    def __init__(self, message: str, failure_details: task.FailureDetails):
        super().__init__(message)
        self._failure_details = failure_details

    @property
    def failure_details(self):
        return self._failure_details


def new_orchestration_state(instance_id: str, res: pb.GetInstanceResponse) -> Optional[OrchestrationState]:
    if not res.exists:
        return None

    state = res.orchestrationState

    failure_details = None
    if state.failureDetails.errorMessage != "" or state.failureDetails.errorType != "":
        failure_details = task.FailureDetails(
            state.failureDetails.errorMessage,
            state.failureDetails.errorType,
            state.failureDetails.stackTrace.value if not helpers.is_empty(state.failureDetails.stackTrace) else None,
        )

    return OrchestrationState(
        instance_id,
        state.name,
        OrchestrationStatus(state.orchestrationStatus),
        state.createdTimestamp.ToDatetime(),
        state.lastUpdatedTimestamp.ToDatetime(),
        state.input.value if not helpers.is_empty(state.input) else None,
        state.output.value if not helpers.is_empty(state.output) else None,
        state.customStatus.value if not helpers.is_empty(state.customStatus) else None,
        failure_details,
    )


class TaskHubGrpcClient:
    def __init__(
        self,
        *,
        host_address: Optional[str] = None,
        metadata: Optional[list[tuple[str, str]]] = None,
        log_handler: Optional[logging.Handler] = None,
        log_formatter: Optional[logging.Formatter] = None,
        secure_channel: bool = False,
        interceptors: Optional[Sequence[shared.ClientInterceptor]] = None,
    ):
        # If the caller provided metadata, we need to create a new interceptor for it and
        # add it to the list of interceptors.
        if interceptors is not None:
            interceptors = list(interceptors)
            if metadata is not None:
                interceptors.append(DefaultClientInterceptorImpl(metadata))
        elif metadata is not None:
            interceptors = [DefaultClientInterceptorImpl(metadata)]
        else:
            interceptors = None

        # Create async channel using grpc.aio
        # Note: interceptors for sync grpc may not be compatible with grpc.aio
        # For now, we'll create the channel without interceptors
        # TODO: Convert interceptors to grpc.aio.ClientInterceptor if needed
        if secure_channel:
            channel = grpc.aio.secure_channel(
                host_address or "localhost:4001",
                grpc.ssl_channel_credentials(),
            )
        else:
            channel = grpc.aio.insecure_channel(
                host_address or "localhost:4001",
            )

        # Store metadata for manual injection if needed
        self._metadata = metadata
        self._channel = channel
        self._stub = stubs.TaskHubSidecarServiceStub(channel)
        self._logger = shared.get_logger("async-client", log_handler, log_formatter)
        self._logger.warning("CREATED ASYNC TASKHUB CLIENT")

    async def __aenter__(self):
        """Async context manager entry."""
        self._logger.warning("CREATED ASYNC TASKHUB CLIENT - aenter")
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb):
        """Async context manager exit - closes the channel."""
        await self.close()

    async def close(self):
        """Close the gRPC channel."""
        if hasattr(self, "_channel"):
            await self._channel.close()

    async def schedule_new_orchestration(
        self,
        orchestrator: Union[task.Orchestrator[TInput, TOutput], str],
        *,
        input: Optional[TInput] = None,
        instance_id: Optional[str] = None,
        start_at: Optional[datetime] = None,
        reuse_id_policy: Optional[pb.OrchestrationIdReusePolicy] = None,
    ) -> str:
        name = orchestrator if isinstance(orchestrator, str) else task.get_name(orchestrator)

        req = pb.CreateInstanceRequest(
            name=name,
            instanceId=instance_id if instance_id else uuid.uuid4().hex,
            input=wrappers_pb2.StringValue(value=shared.to_json(input)) if input is not None else None,
            scheduledStartTimestamp=helpers.new_timestamp(start_at) if start_at else None,
            version=wrappers_pb2.StringValue(value=""),
            orchestrationIdReusePolicy=reuse_id_policy,
        )

        self._logger.info(f"Starting new '{name}' instance with ID = '{req.instanceId}'.")
        res: pb.CreateInstanceResponse = await self._stub.StartInstance(req, metadata=self._metadata)
        return res.instanceId

    async def get_orchestration_state(
        self, instance_id: str, *, fetch_payloads: bool = True
    ) -> Optional[OrchestrationState]:
        req = pb.GetInstanceRequest(instanceId=instance_id, getInputsAndOutputs=fetch_payloads)
        res: pb.GetInstanceResponse = await self._stub.GetInstance(req, metadata=self._metadata)
        return new_orchestration_state(req.instanceId, res)

    async def wait_for_orchestration_start(
        self, instance_id: str, *, fetch_payloads: bool = False, timeout: int = 0
    ) -> Optional[OrchestrationState]:
        req = pb.GetInstanceRequest(instanceId=instance_id, getInputsAndOutputs=fetch_payloads)
        try:
            grpc_timeout = None if timeout == 0 else timeout
            self._logger.info(
                f"Waiting {'indefinitely' if timeout == 0 else f'up to {timeout}s'} for instance '{instance_id}' to start."
            )
            res: pb.GetInstanceResponse = await self._stub.WaitForInstanceStart(
                req, timeout=grpc_timeout, metadata=self._metadata
            )

            return new_orchestration_state(req.instanceId, res)
        except grpc.aio.AioRpcError as rpc_error:
            if rpc_error.code() == grpc.StatusCode.DEADLINE_EXCEEDED:  # type: ignore
                # Replace gRPC error with the built-in TimeoutError
                raise TimeoutError("Timed-out waiting for the orchestration to start")
            else:
                raise

    async def wait_for_orchestration_completion(
        self, instance_id: str, *, fetch_payloads: bool = True, timeout: int = 0
    ) -> Optional[OrchestrationState]:
        req = pb.GetInstanceRequest(instanceId=instance_id, getInputsAndOutputs=fetch_payloads)
        try:
            grpc_timeout = None if timeout == 0 else timeout
            self._logger.info(
                f"Waiting {'indefinitely' if timeout == 0 else f'up to {timeout}s'} for instance '{instance_id}' to complete."
            )
            res: pb.GetInstanceResponse = await self._stub.WaitForInstanceCompletion(
                req, timeout=grpc_timeout, metadata=self._metadata
            )
            state = new_orchestration_state(req.instanceId, res)
            if not state:
                return None

            if state.runtime_status == OrchestrationStatus.FAILED and state.failure_details is not None:
                details = state.failure_details
                self._logger.info(f"Instance '{instance_id}' failed: [{details.error_type}] {details.message}")
            elif state.runtime_status == OrchestrationStatus.TERMINATED:
                self._logger.info(f"Instance '{instance_id}' was terminated.")
            elif state.runtime_status == OrchestrationStatus.COMPLETED:
                self._logger.info(f"Instance '{instance_id}' completed.")

            return state
        except grpc.aio.AioRpcError as rpc_error:
            if rpc_error.code() == grpc.StatusCode.DEADLINE_EXCEEDED:  # type: ignore
                # Replace gRPC error with the built-in TimeoutError
                raise TimeoutError("Timed-out waiting for the orchestration to complete")
            else:
                raise

    async def raise_orchestration_event(self, instance_id: str, event_name: str, *, data: Optional[Any] = None):
        req = pb.RaiseEventRequest(
            instanceId=instance_id,
            name=event_name,
            input=wrappers_pb2.StringValue(value=shared.to_json(data)) if data else None,
        )

        self._logger.info(f"Raising event '{event_name}' for instance '{instance_id}'.")
        await self._stub.RaiseEvent(req, metadata=self._metadata)

    async def terminate_orchestration(self, instance_id: str, *, output: Optional[Any] = None, recursive: bool = True):
        req = pb.TerminateRequest(
            instanceId=instance_id,
            output=wrappers_pb2.StringValue(value=shared.to_json(output)) if output else None,
            recursive=recursive,
        )

        self._logger.info(f"Terminating instance '{instance_id}'.")
        await self._stub.TerminateInstance(req, metadata=self._metadata)

    async def suspend_orchestration(self, instance_id: str):
        req = pb.SuspendRequest(instanceId=instance_id)
        self._logger.info(f"Suspending instance '{instance_id}'.")
        await self._stub.SuspendInstance(req, metadata=self._metadata)

    async def resume_orchestration(self, instance_id: str):
        req = pb.ResumeRequest(instanceId=instance_id)
        self._logger.info(f"Resuming instance '{instance_id}'.")
        await self._stub.ResumeInstance(req, metadata=self._metadata)

    async def purge_orchestration(self, instance_id: str, recursive: bool = True):
        req = pb.PurgeInstancesRequest(instanceId=instance_id, recursive=recursive)
        self._logger.info(f"Purging instance '{instance_id}'.")
        await self._stub.PurgeInstances(req, metadata=self._metadata)
