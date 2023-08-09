# Standard Libraries
import asyncio

# 3rd Party Libraries
import nemesiscommon.constants as constants
import nemesispb.nemesis_pb2 as pb
import structlog
from enrichment.tasks.service_categorizer.categorizer import ServiceCategorizerInterface
from nemesiscommon.messaging import (
    MessageQueueConsumerInterface,
    MessageQueueProducerInterface,
)
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


class ServiceCategorizer(TaskInterface):
    in_q_service: MessageQueueConsumerInterface
    out_q_serviceenriched: MessageQueueProducerInterface

    def __init__(
        self,
        in_q_service: MessageQueueConsumerInterface,
        out_q_serviceenriched: MessageQueueProducerInterface,
        categorizer: ServiceCategorizerInterface,
    ):
        self.in_q_service = in_q_service
        self.outputQueue = out_q_serviceenriched
        self.categorizer = categorizer

    async def run(self) -> None:
        await self.in_q_service.Read(self.process_message)  # type: ignore
        await asyncio.Future()

    @aio.time(Summary("process_windows_service", "Time spent processing a Windows service"))  # type: ignore
    async def process_message(self, ingestedServiceMsg: pb.ServiceIngestionMessage) -> None:
        total_services = len(ingestedServiceMsg.data)

        await logger.adebug("Received ServiceIngestionMessage", total_services=total_services)

        enrichedServiceMsg = pb.ServiceEnrichedMessage()
        enrichedServiceMsg.metadata.CopyFrom(ingestedServiceMsg.metadata)

        for i in range(total_services):
            ingestedService = ingestedServiceMsg.data[i]

            enrichedService = pb.ServiceEnriched()
            enrichedService.origin.CopyFrom(ingestedService)

            enrichments_success = []
            # enrichments_failure = []

            category = await self.categorizer.lookup(ingestedService.name)

            # right now there is no failure mode for the lookup so there are no enrichments_failure
            enrichments_success.append(constants.E_SERVICE_CATEGORY)

            enrichedService.category = category.category
            enrichedService.enrichments_success.extend(enrichments_success)

            enrichedServiceMsg.data.append(enrichedService)

        await self.outputQueue.Send(enrichedServiceMsg.SerializeToString())
