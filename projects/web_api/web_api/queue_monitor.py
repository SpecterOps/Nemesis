# src/workflow/queue_monitor.py
import asyncio
import aiohttp
import base64
import os
from typing import Optional, Dict, Any, List
import structlog
from datetime import datetime

from dapr.clients import DaprClient

logger = structlog.get_logger(__name__)

class WorkflowQueueMonitor:
    """Provides queue metrics via RabbitMQ Management HTTP API."""

    TOPIC_TO_QUEUE_MAPPING = {
        'file': 'file-enrichment-file',
        'yara': 'file-enrichment-yara',
        'dotnet-output': 'file-enrichment-dotnet-output',
        'noseyparker-output': 'file-enrichment-noseyparker-output',
        'workflow-completed': 'web-api-workflow-completed',
        'alert': 'alerting-alert',
        'dotnet-input': 'dotnet-service-dotnet-input',
        'noseyparker-input': 'noseyparker-scanner-noseyparker-input',
        'file_enriched': 'document-conversion-file_enriched'
    }
    DEFAULT_TOPICS = list(TOPIC_TO_QUEUE_MAPPING.keys())

    def _resolve_queue_name(self, topic: str) -> str:
        """Convert logical topic name to actual queue name"""
        return self.TOPIC_TO_QUEUE_MAPPING.get(topic, topic)

    def __init__(self):
        self.management_url = "http://rabbitmq:15672/rabbitmq"
        self._session = None

        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="RABBITMQ_USER")
            rabbitmq_user = secret.secret["RABBITMQ_USER"]
            secret = client.get_secret(store_name="nemesis-secret-store", key="RABBITMQ_PASSWORD")
            rabbitmq_password = secret.secret["RABBITMQ_PASSWORD"]

        credentials = f"{rabbitmq_user}:{rabbitmq_password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        self.auth_header = f"Basic {encoded_credentials}"

    async def __aenter__(self):
        """Async context manager for connection pooling"""
        self._session = aiohttp.ClientSession(
            headers={"Authorization": self.auth_header},
            timeout=aiohttp.ClientTimeout(total=10)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    async def get_workflow_queue_metrics(self, topics: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Get comprehensive queue metrics for workflow topics.

        Args:
            topics: List of topic names to monitor. If None, uses DEFAULT_TOPICS.

        Returns:
            Dictionary containing queue metrics and summary statistics
        """
        if topics is None:
            topics = self.DEFAULT_TOPICS.copy()

        if not self._session:
            raise RuntimeError("Monitor must be used as async context manager")

        queue_metrics = {}
        total_queued = 0
        total_processing = 0
        total_consumers = 0

        for topic in topics:
            try:
                queue_name = self._resolve_queue_name(topic)
                url = f"{self.management_url}/api/queues/%2f/{queue_name}"
                async with self._session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()

                        messages = data.get('messages', 0)
                        messages_ready = data.get('messages_ready', 0)
                        messages_unacknowledged = data.get('messages_unacknowledged', 0)
                        consumers = data.get('consumers', 0)

                        queue_metrics[topic] = {
                            'total_messages': messages,
                            'ready_messages': messages_ready,
                            'processing_messages': messages_unacknowledged,
                            'consumers': consumers,
                            'queue_exists': True,
                            'memory_bytes': data.get('memory', 0),
                            'state': data.get('state', 'running'),
                            'message_stats': {
                                'publish_rate': data.get('message_stats', {}).get('publish_details', {}).get('rate', 0),
                                'deliver_rate': data.get('message_stats', {}).get('deliver_details', {}).get('rate', 0),
                                'ack_rate': data.get('message_stats', {}).get('ack_details', {}).get('rate', 0)
                            }
                        }

                        total_queued += messages_ready
                        total_processing += messages_unacknowledged
                        total_consumers += consumers

                    elif response.status == 404:
                        queue_metrics[topic] = {
                            'total_messages': 0,
                            'ready_messages': 0,
                            'processing_messages': 0,
                            'consumers': 0,
                            'queue_exists': False,
                            'memory_bytes': 0,
                            'state': 'missing',
                            'message_stats': {
                                'publish_rate': 0,
                                'deliver_rate': 0,
                                'ack_rate': 0
                            },
                            'error': 'Queue not found'
                        }
                    else:
                        logger.warning(f"Error getting queue {topic}: {response.status}")
                        queue_metrics[topic] = {
                            'total_messages': 0,
                            'ready_messages': 0,
                            'processing_messages': 0,
                            'consumers': 0,
                            'queue_exists': False,
                            'memory_bytes': 0,
                            'state': 'error',
                            'message_stats': {
                                'publish_rate': 0,
                                'deliver_rate': 0,
                                'ack_rate': 0
                            },
                            'error': f'HTTP {response.status}'
                        }

            except asyncio.TimeoutError:
                logger.warning(f"Timeout getting queue metrics for {topic}")
                queue_metrics[topic] = {
                    'total_messages': 0,
                    'ready_messages': 0,
                    'processing_messages': 0,
                    'consumers': 0,
                    'queue_exists': False,
                    'memory_bytes': 0,
                    'state': 'timeout',
                    'message_stats': {
                        'publish_rate': 0,
                        'deliver_rate': 0,
                        'ack_rate': 0
                    },
                    'error': 'Timeout'
                }
            except Exception as e:
                logger.error(f"Exception getting queue {topic}: {e}")
                queue_metrics[topic] = {
                    'total_messages': 0,
                    'ready_messages': 0,
                    'processing_messages': 0,
                    'consumers': 0,
                    'queue_exists': False,
                    'memory_bytes': 0,
                    'state': 'error',
                    'message_stats': {
                        'publish_rate': 0,
                        'deliver_rate': 0,
                        'ack_rate': 0
                    },
                    'error': str(e)
                }

        healthy_queues = sum(1 for q in queue_metrics.values() if q.get('queue_exists', False))
        bottleneck_queues = [
            topic for topic, metrics in queue_metrics.items()
            if metrics.get('ready_messages', 0) > 10
        ]
        queues_without_consumers = [
            topic for topic, metrics in queue_metrics.items()
            if metrics.get('consumers', 0) == 0 and metrics.get('queue_exists', False)
        ]

        return {
            'queue_details': queue_metrics,
            'summary': {
                'total_queued_messages': total_queued,
                'total_processing_messages': total_processing,
                'total_consumers': total_consumers,
                'healthy_queues': healthy_queues,
                'total_queues_checked': len(topics),
                'bottleneck_queues': bottleneck_queues,
                'queues_without_consumers': queues_without_consumers,
                'total_memory_bytes': sum(q.get('memory_bytes', 0) for q in queue_metrics.values())
            },
            'timestamp': datetime.now().isoformat()
        }

    async def check_queue_health(self, topics: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Quick health check for queues. Returns simple status for each.

        Args:
            topics: List of topic names to check. If None, uses DEFAULT_TOPICS.

        Returns:
            Dictionary mapping topic names to health status strings
        """
        if topics is None:
            topics = self.DEFAULT_TOPICS.copy()

        if not self._session:
            raise RuntimeError("Monitor must be used as async context manager")

        health_status = {}

        for topic in topics:
            try:
                queue_name = self._resolve_queue_name(topic)
                url = f"{self.management_url}/api/queues/%2f/{queue_name}"
                async with self._session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        consumers = data.get('consumers', 0)
                        state = data.get('state', 'unknown')

                        if state == 'running' and consumers > 0:
                            health_status[topic] = 'healthy'
                        elif state == 'running' and consumers == 0:
                            health_status[topic] = 'no_consumers'
                        else:
                            health_status[topic] = f'unhealthy_{state}'
                    elif response.status == 404:
                        health_status[topic] = 'missing'
                    else:
                        health_status[topic] = f'error_http_{response.status}'
            except asyncio.TimeoutError:
                health_status[topic] = 'timeout'
            except Exception:
                health_status[topic] = 'error'

        return health_status

    async def get_single_queue_metrics(self, topic: str) -> Dict[str, Any]:
        """
        Get metrics for a single queue topic.

        Args:
            topic: The topic name to get metrics for

        Returns:
            Dictionary containing metrics for the single topic
        """
        queue_name = self._resolve_queue_name(topic)
        result = await self.get_workflow_queue_metrics([topic])
        return {
            'topic': topic,
            'queue_name': queue_name,
            'metrics': result['queue_details'].get(topic, {}),
            'timestamp': result['timestamp']
        }

    async def purge_all_workflow_queues(self, topics: Optional[List[str]] = None, confirm: bool = False) -> Dict[str, Any]:
        """
        Purge all messages from workflow queues.

        WARNING: This will permanently delete all messages in the specified queues!

        Args:
            topics: List of topic names to purge. If None, uses DEFAULT_TOPICS.
            confirm: Must be True to actually perform the purge (safety mechanism)

        Returns:
            Dictionary containing purge results for each queue
        """
        if not confirm:
            raise ValueError("Must set confirm=True to actually purge queues. This operation cannot be undone!")

        if topics is None:
            topics = self.DEFAULT_TOPICS.copy()

        if not self._session:
            raise RuntimeError("Monitor must be used as async context manager")

        purge_results = {}
        total_purged = 0

        logger.warning(f"Starting purge operation for {len(topics)} queues")

        for topic in topics:
            try:
                queue_name = self._resolve_queue_name(topic)

                # First get current message count
                metrics_url = f"{self.management_url}/api/queues/%2f/{queue_name}"
                async with self._session.get(metrics_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        messages_before = data.get('messages', 0)
                    elif response.status == 404:
                        purge_results[topic] = {
                            'success': False,
                            'messages_purged': 0,
                            'error': 'Queue not found'
                        }
                        continue
                    else:
                        purge_results[topic] = {
                            'success': False,
                            'messages_purged': 0,
                            'error': f'Cannot access queue: HTTP {response.status}'
                        }
                        continue

                # Perform the purge
                purge_url = f"{self.management_url}/api/queues/%2f/{queue_name}/contents"
                async with self._session.delete(purge_url) as response:
                    if response.status == 204:  # RabbitMQ returns 204 for successful purge
                        purge_results[topic] = {
                            'success': True,
                            'messages_purged': messages_before,
                            'queue_name': queue_name
                        }
                        total_purged += messages_before
                        logger.info(f"Purged {messages_before} messages from queue {queue_name} (topic: {topic})")
                    else:
                        error_text = await response.text()
                        purge_results[topic] = {
                            'success': False,
                            'messages_purged': 0,
                            'error': f'Purge failed: HTTP {response.status} - {error_text}'
                        }
                        logger.error(f"Failed to purge queue {queue_name}: {response.status}")

            except asyncio.TimeoutError:
                purge_results[topic] = {
                    'success': False,
                    'messages_purged': 0,
                    'error': 'Timeout during purge operation'
                }
                logger.error(f"Timeout purging queue for topic {topic}")
            except Exception as e:
                purge_results[topic] = {
                    'success': False,
                    'messages_purged': 0,
                    'error': str(e)
                }
                logger.error(f"Exception purging queue for topic {topic}: {e}")

        successful_purges = sum(1 for result in purge_results.values() if result['success'])

        logger.warning(f"Purge operation completed: {successful_purges}/{len(topics)} queues purged, {total_purged} total messages deleted")

        return {
            'purge_results': purge_results,
            'summary': {
                'total_queues_attempted': len(topics),
                'successful_purges': successful_purges,
                'failed_purges': len(topics) - successful_purges,
                'total_messages_purged': total_purged
            },
            'timestamp': datetime.now().isoformat()
        }

    async def purge_single_queue(self, topic: str, confirm: bool = False) -> Dict[str, Any]:
        """
        Purge all messages from a single queue.

        WARNING: This will permanently delete all messages in the specified queue!

        Args:
            topic: The topic name to purge
            confirm: Must be True to actually perform the purge (safety mechanism)

        Returns:
            Dictionary containing purge result for the queue
        """
        if not confirm:
            raise ValueError("Must set confirm=True to actually purge queue. This operation cannot be undone!")

        result = await self.purge_all_workflow_queues([topic], confirm=True)
        queue_name = self._resolve_queue_name(topic)

        return {
            'topic': topic,
            'queue_name': queue_name,
            'result': result['purge_results'].get(topic, {}),
            'timestamp': result['timestamp']
        }

    async def purge_all_rabbitmq_queues(self, confirm: bool = False, exclude_system_queues: bool = True) -> Dict[str, Any]:
        """
        Purge ALL queues in the RabbitMQ instance (not just workflow queues).

        WARNING: This will permanently delete all messages from ALL queues in RabbitMQ!

        Args:
            exclude_system_queues: If True, excludes RabbitMQ system/management queues

        Returns:
            Dictionary containing purge results for all queues
        """

        if not self._session:
            raise RuntimeError("Monitor must be used as async context manager")

        # First, get all queues in the RabbitMQ instance
        all_queues_url = f"{self.management_url}/api/queues"
        async with self._session.get(all_queues_url) as response:
            if response.status != 200:
                raise RuntimeError(f"Failed to retrieve queue list: HTTP {response.status}")

            queues_data = await response.json()

        # Filter queues if needed
        queue_names = []
        for queue_info in queues_data:
            queue_name = queue_info.get('name', '')
            vhost = queue_info.get('vhost', '/')

            # Skip queues not in default vhost
            if vhost != '/':
                continue

            # Optionally exclude system queues
            if exclude_system_queues and (
                queue_name.startswith('amq.') or
                queue_name.startswith('rabbitmq-') or
                'management' in queue_name.lower()
            ):
                continue

            queue_names.append(queue_name)

        logger.warning(f"Starting purge operation for ALL {len(queue_names)} queues in RabbitMQ instance")

        purge_results = {}
        total_purged = 0

        for queue_name in queue_names:
            try:
                # Get current message count
                metrics_url = f"{self.management_url}/api/queues/%2f/{queue_name}"
                async with self._session.get(metrics_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        messages_before = data.get('messages', 0)
                    else:
                        purge_results[queue_name] = {
                            'success': False,
                            'messages_purged': 0,
                            'error': f'Cannot access queue: HTTP {response.status}'
                        }
                        continue

                # Perform the purge
                purge_url = f"{self.management_url}/api/queues/%2f/{queue_name}/contents"
                async with self._session.delete(purge_url) as response:
                    if response.status == 204:
                        purge_results[queue_name] = {
                            'success': True,
                            'messages_purged': messages_before
                        }
                        total_purged += messages_before
                        logger.info(f"Purged {messages_before} messages from queue {queue_name}")
                    else:
                        error_text = await response.text()
                        purge_results[queue_name] = {
                            'success': False,
                            'messages_purged': 0,
                            'error': f'Purge failed: HTTP {response.status} - {error_text}'
                        }

            except asyncio.TimeoutError:
                purge_results[queue_name] = {
                    'success': False,
                    'messages_purged': 0,
                    'error': 'Timeout during purge operation'
                }
            except Exception as e:
                purge_results[queue_name] = {
                    'success': False,
                    'messages_purged': 0,
                    'error': str(e)
                }

        successful_purges = sum(1 for result in purge_results.values() if result['success'])

        logger.warning(f"Global purge operation completed: {successful_purges}/{len(queue_names)} queues purged, {total_purged} total messages deleted")

        return {
            'purge_results': purge_results,
            'summary': {
                'total_queues_attempted': len(queue_names),
                'successful_purges': successful_purges,
                'failed_purges': len(queue_names) - successful_purges,
                'total_messages_purged': total_purged,
                'excluded_system_queues': exclude_system_queues
            },
            'timestamp': datetime.now().isoformat()
        }