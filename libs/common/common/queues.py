# The *_PUBSUB variables correspond with the metadata.name field in the
# Dapr pubsub yaml files in infra/dapr/components/pubsub

ALERTING_PUBSUB = "alerting"
ALERTING_NEW_ALERT_TOPIC = "new_alert"

DOTNET_PUBSUB = "dotnet"
DOTNET_INPUT_TOPIC = "dotnet_input"
DOTNET_OUTPUT_TOPIC = "dotnet_output"

FILES_PUBSUB = "files"
FILES_NEW_FILE_TOPIC = "new_file"  # Emitted when a new file is uploaded
FILES_FILE_ENRICHED_TOPIC = "file_enriched"  # Emitted when a file is finished being enriched
FILES_BULK_ENRICHMENT_TASK_TOPIC = "bulk_enrichment_task"

WORKFLOW_MONITOR_PUBSUB = "workflow_monitor"
WORKFLOW_MONITOR_COMPLETED_TOPIC = "workflow_completed"

NOSEYPARKER_PUBSUB = "noseyparker"
NOSEYPARKER_INPUT_TOPIC = "noseyparker_input"
NOSEYPARKER_OUTPUT_TOPIC = "noseyparker_output"
