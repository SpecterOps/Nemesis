# Nemesis Performance Tuning

This document details different ways to monitor and tune Nemesis's performance. Nemesis performs differently depending on a variety of factors, including the host's architecture and resources (particularly CPU, RAM, and disk speed) and the workload (e.g. the # of files and imbalances in the number of documents, .NET assemblies, source code, etc.).

If workflows begin to fail, or you are experiencing major performance issues, there are a few tunable settings that can help. Alternatively, if your performance is fine already and you want to potentially increase performance more or potentially reduce CPU/RAM usage (to save $$$), you can adjust these values. This document primarily focuses on increasing performance, but you can of course adjust the settings down to decrease resources.

# Hardware Resourcing
The first thing to check is if Nemesis has enough hardware resources.

## CPU

Under load, monitor CPU usage (e.g. with `top`/`htop` or the "Node Exporter" Grafana dashboard (if monitoring is enabled in Nemesis). If all cores are at lower utilization or not maxed out, continue following through this guide. Otherwise, you'll need to increase CPU resources for Nemesis since Nemesis is primarily CPU bound.

## RAM
Under load, monitor RAM usage (e.g. with `top`/`htop`, `free -h`, or the "Node Exporter" Grafana dashboard if monitoring is enabled in Nemesis). Ensure that all memory is not being used; otherwise, you will need to increase RAM.

Note that Nemesis will buffer/cache memory if it can. Minio in particular will use any available RAM to cache file data in RAM. This memory is reclaimable, and therefore is still useable by other services/applications. We recommend having at least 1Gb of cache memory available. More may improve performance, but for the most part Nemesis is CPU bound, not RAM bound. You can apply [docker compose memory limits](https://docs.docker.com/reference/compose-file/deploy/#resources) to specific services if you want to constrain how much RAM minio consumes.

## Disk
The requirements will vary widely here depending on your workload size. A general rule of thumb is 3x the size of all the files being uploaded. Use SSDs if possible.

# Analyzing Your Workload
## Analyzing Queues
Normally people realize Nemesis isn't going fast enough after uploading a bunch of files and it taking forever to process. Usually this is indicative that files get queued up for processing, but aren't processed fast enough. You can confirm this by [analyzing the message queues](./troubleshooting.md#analyze-message-queues) in Nemesis/RabbitMQ.

In RabbitMQ, `Ready` counts signify messages waiting to be processed and the `delivery / get` rates (messages per second) will give you an idea of the processing speed. The following table maps the service to queue mappings:

| Docker Service      | Queue Name                      | Description                                                                               |
|---------------------|---------------------------------|-------------------------------------------------------------------------------------------|
| file_enrichment     | files-new_file                  | Uploaded files that haven't begun processing                                              |
| document_conversion | files-document_conversion_input | Files waiting to go through document_conversion (strings, text extraction, PDF conversion) |
| dotnet_service      | dotnet-dotnet_input             | Files waiting for .NET decompilation and inspect assembly                                 |
| noseyparker-scanner | noseyparker-noseyparker_input   | Files waiting to be scanned by noseyparker                                                |

If the queue message rates are too slow, you can adjust some settings to try and increase performance. The following sections detail the best bang-for-the-buck service-specific adjustments you can make.

### file_enrichment
Every uploaded file is first placed on the `files-new_file` queue. The file_enrichment service consumes files from the queue and processes each one with the [applicable enrichment modules](https://github.com/SpecterOps/Nemesis/tree/main/libs/file_enrichment_modules). To improve file_enrichment performance, analyze its CPU usage with `docker compose stats file-enrichment` or in the "Docker Monitoring" dashboard in Grafana. 

The first thing to tune is making sure file_enrichment is efficiently using a single core (currently, the file_enrichment service does not take full advantage of parallelism). Good utilization will look like ~90-110% CPU usage. i.e. the worker thread is taking full advantage of a single core. If CPU utilization is low, increase the number of workers with the `ENRICHMENT_MAX_PARALLEL_WORKFLOWS` environment variable (default is 5, meaning 5 workers). You'll also want to make sure this isn't set too high, causing workers to compete for CPU amongst themselves. If you increase to ~100 workers, then you'll also need to adjust Dapr's RabbitMQ `prefetchCount` count in [file.yaml](https://github.com/SpecterOps/Nemesis/blob/main/infra/dapr/components/pubsub/files.yaml).

If additional cores are available, you can scale the file_enrichment container by adding replicas. Do this by modifying both the [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.yaml#L327) and [compose.prod.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.prod.build.yaml#L34) files, uncommenting the disabled `file-enrichment-###` placeholder replicas therein. Feel free to add more by following the same pattern, if wanted.

### document_conversion
Every file is added to the `files-document_conversion_input` queue. The document_conversion service consumes files from the queue and extracts text, runs `strings` on the file, and converts documents to PDFs. To improve document_conversion performance, analyze its CPU usage with `docker compose stats document-conversion` or in the "Docker Monitoring" dashboard in Grafana. The document_conversion service can take full advantage of parallelism (so adding replicas is not necessary since a single instance can utilize multiple cores). However, the [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.yaml#L565) has [resource limits](https://docs.docker.com/reference/compose-file/deploy/#resources) that restrict the document-conversion service to 2 cores by default (adjust it if needed). In addition, you can adjust the `DOCUMENTCONVERSION_MAX_PARALLEL_WORKFLOWS` environment variable to adjust the number of workers (2 workers by default).

### noseyparker-scanner
Every text file is added to the `noseyparker-noseyparker_input` queue. The noseyparker-scanner service consumes files from the queue and scans them with noseyparker. To improve noseyparker-scanner performance, analyze its CPU usage with `docker compose stats noseyparker-scanner` or in the "Docker Monitoring" dashboard in Grafana. The noseyparker-scanner service can take full advantage of parallelism (so adding replicas is not necessary since a single instance can utilize multiple cores). However, the [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.yaml#L129) has [resource limits](https://docs.docker.com/reference/compose-file/deploy/#resources) that restrict the noseyparker-scanner service to 2 cores by default (adjust it if needed). In addition, you can adjust the `NOSEYPARKER_MAX_CONCURRENT_FILES` environment variable to adjust the number of workers (2 workers by default).


# Dapr Scaling
Nemesis uses [Dapr Workflows](https://docs.dapr.io/developing-applications/building-blocks/workflow/workflow-overview/) to build durable and reliable enrichment pipelines. Underneath, the workflows are managed by Dapr's scheduler service, which shares usage of the Postgres database with Nemesis.

You may need to scale the Dapr infrastructure if you considerably increase the performance of the file_enrichment and/or document_conversion services. Scaling Dapr is beyond the scope of this document, but here's some indicators when you may need to:
- Significant sustained CPU usage (> 80%-90%) by the scheduler container and/or Postgres container.
- Workflows begin failing frequently.
- You notice frequent activity failures/retries in Jaeger traces.

If this is the case, first try increasing the number of scheduler instances ([example](https://github.com/olitomlinson/dapr-workflow-testing/blob/main/compose-1-3.yml#L111-L152)). Dapr does not support more than 3 scheduler instances unless you migrate to using [an external etcd store](https://docs.dapr.io/concepts/dapr-services/scheduler/#external-etcd-database). If Postgres begins to be the bottleneck, you may consider using a separate Postgres instance to store Dapr state.

Additional resources:
- [Tuning Dapr Scheduler for Production](https://www.diagrid.io/blog/tuning-dapr-scheduler-for-production)
- [Dapr Scheduler control plane service overview](https://docs.dapr.io/concepts/dapr-services/scheduler/)


