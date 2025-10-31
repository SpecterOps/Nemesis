# Performance Tuning

Nemesis may perform differently depending on the system architecture and resources, specifically RAM and the number of CPUs.

If workflows begin to fail, or you are experiencing major performance issues (as diagnosed by the [Troubleshooting](troubleshooting.md) document) there are a few tunable parameters that can help. Alternatively, if your performance is fine and you want to potentially increase performance, you can increase these values. Most/all of these values involve altering behaviors for the `file-enrichment` service.


# Useful Prometheus Metrics
Minio
```
minio_cluster_usage_objects_count{}
```


# Jaeger
See how long a particular activity takes:
```
curl -sk --user 'n:n' "https://localhost:7443/jaeger/api/traces?service=file-enrichment&operation=activity%7C%7Crun_enrichment_modules&limit=2000" | jq -r '
  [
    .data[]
    .spans[]
    | select(.operationName == "activity||run_enrichment_modules")
    | .duration
  ] as $durs
  | {
      count: ($durs | length),
      min_ms: ($durs | min / 1000),
      max_ms: ($durs | max / 1000),
      avg_ms: (($durs | add / ($durs | length)) / 1000)
    }
'
```


# TODO: Need to document these
- Adjust enrichment workers
- Add some metrics around throughput and RAM/CPU consumption
- Adjust dapr workflow/activity concurrency settings
- How to tune your system to the right settings
  - Seeing gaps between activities in Jaeger
  - Useful Grafana/prometheus metrics
- Scaling the Dapr scheduler:
  - How to determine if scheduler is slow down
  - Creating scheduler replicas
  - Disk performance recommendations (Fast/ramdisk suggestion)
  - Use separate DB instance from app
