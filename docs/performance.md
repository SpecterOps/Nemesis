# Performance Tuning

Nemesis may perform differently depending on the system architecture and resources, specifically RAM and the number of CPUs.

If workflows begin to fail, or you are experiencing major performance issues (as diagnosed by the [Troubleshooting](troubleshooting.md) document) there are a few tunable parameters that can help. Alternatively, if your performance is fine and you want to potentially increase performance, you can increase these values. Most/all of these values involve altering behaviors for the `file-enrichment` service.


### UVICORN_WORKERS

For production (non-dev) deployments, multiple UVICORN_WORKERS are used for the `file-enrichment` service. The default value is 2 and is defined in the `file-enrichment` section in [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/71406afc12f855140ea68aae337076f9b8dc292f/compose.yaml#L217). This value can be set to 1 for troubleshooting, or increased to 4+ for potential performance gains. You can modify this value by defining the `export UVICORN_WORKERS=4` environment variable before launching Nemesis.


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