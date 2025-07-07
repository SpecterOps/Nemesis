# Performance Tuning

Nemesis may perform differently depending on the system architecture and resources, specifically RAM and the number of CPUs.

If workflows begin to fail, or you are experiencing major performance issues (as diagnosed by the [Troubleshooting](troubleshooting.md) document) there are a few tunable parameters that can help. Alternatively, if your performance is fine and you want to potentially increase performance, you can increase these values. Most/all of these values involve altering behaviors for the `file-enrichment` service.


### UVICORN_WORKERS

For production (non-dev) deployments, multiple UVICORN_WORKERS are used for the `file-enrichment` service. The default value is 2 and is defined in the `file-enrichment` section in [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/71406afc12f855140ea68aae337076f9b8dc292f/compose.yaml#L217). This value can be set to 1 for troubleshooting, or increased to 4+ for potential performance gains. You can modify this value by defining the `export UVICORN_WORKERS=4` environment variable before launching Nemesis.


### MAX_PARALLEL_WORKFLOWS

The `file-enrichment` container runs a number of file-enrichment workflows in parallel, defaulting to 5. You can modify this value by defining the `export MAX_PARALLEL_WORKFLOWS=3` environment variable before launching Nemesis.


### MAX_PARALLEL_ENRICHMENT_MODULES

For each file enrichment workflow, the `file-enrichment` container runs multiple file enrichment modules in parallel, defaulting to 5. You can modify this value by defining the `export MAX_PARALLEL_ENRICHMENT_MODULES=3` environment variable before launching Nemesis.
