{{/*
Expand the name of the chart.
*/}}
{{- define "nemesis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "nemesis.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "nemesis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nemesis.labels" -}}
helm.sh/chart: {{ include "nemesis.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nemesis
{{- end }}

{{/*
Selector labels for a given component
Usage: {{ include "nemesis.selectorLabels" (dict "name" "web-api" "context" .) }}
*/}}
{{- define "nemesis.selectorLabels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
{{- end }}

{{/*
Image reference helper
Usage: {{ include "nemesis.image" (dict "image" .Values.webApi.image "context" .) }}
*/}}
{{- define "nemesis.image" -}}
{{- if .image.registry -}}
{{ .image.registry }}/{{ .image.repository }}:{{ .image.tag | default "latest" }}
{{- else if .context.Values.global.imageRegistry -}}
{{ .context.Values.global.imageRegistry }}/{{ .image.repository }}:{{ .image.tag | default "latest" }}
{{- else -}}
{{ .image.repository }}:{{ .image.tag | default "latest" }}
{{- end -}}
{{- end }}

{{/*
Namespace
*/}}
{{- define "nemesis.namespace" -}}
{{- default .Release.Namespace .Values.namespace }}
{{- end }}

{{/*
PostgreSQL connection string
*/}}
{{- define "nemesis.postgresConnectionString" -}}
postgresql://{{ .Values.credentials.postgres.user }}:{{ .Values.credentials.postgres.password }}@pgbouncer:{{ .Values.postgres.port }}/{{ .Values.postgres.database }}?{{ .Values.postgres.parameters }}
{{- end }}

{{/*
RabbitMQ connection string
*/}}
{{- define "nemesis.rabbitmqConnectionString" -}}
amqp://{{ .Values.credentials.rabbitmq.user }}:{{ .Values.credentials.rabbitmq.password }}@rabbitmq:5672
{{- end }}

{{/*
Common Dapr annotations for a service
Usage: {{ include "nemesis.daprAnnotations" (dict "appId" "web-api" "appPort" "8000" "config" "dapr-config" "maxRequestSize" "1Gi") }}
Pass "mountSecrets" false to keep the Dapr secrets file out of the sidecar.
*/}}
{{- define "nemesis.daprAnnotations" -}}
dapr.io/enabled: "true"
dapr.io/app-id: {{ .appId | quote }}
dapr.io/app-port: {{ .appPort | quote }}
dapr.io/config: {{ .config | default "dapr-config" | quote }}
dapr.io/sidecar-image: {{ .sidecarImage | quote }}
dapr.io/http-max-request-size: {{ .maxRequestSizeMB | default "300" | quote }}
dapr.io/enable-metrics: "true"
dapr.io/metrics-port: {{ .metricsPort | default "9090" | quote }}
dapr.io/graceful-shutdown-seconds: "5"
dapr.io/log-level: {{ .logLevel | default "info" | quote }}
{{- if ne (toString .mountSecrets) "false" }}
dapr.io/volume-mounts: "dapr-secrets:/dapr/secrets"
{{- end }}
dapr.io/sidecar-cpu-request: {{ .sidecarCpuRequest | default "50m" | quote }}
dapr.io/sidecar-memory-request: {{ .sidecarMemoryRequest | default "64Mi" | quote }}
dapr.io/sidecar-cpu-limit: {{ .sidecarCpuLimit | default "300m" | quote }}
dapr.io/sidecar-memory-limit: {{ .sidecarMemoryLimit | default "256Mi" | quote }}
{{- if .maxConcurrency }}
dapr.io/app-max-concurrency: {{ .maxConcurrency | quote }}
{{- end }}
{{- end }}

{{/*
Common environment variables for services that need DB access
*/}}
{{- define "nemesis.postgresEnv" -}}
- name: POSTGRES_USER
  valueFrom:
    secretKeyRef:
      name: nemesis-secrets
      key: POSTGRES_USER
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: nemesis-secrets
      key: POSTGRES_PASSWORD
- name: POSTGRES_HOST
  value: "pgbouncer"
- name: POSTGRES_PORT
  value: {{ .Values.postgres.port | quote }}
- name: POSTGRES_DB
  value: {{ .Values.postgres.database | quote }}
- name: POSTGRES_PARAMETERS
  value: {{ .Values.postgres.parameters | quote }}
{{- end }}

{{/*
Common environment variables for services that need S3-compatible storage access
*/}}
{{- define "nemesis.s3Env" -}}
- name: S3_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: nemesis-secrets
      key: S3_ACCESS_KEY
- name: S3_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: nemesis-secrets
      key: S3_SECRET_KEY
- name: S3_ENDPOINT
  value: "seaweedfs:8333"
- name: S3_BUCKET
  value: "files"
{{- end }}

{{/*
Common environment variables for services that need RabbitMQ access
*/}}
{{- define "nemesis.rabbitmqEnv" -}}
- name: RABBITMQ_USER
  valueFrom:
    secretKeyRef:
      name: nemesis-secrets
      key: RABBITMQ_USER
- name: RABBITMQ_PASSWORD
  valueFrom:
    secretKeyRef:
      name: nemesis-secrets
      key: RABBITMQ_PASSWORD
- name: RABBITMQ_CONNECTION_STRING
  valueFrom:
    secretKeyRef:
      name: nemesis-secrets
      key: RABBITMQ_CONNECTION_STRING
{{- end }}

{{/*
Init container that waits for PostgreSQL to be ready.
Usage: {{ include "nemesis.waitForPostgres" . | nindent 8 }}
*/}}
{{- define "nemesis.waitForPostgres" -}}
- name: wait-for-postgres
  image: busybox:1.38.0
  command: ['sh', '-c', 'until nc -z postgres 5432; do echo "Waiting for PostgreSQL..."; sleep 2; done']
{{- end }}

{{/*
Init container that waits for RabbitMQ to be ready.
Usage: {{ include "nemesis.waitForRabbitmq" . | nindent 8 }}
*/}}
{{- define "nemesis.waitForRabbitmq" -}}
- name: wait-for-rabbitmq
  image: busybox:1.38.0
  command: ['sh', '-c', 'until nc -z rabbitmq 5672; do echo "Waiting for RabbitMQ..."; sleep 2; done']
{{- end }}

{{/*
Init container that waits for PgBouncer to be ready.
Usage: {{ include "nemesis.waitForPgbouncer" . | nindent 8 }}
*/}}
{{- define "nemesis.waitForPgbouncer" -}}
- name: wait-for-pgbouncer
  image: busybox:1.38.0
  command: ['sh', '-c', 'until nc -z pgbouncer 5432; do echo "Waiting for PgBouncer..."; sleep 2; done']
{{- end }}

{{/*
Init containers that wait for PgBouncer and RabbitMQ.
Usage: include in pod spec under initContainers
*/}}
{{- define "nemesis.waitForInfra" -}}
{{- include "nemesis.waitForPgbouncer" . }}
{{ include "nemesis.waitForRabbitmq" . }}
{{- end }}

{{/*
Volume definition for Dapr secrets file.
Usage: include in pod spec under volumes
*/}}
{{- define "nemesis.daprSecretsVolume" -}}
- name: dapr-secrets
  secret:
    secretName: nemesis-dapr-secrets
{{- end }}

{{/*
Volume mount for Dapr secrets file.
Usage: include in container spec under volumeMounts
*/}}
{{- define "nemesis.daprSecretsVolumeMount" -}}
- name: dapr-secrets
  mountPath: /dapr/secrets
  readOnly: true
{{- end }}

{{/*
Hasura admin secret. Uses credentials.hasura.adminSecret when set to something other than the old
public default; otherwise keeps the value already stored in the nemesis-secrets Secret (so upgrades
don't rotate it), or generates a random one on first install. Resolved once per render so every
template gets the same value.
*/}}
{{- define "nemesis.hasuraAdminSecret" -}}
{{- if not (hasKey .Values.credentials.hasura "_resolvedAdminSecret") -}}
{{- $secret := .Values.credentials.hasura.adminSecret | default "" -}}
{{- if or (eq $secret "") (eq $secret "pass456") -}}
{{- $secret = "" -}}
{{- $existing := lookup "v1" "Secret" (include "nemesis.namespace" .) "nemesis-secrets" -}}
{{- if and $existing $existing.data (hasKey $existing.data "HASURA_ADMIN_SECRET") -}}
{{- $stored := index $existing.data "HASURA_ADMIN_SECRET" | b64dec -}}
{{- if and (ne $stored "") (ne $stored "pass456") -}}
{{- $secret = $stored -}}
{{- end -}}
{{- end -}}
{{- if eq $secret "" -}}
{{- $secret = randAlphaNum 48 -}}
{{- end -}}
{{- end -}}
{{- $_ := set .Values.credentials.hasura "_resolvedAdminSecret" $secret -}}
{{- end -}}
{{- index .Values.credentials.hasura "_resolvedAdminSecret" -}}
{{- end }}

{{/*
Legacy LiteLLM password from llm.litellm.env.litellmAdminPassword (pre-credentials.litellm values), or "admin123",
the value older releases used for both the LiteLLM master key and salt.
*/}}
{{- define "nemesis.litellmLegacyPassword" -}}
{{- $llm := .Values.llm | default dict -}}
{{- $litellm := $llm.litellm | default dict -}}
{{- $env := $litellm.env | default dict -}}
{{- $env.litellmAdminPassword | default "admin123" -}}
{{- end }}

{{/*
LiteLLM master key ("sk-" + credentials.litellm.adminPassword). When unset or the old public default
("admin123"), keeps the value already stored in nemesis-secrets or generates a random one.
*/}}
{{- define "nemesis.litellmMasterKey" -}}
{{- if not (hasKey .Values.credentials.litellm "_resolvedMasterKey") -}}
{{- $password := .Values.credentials.litellm.adminPassword | default (include "nemesis.litellmLegacyPassword" .) -}}
{{- $key := "" -}}
{{- if and (ne $password "") (ne $password "admin123") -}}
{{- $key = printf "sk-%s" $password -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" (include "nemesis.namespace" .) "nemesis-secrets" -}}
{{- if and $existing $existing.data (hasKey $existing.data "LITELLM_MASTER_KEY") -}}
{{- $stored := index $existing.data "LITELLM_MASTER_KEY" | b64dec -}}
{{- if and (ne $stored "") (ne $stored "sk-admin123") -}}
{{- $key = $stored -}}
{{- end -}}
{{- end -}}
{{- if eq $key "" -}}
{{- $key = printf "sk-%s" (randAlphaNum 48) -}}
{{- end -}}
{{- end -}}
{{- $_ := set .Values.credentials.litellm "_resolvedMasterKey" $key -}}
{{- end -}}
{{- index .Values.credentials.litellm "_resolvedMasterKey" -}}
{{- end }}

{{/*
LiteLLM salt key. Uses credentials.litellm.saltKey when set; otherwise keeps the stored value. An
existing release without a stored salt used its old master key (normally "sk-admin123") as its salt, and keeps
it so credentials LiteLLM already encrypted stay readable; a fresh install gets a random salt.
*/}}
{{- define "nemesis.litellmSaltKey" -}}
{{- if not (hasKey .Values.credentials.litellm "_resolvedSaltKey") -}}
{{- $salt := .Values.credentials.litellm.saltKey | default "" -}}
{{- if eq $salt "" -}}
{{- $existing := lookup "v1" "Secret" (include "nemesis.namespace" .) "nemesis-secrets" -}}
{{- if and $existing $existing.data -}}
{{- if hasKey $existing.data "LITELLM_SALT_KEY" -}}
{{- $salt = index $existing.data "LITELLM_SALT_KEY" | b64dec -}}
{{- else -}}
{{- $salt = printf "sk-%s" (include "nemesis.litellmLegacyPassword" .) -}}
{{- end -}}
{{- end -}}
{{- if eq $salt "" -}}
{{- $salt = printf "sk-%s" (randAlphaNum 48) -}}
{{- end -}}
{{- end -}}
{{- $_ := set .Values.credentials.litellm "_resolvedSaltKey" $salt -}}
{{- end -}}
{{- index .Values.credentials.litellm "_resolvedSaltKey" -}}
{{- end }}

{{/*
Dapr app IDs allowed to load the secret store and the components that read from it (state store).
Every Dapr app except gotenberg, which renders attacker-influenced HTML and must not reach secrets.
*/}}
{{- define "nemesis.daprSecretScopes" -}}
- {{ .Values.webApi.dapr.appId }}
- {{ .Values.fileEnrichment.dapr.appId }}
- {{ .Values.documentConversion.dapr.appId }}
- {{ .Values.titusScanner.dapr.appId }}
- {{ .Values.dotnetService.dapr.appId }}
- {{ .Values.alerting.dapr.appId }}
- {{ .Values.housekeeping.dapr.appId }}
- {{ .Values.llm.agents.dapr.appId }}
{{- end }}
