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
*/}}
{{- define "nemesis.daprAnnotations" -}}
dapr.io/enabled: "true"
dapr.io/app-id: {{ .appId | quote }}
dapr.io/app-port: {{ .appPort | quote }}
dapr.io/config: {{ .config | default "dapr-config" | quote }}
dapr.io/http-max-request-size: {{ .maxRequestSizeMB | default "300" | quote }}
dapr.io/enable-metrics: "true"
dapr.io/metrics-port: {{ .metricsPort | default "9090" | quote }}
dapr.io/graceful-shutdown-seconds: "5"
dapr.io/log-level: {{ .logLevel | default "info" | quote }}
dapr.io/volume-mounts: "dapr-secrets:/dapr/secrets"
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
  image: busybox:1.37
  command: ['sh', '-c', 'until nc -z postgres 5432; do echo "Waiting for PostgreSQL..."; sleep 2; done']
{{- end }}

{{/*
Init container that waits for RabbitMQ to be ready.
Usage: {{ include "nemesis.waitForRabbitmq" . | nindent 8 }}
*/}}
{{- define "nemesis.waitForRabbitmq" -}}
- name: wait-for-rabbitmq
  image: busybox:1.37
  command: ['sh', '-c', 'until nc -z rabbitmq 5672; do echo "Waiting for RabbitMQ..."; sleep 2; done']
{{- end }}

{{/*
Init container that waits for PgBouncer to be ready.
Usage: {{ include "nemesis.waitForPgbouncer" . | nindent 8 }}
*/}}
{{- define "nemesis.waitForPgbouncer" -}}
- name: wait-for-pgbouncer
  image: busybox:1.37
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
