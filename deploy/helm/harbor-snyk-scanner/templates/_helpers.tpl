{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "harbor-snyk-scanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "harbor-snyk-scanner.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "harbor-snyk-scanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "harbor-snyk-scanner.labels" -}}
helm.sh/chart: {{ include "harbor-snyk-scanner.chart" . }}
{{ include "harbor-snyk-scanner.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "harbor-snyk-scanner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "harbor-snyk-scanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Additional annotations for the Deployment, Pods and Service.
*/}}
{{- define "scanner.annotations" -}}
{{- if .Values.annotations }}
{{- toYaml .Values.annotations }}
{{- end }}
{{- end }}

{{/*
Additional labels for the Deployment, Pods and Service.
*/}}
{{- define "scanner.labels" -}}
{{- if .Values.labels }}
{{- toYaml .Values.labels }}
{{- end }}
{{- end }}
