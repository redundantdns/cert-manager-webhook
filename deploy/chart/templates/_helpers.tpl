{{/* Name of the chart. */}}
{{- define "rdns-webhook.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified name of the release's objects. */}}
{{- define "rdns-webhook.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "rdns-webhook.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rdns-webhook.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "rdns-webhook.labels" -}}
{{ include "rdns-webhook.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/* The image reference: repository:tag, plus @digest when pinned. */}}
{{- define "rdns-webhook.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if .Values.image.digest -}}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "rdns-webhook.servingCertificate" -}}
{{- printf "%s-webhook-tls" (include "rdns-webhook.fullname" .) -}}
{{- end -}}

{{- define "rdns-webhook.rootCACertificate" -}}
{{- printf "%s-ca" (include "rdns-webhook.fullname" .) -}}
{{- end -}}

{{- define "rdns-webhook.selfSignedIssuer" -}}
{{- printf "%s-selfsign" (include "rdns-webhook.fullname" .) -}}
{{- end -}}

{{- define "rdns-webhook.rootCAIssuer" -}}
{{- printf "%s-ca" (include "rdns-webhook.fullname" .) -}}
{{- end -}}

{{/* Namespaces of the token Secrets (default: the release namespace). */}}
{{- define "rdns-webhook.secretNamespaces" -}}
{{- if .Values.secretNamespaces -}}
{{- toJson (uniq .Values.secretNamespaces) -}}
{{- else -}}
{{- toJson (list .Release.Namespace) -}}
{{- end -}}
{{- end -}}
