{{- define "sekret-operator.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sekret-operator.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "sekret-operator.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "sekret-operator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "sekret-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sekret-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Watched namespaces as a list, after checking the values agree with each other. */}}
{{- define "sekret-operator.watchNamespaces" -}}
{{- if hasKey .Values "watchNamespace" }}
{{- fail "watchNamespace was replaced by watchNamespaces (a list); set watchNamespaces, or clusterWide: true to watch every namespace" }}
{{- end }}
{{- if and .Values.clusterWide .Values.watchNamespaces }}
{{- fail "set either clusterWide or watchNamespaces, not both" }}
{{- end }}
{{- if .Values.clusterWide }}
{{- list | toJson }}
{{- else }}
{{- default (list .Release.Namespace) .Values.watchNamespaces | uniq | toJson }}
{{- end }}
{{- end }}

{{- define "sekret-operator.rules" -}}
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  - apiGroups: ["sekret.sam-ruff.github.io"]
    resources: ["sekretsecrets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["sekret.sam-ruff.github.io"]
    resources: ["sekretsecrets/status"]
    verbs: ["patch", "update"]
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    verbs: ["get"]
    {{- with .Values.tokenServiceAccounts }}
    resourceNames: {{ toJson . }}
    {{- end }}
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    verbs: ["create"]
    {{- with .Values.tokenServiceAccounts }}
    resourceNames: {{ toJson . }}
    {{- end }}
{{- end }}

{{- /*
The operator's rights would pass to every pod that runs as the account, so it is never the
namespace's `default` one, which pods get when they name none.
*/}}
{{- define "sekret-operator.serviceAccountName" -}}
{{- $name := .Values.serviceAccount.name }}
{{- if eq $name "default" }}
{{- fail "serviceAccount.name must not be \"default\": every pod in the namespace that names no account would get the operator's rights" }}
{{- end }}
{{- if .Values.serviceAccount.create }}
{{- default (include "sekret-operator.fullname" .) $name }}
{{- else if $name }}
{{- $name }}
{{- else }}
{{- fail "serviceAccount.name is required when serviceAccount.create is false; name an account used only by the operator" }}
{{- end }}
{{- end }}
