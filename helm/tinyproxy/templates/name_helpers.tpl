{{/* Chart naming helpers */}}
{{- define "tinyproxy.name" -}}
tinyproxy
{{- end -}}

{{- define "tinyproxy.fullname" -}}
{{ include "tinyproxy.name" . }}-{{ .Release.Name }}
{{- end -}}
