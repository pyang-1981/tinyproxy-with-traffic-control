{{/* Helper to render lines in tinyproxy.conf for traffic control rules */}}
{{- define "tinyproxy.tcRules" -}}
{{- $rules := .Values.trafficControl.rules -}}
{{- range $i, $r := $rules }}
{{- if and (kindIs "slice" $r) (ge (len $r) 2) }}
TrafficControlRule {{ index $r 0 }} {{ index $r 1 }}
{{- else }}
{{/* ignore invalid entries */}}
{{- end }}
{{- end }}
{{- end }}

{{- define "tinyproxy.tcMappings" -}}
{{- $maps := .Values.trafficControl.mappings -}}
{{- range $i, $m := $maps }}
{{- if and (kindIs "slice" $m) (ge (len $m) 2) }}
TrafficControlMapping {{ index $m 0 }} {{ index $m 1 }}
{{- else }}
{{- end }}
{{- end }}
{{- end }}
