/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package otel

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/ctem/security-operator/api/v1alpha1"
	"github.com/ctem/security-operator/internal/controller/feature"
)

const (
	NodeCollectorConfigMapName = "otel-node-collector-config"
	GatewayConfigMapName       = "otel-gateway-config"
	NodeCollectorConfigKey     = "config.yaml"
	GatewayConfigKey           = "config.yaml"
)

// nodeCollectorTemplate is the OTel Node Collector config template.
// It generates filelog receivers for each security tool that produces logs.
var nodeCollectorTemplate = template.Must(template.New("node-collector").Parse(`
receivers:
{{- range .Receivers }}
  {{ .ReceiverName }}:
    include:
      - {{ .LogPath }}
    start_at: beginning
    include_file_path: true
    include_file_name: false
    operators:
      - type: json_parser
        parse_from: body
        {{- if .Attributes }}
      - type: add
        field: resource["security_tool"]
        value: "{{ index .Attributes "security_tool" }}"
        {{- end }}
{{- end }}

processors:
  batch:
    timeout: 5s
    send_batch_size: 1000
  resource:
    attributes:
      - key: k8s.node.name
        from_attribute: env.K8S_NODE_NAME
        action: insert

exporters:
  otlp:
    endpoint: "otel-gateway:4317"
    tls:
      insecure: true

service:
  pipelines:
    logs:
      receivers:
{{- range .Receivers }}
        - {{ .ReceiverName }}
{{- end }}
      processors:
        - resource
        - batch
      exporters:
        - otlp
`))

// gatewayTemplate is the OTel Gateway config template.
// It routes logs to the appropriate ES indices based on the target_index attribute.
var gatewayTemplate = template.Must(template.New("gateway").Parse(`
extensions:
  health_check:
    endpoint: "0.0.0.0:13133"

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"
      http:
        endpoint: "0.0.0.0:4318"

processors:
  batch:
    timeout: 5s
    send_batch_size: 1000

exporters:
  elasticsearch/events:
    endpoints:
      - "{{ .ESURL }}"
    logs_index: "{{ .EventsIndex }}"
    {{- if .ESUser }}
    user: "{{ .ESUser }}"
    password: "${ES_PASSWORD}"
    {{- end }}
    tls:
      insecure_skip_verify: {{ .InsecureSkipVerify }}
  elasticsearch/inventory:
    endpoints:
      - "{{ .ESURL }}"
    logs_index: "{{ .InventoryIndex }}"
    {{- if .ESUser }}
    user: "{{ .ESUser }}"
    password: "${ES_PASSWORD}"
    {{- end }}
    tls:
      insecure_skip_verify: {{ .InsecureSkipVerify }}

connectors:
  routing:
    default_pipelines:
      - logs/events
    error_mode: ignore
    table:
      - statement: route() where attributes["security_tool"] == "osquery"
        pipelines:
          - logs/inventory

service:
  extensions:
    - health_check
  pipelines:
    logs/receive:
      receivers:
        - otlp
      processors:
        - batch
      exporters:
        - routing
    logs/events:
      receivers:
        - routing
      exporters:
        - elasticsearch/events
    logs/inventory:
      receivers:
        - routing
      exporters:
        - elasticsearch/inventory
`))

// nodeCollectorTemplateData holds the data for the node collector config template.
type nodeCollectorTemplateData struct {
	Receivers []*feature.OTelReceiverConfig
}

// gatewayTemplateData holds the data for the gateway config template.
type gatewayTemplateData struct {
	ESURL              string
	EventsIndex        string
	InventoryIndex     string
	ESUser             string
	InsecureSkipVerify bool
}

// BuildNodeCollectorConfig generates the OTel Node Collector ConfigMap from the
// list of active feature receiver configs.
func BuildNodeCollectorConfig(receivers []*feature.OTelReceiverConfig, output securityv1alpha1.OutputSpec, namespace string) *corev1.ConfigMap {
	data := nodeCollectorTemplateData{
		Receivers: receivers,
	}

	var buf bytes.Buffer
	if err := nodeCollectorTemplate.Execute(&buf, data); err != nil {
		// Template execution should never fail with valid data; return minimal config
		return buildMinimalConfigMap(NodeCollectorConfigMapName, namespace, NodeCollectorConfigKey,
			fmt.Sprintf("# Error generating config: %v\n", err))
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      NodeCollectorConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			NodeCollectorConfigKey: strings.TrimLeft(buf.String(), "\n"),
		},
	}
}

// BuildGatewayConfig generates the OTel Gateway ConfigMap.
func BuildGatewayConfig(output securityv1alpha1.OutputSpec, namespace string) *corev1.ConfigMap {
	data := gatewayTemplateData{
		InsecureSkipVerify: false,
	}

	if output.Elasticsearch != nil {
		data.ESURL = output.Elasticsearch.URL

		idx := output.Elasticsearch.Indices
		data.EventsIndex = idx.Events
		if data.EventsIndex == "" {
			data.EventsIndex = "security-events"
		}
		data.InventoryIndex = idx.Inventory
		if data.InventoryIndex == "" {
			data.InventoryIndex = "security-inventory"
		}

		if output.Elasticsearch.TLS != nil {
			data.InsecureSkipVerify = output.Elasticsearch.TLS.InsecureSkipVerify
		}

		if output.Elasticsearch.Auth != nil && output.Elasticsearch.Auth.SecretRef != nil {
			// Set ESUser to "elastic" as default; the actual password is expected
			// to be injected via ES_PASSWORD env var from the referenced secret.
			data.ESUser = "elastic"
		}
	}

	var buf bytes.Buffer
	if err := gatewayTemplate.Execute(&buf, data); err != nil {
		return buildMinimalConfigMap(GatewayConfigMapName, namespace, GatewayConfigKey,
			fmt.Sprintf("# Error generating config: %v\n", err))
	}

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GatewayConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			GatewayConfigKey: strings.TrimLeft(buf.String(), "\n"),
		},
	}
}

func buildMinimalConfigMap(name, namespace, key, content string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string]string{
			key: content,
		},
	}
}
