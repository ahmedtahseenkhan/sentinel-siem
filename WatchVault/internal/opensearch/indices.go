package opensearch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

func (c *Client) CreateIndex(name string, body map[string]interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	res, err := c.os.Indices.Create(name, c.os.Indices.Create.WithBody(bytes.NewReader(data)))
	if err != nil {
		return fmt.Errorf("create index %s: %w", name, err)
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("create index %s: %s", name, res.String())
	}
	c.logger.Info("index created", zap.String("name", name))
	return nil
}

func (c *Client) IndexExists(name string) (bool, error) {
	res, err := c.os.Indices.Exists([]string{name})
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	return res.StatusCode == 200, nil
}

func (c *Client) DeleteIndex(name string) error {
	res, err := c.os.Indices.Delete([]string{name})
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("delete index %s: %s", name, res.String())
	}
	return nil
}

func (c *Client) PutIndexTemplate(name string, body map[string]interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	res, err := c.os.Indices.PutIndexTemplate(name, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("put template %s: %w", name, err)
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("put template %s: %s", name, res.String())
	}
	c.logger.Info("index template created", zap.String("name", name))
	return nil
}

func (c *Client) ListIndices(pattern string) ([]map[string]interface{}, error) {
	res, err := c.os.Cat.Indices(c.os.Cat.Indices.WithIndex(pattern), c.os.Cat.Indices.WithFormat("json"))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var indices []map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&indices); err != nil {
		return nil, err
	}
	return indices, nil
}

func (c *Client) GetClusterHealth() (map[string]interface{}, error) {
	res, err := c.os.Cluster.Health()
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var health map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&health); err != nil {
		return nil, err
	}
	return health, nil
}

func (c *Client) HealthStatus() int32 {
	health, err := c.GetClusterHealth()
	if err != nil {
		return 2
	}
	status, _ := health["status"].(string)
	switch strings.ToLower(status) {
	case "green":
		return 0
	case "yellow":
		return 1
	default:
		return 2
	}
}

// PutISMPolicy creates or updates an OpenSearch ISM (Index State Management) policy.
// The policy controls index lifecycle transitions such as rollover, warm storage, and deletion.
func (c *Client) PutISMPolicy(policyID string, body map[string]interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal ism policy: %w", err)
	}

	// The opensearch-go transport replaces the host portion of the URL with the
	// pool connection URL, so passing a path-only request is sufficient.
	req, err := http.NewRequest(http.MethodPut, "/_plugins/_ism/policies/"+policyID, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build ism request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.os.Perform(req)
	if err != nil {
		return fmt.Errorf("put ism policy %s: %w", policyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("put ism policy %s: status %d: %s", policyID, resp.StatusCode, string(raw))
	}

	c.logger.Info("ISM policy applied", zap.String("policy", policyID))
	return nil
}
