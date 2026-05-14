package opensearch

import (
	"bytes"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
)

type BulkItem struct {
	Index string
	ID    string
	Doc   map[string]interface{}
}

func (c *Client) BulkIndex(items []BulkItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}

	var buf bytes.Buffer
	for _, item := range items {
		meta := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": item.Index,
			},
		}
		if item.ID != "" {
			meta["index"].(map[string]interface{})["_id"] = item.ID
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return 0, fmt.Errorf("marshal meta: %w", err)
		}
		buf.Write(metaJSON)
		buf.WriteByte('\n')

		docJSON, err := json.Marshal(item.Doc)
		if err != nil {
			return 0, fmt.Errorf("marshal doc: %w", err)
		}
		buf.Write(docJSON)
		buf.WriteByte('\n')
	}

	res, err := c.os.Bulk(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return 0, fmt.Errorf("bulk request: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return 0, fmt.Errorf("bulk error: %s", res.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("parse bulk response: %w", err)
	}

	if errors, ok := result["errors"].(bool); ok && errors {
		failed := 0
		var firstReason string
		if itemsRaw, ok := result["items"].([]interface{}); ok {
			for _, raw := range itemsRaw {
				entry, _ := raw.(map[string]interface{})
				for _, op := range entry {
					opMap, _ := op.(map[string]interface{})
					if errObj, hasErr := opMap["error"]; hasErr && errObj != nil {
						failed++
						if firstReason == "" {
							if errMap, ok := errObj.(map[string]interface{}); ok {
								firstReason, _ = errMap["reason"].(string)
							}
						}
					}
				}
			}
		}
		c.logger.Warn("bulk indexing had errors",
			zap.Int("total_items", len(items)),
			zap.Int("failed", failed),
			zap.String("first_error", firstReason),
		)
	}

	return len(items), nil
}
