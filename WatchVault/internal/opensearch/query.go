package opensearch

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/watchvault/watchvault/internal/models"
)

func (c *Client) Search(req *models.SearchRequest) (*models.SearchResponse, error) {
	body := map[string]interface{}{
		"query": req.Query,
		"from":  req.From,
		"size":  req.Size,
	}
	if len(req.Sort) > 0 {
		body["sort"] = req.Sort
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	res, err := c.os.Search(
		c.os.Search.WithIndex(req.Index),
		c.os.Search.WithBody(bytes.NewReader(data)),
	)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	var raw map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return nil, err
	}

	resp := &models.SearchResponse{}
	if hits, ok := raw["hits"].(map[string]interface{}); ok {
		if total, ok := hits["total"].(map[string]interface{}); ok {
			if v, ok := total["value"].(float64); ok {
				resp.Total = int64(v)
			}
		}
		if hitList, ok := hits["hits"].([]interface{}); ok {
			for _, h := range hitList {
				if hm, ok := h.(map[string]interface{}); ok {
					if src, ok := hm["_source"].(map[string]interface{}); ok {
						src["_id"] = hm["_id"]
						src["_index"] = hm["_index"]
						resp.Hits = append(resp.Hits, src)
					}
				}
			}
		}
	}
	if took, ok := raw["took"].(float64); ok {
		resp.Took = int64(took)
	}

	return resp, nil
}
