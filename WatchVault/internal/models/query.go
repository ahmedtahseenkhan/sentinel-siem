package models

type SearchRequest struct {
	Index string                 `json:"index"`
	Query map[string]interface{} `json:"query"`
	From  int                    `json:"from"`
	Size  int                    `json:"size"`
	Sort  []map[string]string    `json:"sort,omitempty"`
}

type SearchResponse struct {
	Total int64                    `json:"total"`
	Hits  []map[string]interface{} `json:"hits"`
	Took  int64                    `json:"took_ms"`
}
