package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/registry"
	"github.com/watchtower/watchtower/internal/store"
	"github.com/watchtower/watchtower/pkg/proto"
)

type ActiveResponseHandler struct {
	registry *registry.Registry
	store    *store.Store
}

func NewActiveResponseHandler(reg *registry.Registry, st *store.Store) *ActiveResponseHandler {
	return &ActiveResponseHandler{registry: reg, store: st}
}

func (h *ActiveResponseHandler) Trigger(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID    string          `json:"agent_id"`
		Action     string          `json:"action"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.AgentID == "" || body.Action == "" {
		writeError(w, http.StatusBadRequest, "agent_id and action are required")
		return
	}

	ar := &models.ActiveResponse{
		ID:         uuid.New().String(),
		AgentID:    body.AgentID,
		Action:     body.Action,
		Parameters: string(body.Parameters),
		Status:     string(models.CommandPending),
		CreatedAt:  time.Now().UnixMilli(),
	}

	if err := h.store.InsertActiveResponse(ar); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	cmd := &proto.ManagerCommand{
		CommandId:   ar.ID,
		CommandType: body.Action,
		Payload:     body.Parameters,
	}

	sent := h.registry.SendCommand(body.AgentID, cmd)
	if sent {
		ar.Status = string(models.CommandSent)
		_ = h.store.UpdateActiveResponseStatus(ar.ID, ar.Status, "")
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"data": ar,
		"sent": sent,
	})
}
