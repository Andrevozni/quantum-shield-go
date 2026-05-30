package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ── HTTP handlers for cluster management ──────────────────────────────────────
//
// These handlers are mounted under /cluster/ by the API server when a Node is
// configured.  They provide:
//
//   GET  /cluster/status    — node state, leader, peers (public within cluster)
//   POST /cluster/join      — add a new voter (leader only; called by the new node)
//   POST /cluster/remove    — remove a voter (leader only; admin role)
//   GET  /cluster/leader    — current leader address (public; for client redirects)

// StatusResponse is the JSON body returned by GET /cluster/status.
type StatusResponse struct {
	NodeID   string            `json:"node_id"`
	State    string            `json:"state"`
	Leader   string            `json:"leader_addr"`
	LeaderID string            `json:"leader_id"`
	Servers  []ServerInfo      `json:"servers"`
	Stats    map[string]string `json:"stats"`
}

// ServerInfo describes one Raft peer.
type ServerInfo struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Suffrage string `json:"suffrage"` // "Voter" | "Nonvoter" | "Staging"
}

// JoinRequest is the body for POST /cluster/join.
type JoinRequest struct {
	NodeID   string `json:"node_id"`
	BindAddr string `json:"bind_addr"`
}

// RemoveRequest is the body for POST /cluster/remove.
type RemoveRequest struct {
	NodeID string `json:"node_id"`
}

// Handler returns an http.Handler that mounts all /cluster/* routes.
// It must be embedded in the API server's mux under the /cluster/ prefix.
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /cluster/status", n.handleStatus)
	mux.HandleFunc("GET /cluster/leader", n.handleLeader)
	mux.HandleFunc("POST /cluster/join", n.handleJoin)
	mux.HandleFunc("POST /cluster/remove", n.handleRemove)
	return mux
}

func (n *Node) handleStatus(w http.ResponseWriter, _ *http.Request) {
	servers, err := n.Servers()
	if err != nil {
		http.Error(w, `{"error":"failed to get cluster config"}`, http.StatusInternalServerError)
		return
	}
	infos := make([]ServerInfo, 0, len(servers))
	for _, s := range servers {
		infos = append(infos, ServerInfo{
			ID:       string(s.ID),
			Address:  string(s.Address),
			Suffrage: s.Suffrage.String(),
		})
	}
	jsonOK(w, StatusResponse{
		NodeID:   n.cfg.NodeID,
		State:    n.State(),
		Leader:   n.LeaderAddr(),
		LeaderID: n.LeaderID(),
		Servers:  infos,
		Stats:    n.Stats(),
	})
}

func (n *Node) handleLeader(w http.ResponseWriter, _ *http.Request) {
	jsonOK(w, map[string]string{
		"leader_addr": n.LeaderAddr(),
		"leader_id":   n.LeaderID(),
	})
}

func (n *Node) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.NodeID == "" || req.BindAddr == "" {
		jsonErr(w, "node_id and bind_addr are required", http.StatusBadRequest)
		return
	}
	if !n.IsLeader() {
		jsonErr(w, fmt.Sprintf("not leader; redirect to %s", n.LeaderAddr()), http.StatusTemporaryRedirect)
		return
	}
	if err := n.Join("", req.NodeID, req.BindAddr); err != nil {
		jsonErr(w, "join failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "joined", "node_id": req.NodeID})
}

func (n *Node) handleRemove(w http.ResponseWriter, r *http.Request) {
	var req RemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.NodeID == "" {
		jsonErr(w, "node_id is required", http.StatusBadRequest)
		return
	}
	if !n.IsLeader() {
		jsonErr(w, fmt.Sprintf("not leader; redirect to %s", n.LeaderAddr()), http.StatusTemporaryRedirect)
		return
	}
	if err := n.Remove(req.NodeID); err != nil {
		jsonErr(w, "remove failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "removed", "node_id": req.NodeID})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
