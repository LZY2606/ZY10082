package forensic

import "net/http"

// GraphNode is any vertex in the custody visualization.
type GraphNode struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // session, artifact, custody, package, clock
	Label  string `json:"label"`
	Status string `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// GraphEdge is one directed link.
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// Graph is the directed provenance graph.
type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// BuildGraph constructs the directed graph of sources and handoffs.
func (s *Service) BuildGraph() Graph {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var g Graph
	add := func(n GraphNode) { g.Nodes = append(g.Nodes, n) }
	link := func(from, to, kind string) { g.Edges = append(g.Edges, GraphEdge{From: from, To: to, Kind: kind}) }
	for _, sess := range sortedSessions(s.sess) {
		add(GraphNode{ID: "session:" + sess.ID, Kind: "session", Label: sess.Filename, Status: sess.Status,
			Detail: sess.Source.Origin})
	}
	for _, a := range sortedArtifacts(s.art) {
		st := "accepted"
		add(GraphNode{ID: "artifact:" + a.ID, Kind: "artifact", Label: a.Filename, Status: st,
			Detail: shortHash(a.Hashes.SHA256)})
		if a.SessionID != "" {
			link("session:"+a.SessionID, "artifact:"+a.ID, "produced")
		}
		if a.DerivedFrom != nil {
			link("artifact:"+a.DerivedFrom.ParentID, "artifact:"+a.ID, "derived")
		}
		if a.PackageID != "" {
			pid := "package:" + a.PackageID
			link(pid, "artifact:"+a.ID, "imported")
		}
	}
	for _, c := range s.cust {
		nid := "custody:" + c.ID
		add(GraphNode{ID: nid, Kind: "custody", Label: c.From + " → " + c.To,
			Detail: c.Reason, Status: "accepted"})
		link("artifact:"+c.ArtifactID, nid, "handoff")
	}
	for _, p := range s.pkgs {
		pid := "package:" + p.PackageID
		add(GraphNode{ID: pid, Kind: "package", Label: p.Direction + " " + shortHash(p.ContentHash),
			Detail: p.PackageID})
		if p.Direction == "export" {
			for _, id := range p.ArtifactIDs {
				link("artifact:"+id, pid, "exported")
			}
		}
	}
	for _, c := range s.clocks {
		add(GraphNode{ID: "clock:" + c.ID, Kind: "clock", Label: "clock " + c.NewOffset,
			Detail: c.Reason})
	}
	return g
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.svc.BuildGraph())
}
