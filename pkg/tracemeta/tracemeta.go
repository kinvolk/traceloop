package tracemeta

type TraceMeta struct {
	Status       string `json:"status,omitempty"`
	TraceID      string `json:"traceid,omitempty"`
	PodUID       string `json:"uid,omitempty"`
	ContainerID  string `json:"containerid,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
	Podname      string `json:"podname,omitempty"`
	Containeridx int    `json:"containeridx,omitempty"`
	TimeCreation string `json:"timecreation,omitempty"`
	TimeDeletion string `json:"timedeletion,omitempty"`
	Capabilities uint64 `json:"capabilities,omitempty"`
	Node         string `json:"node,omitempty"`
}
