package allinpay

import "time"

type Request struct {
	Config *Config
	Sign   string

	Sysid     string
	Timestamp string
	V         string
	Req       struct {
		Service string                 `json:"service"`
		Method  string                 `json:"method"`
		Param   map[string]interface{} `json:"param"`
	}
}

func NewRequest(config *Config) *Request {
	return &Request{
		Config:    config,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Sysid:     config.Sysid,
		V:         "2.0",
	}
}

func (r *Request) SetReq(service, method string, param map[string]interface{}) {
	r.Req.Service = service
	r.Req.Method = method
	r.Req.Param = param
}
