package allinpay

type Pay struct {
	config *Config
	client *Client
}

func New(c *Config) (*Pay, error) {
	if err := c.init(); err != nil {
		return nil, err
	}
	return &Pay{
		config: c,
		client: NewClient(),
	}, nil
}

func (p *Pay) Request(service, method string, param map[string]interface{}) (*Response, error) {
	req := NewRequest(p.config)
	req.SetReq(service, method, param)
	return p.client.Get(req)
}

func (p *Pay) RequestAndCheckStatus(service, method string, param map[string]interface{}) (resp *Response, err error) {
	if resp, err = p.Request(service, method, param); err != nil {
		return resp, err
	}
	return resp, resp.CheckStatus()
}

func (p *Pay) GetConfig() *Config {
	return p.config
}
