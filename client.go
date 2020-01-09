package allinpay

import (
	"encoding/json"
	"fmt"
	"github.com/hhjpin/goutils/logger"
	"io/ioutil"
	"net/http"
)

type Client struct {
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Get(req *Request) (*Response, error) {
	param, err := c.CreateUriParam(req)
	if err != nil {
		return nil, err
	}
	body, err := c.doGet(req.Config.RequestUrl+param, req.Config.IsDebug)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if err := c.verify(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) doGet(uri string, debug bool) ([]byte, error) {
	if debug {
		logger.Info("[allinpay request]:", uri)
	}
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if debug {
		logger.Info("[allinpay response]:", string(body))
	}
	return body, nil
}

func (c *Client) CreateUriParam(req *Request) (string, error) {
	if err := c.sign(req); err != nil {
		return "", err
	}
	reqBytes, _ := json.Marshal(req.Req)
	param := fmt.Sprintf("?sysid=%s&v=%s&timestamp=%s&req=%s&sign=%s&", req.Sysid, req.V,
		EncodeURIComponent(req.Timestamp), EncodeURIComponent(string(reqBytes)), EncodeURIComponent(req.Sign))
	return param, nil
}

func (c *Client) sign(req *Request) error {
	reqBytes, _ := json.Marshal(req.Req)
	sourceStr := req.Sysid + string(reqBytes) + req.Timestamp

	var err error
	req.Sign, err = req.Config.Sign([]byte(sourceStr))
	return err
}

func (c *Client) verify(req *Request, resp *Response) error {
	return req.Config.Verify(resp.SignedValue, resp.Sign)
}
