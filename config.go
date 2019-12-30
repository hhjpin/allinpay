package allinpay

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/hhjpin/goutils/logger"
	"io/ioutil"
	"os"
)

type Config struct {
	RequestUrl  string //请求地址
	PrivateFile string //私钥文件
	PublicFile  string //公钥文件
	Sysid       string //系统id

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey

	IsDebug bool
}

func (c *Config) init() error {
	if err := c.initPrivateKey(); err != nil {
		return err
	}
	if err := c.initPublicKey(); err != nil {
		return err
	}
	return nil
}

func (c *Config) initPrivateKey() error {
	if c.PrivateFile == "" {
		return fmt.Errorf("私钥文件必须指定")
	}
	priFile, err := os.Open(c.PrivateFile)
	if err != nil {
		logger.Error(err)
		return err
	}
	defer func() {
		_ = priFile.Close()
	}()
	privateData, err := ioutil.ReadAll(priFile)
	if err != nil {
		logger.Error(err)
		return err
	}

	block, _ := pem.Decode(privateData)
	if block == nil {
		logger.Error("sign pem.Decode error")
		return fmt.Errorf("sign pem.Decode error")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logger.Error(err)
		return err
	}
	key, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		err = fmt.Errorf("key is not a valid RSA public key")
		logger.Error(err)
		return err
	}

	c.privateKey = key
	return nil
}

func (c *Config) initPublicKey() error {
	if c.PublicFile == "" {
		return fmt.Errorf("公钥文件必须指定")
	}

	pubFile, err := os.Open(c.PublicFile)
	if err != nil {
		logger.Error(err)
		return err
	}
	defer func() {
		_ = pubFile.Close()
	}()
	publicData, err := ioutil.ReadAll(pubFile)
	if err != nil {
		logger.Error(err)
		return err
	}

	block, _ := pem.Decode(publicData)
	if block == nil {
		logger.Error("verify pem.Decode error")
		return fmt.Errorf("verify pem.Decode error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Error(err)
		return err
	}
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err = fmt.Errorf("key is not a valid RSA public key")
		logger.Error(err)
		return err
	}

	c.publicKey = key
	return nil
}

func (c *Config) GetPrivateKey() *rsa.PrivateKey {
	return c.privateKey
}

func (c *Config) GetPublicKey() *rsa.PublicKey {
	return c.publicKey
}

func (c *Config) Encrypt(data []byte) ([]byte, error) {
	text, err := rsa.EncryptPKCS1v15(rand.Reader, c.GetPublicKey(), data)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	dst := make([]byte, hex.EncodedLen(len(text)))
	hex.Encode(dst, text)
	return bytes.ToUpper(dst), nil
}

func (c *Config) Decrypt(text []byte) ([]byte, error) {
	n, err := hex.Decode(text, text)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	data, err := rsa.DecryptPKCS1v15(rand.Reader, c.GetPrivateKey(), text[:n])
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	return data, nil
}

func (c *Config) Sign(data []byte) (string, error) {
	m := md5.New()
	m.Write(data)
	md5Base64 := base64.StdEncoding.EncodeToString(m.Sum(nil))

	h := sha1.New()
	h.Write([]byte(md5Base64))
	digest := h.Sum(nil)

	sign, err := rsa.SignPKCS1v15(nil, c.GetPrivateKey(), crypto.SHA1, digest)
	if err != nil {
		logger.Error(err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

func (c *Config) Verify(data, sign string) error {
	m := md5.New()
	m.Write([]byte(data))
	md5Base64 := base64.StdEncoding.EncodeToString(m.Sum(nil))

	sig, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		logger.Error(err)
		return err
	}

	hash := sha1.New()
	hash.Write([]byte(md5Base64))
	err = rsa.VerifyPKCS1v15(c.GetPublicKey(), crypto.SHA1, hash.Sum(nil), sig)
	if err != nil {
		logger.Error(err)
		return err
	}
	return nil
}
