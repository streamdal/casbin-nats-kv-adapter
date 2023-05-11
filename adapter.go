package natskvadapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/batchcorp/casbin/v2/persist"

	"github.com/nats-io/nats.go"
	"github.com/pkg/errors"

	"github.com/batchcorp/casbin/v2/model"
)

const (
	RequestTimeout = 5 * time.Second

	DefaultBucket = "casbin-policy"

	// Placeholder represent the NULL value in the Casbin Rule.
	Placeholder = "_"
)

type CasbinRule struct {
	Key   string `json:"key"`
	PType string `json:"ptype"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

type Adapter struct {
	natsHosts  []string
	bucketName string
	authConfig *AuthConfig
	conn       *nats.Conn
	jsCtx      nats.JetStreamContext
}

type AuthConfig struct {
	UseTLS bool

	// Contents of the certs/keys (ie. not files); not used if UseTLS is false
	CACert     string
	ClientKey  string
	ClientCert string
}

func NewAdapter(natsHosts []string, bucketName string, authConfig *AuthConfig) (*Adapter, error) {
	if bucketName == "" {
		bucketName = DefaultBucket
	}
	a := &Adapter{
		natsHosts:  natsHosts,
		bucketName: bucketName,
		authConfig: authConfig,
	}

	if err := a.connect(); err != nil {
		return nil, err
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

func (a *Adapter) loadPolicy(rule CasbinRule, model model.Model) {
	lineText := rule.PType
	if rule.V0 != "" {
		lineText += ", " + rule.V0
	}
	if rule.V1 != "" {
		lineText += ", " + rule.V1
	}
	if rule.V2 != "" {
		lineText += ", " + rule.V2
	}
	if rule.V3 != "" {
		lineText += ", " + rule.V3
	}
	if rule.V4 != "" {
		lineText += ", " + rule.V4
	}
	if rule.V5 != "" {
		lineText += ", " + rule.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

// LoadPolicy loads all of policys from ETCD
func (a *Adapter) LoadPolicy(model model.Model) error {
	var rule CasbinRule
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	bucket, err := a.getBucket(ctx, a.bucketName, true, 0)
	if err != nil {
		return errors.Wrapf(err, "unable to get bucket '%s'", a.bucketName)
	}

	keys, err := bucket.Keys()
	if err != nil {
		return errors.Wrap(err, "unable to fetch keys from bucket")
	}

	for _, key := range keys {
		kv, err := bucket.Get(key)
		if err != nil {
			return err
		}

		if err = json.Unmarshal(kv.Value(), &rule); err != nil {
			return err
		}

		a.loadPolicy(rule, model)
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
// Part of the Auto-Save feature.
func (a *Adapter) AddPolicy(sec string, ptype string, line []string) error {
	rule := a.convertRule(ptype, line)
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	bucket, err := a.getBucket(ctx, a.bucketName, true, 0)
	if err != nil {
		return errors.Wrapf(err, "unable to get bucket '%s'", a.bucketName)
	}

	ruleData, err := json.Marshal(rule)
	if err != nil {
		return errors.Wrap(err, "unable to marshal policy to JSON")
	}

	if _, err := bucket.Put(rule.Key, ruleData); err != nil {
		return errors.Wrapf(err, "unable to put policy into bucket key '%s'", rule.Key)
	}

	return nil
}

// RemovePolicy removes a policy rule from the storage.
// Part of the Auto-Save feature.
func (a *Adapter) RemovePolicy(sec string, ptype string, line []string) error {
	rule := a.convertRule(ptype, line)
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	bucket, err := a.getBucket(ctx, a.bucketName, true, 0)
	if err != nil {
		return errors.Wrapf(err, "unable to get bucket '%s'", a.bucketName)
	}

	if err := bucket.Delete(rule.Key); err != nil {
		return errors.Wrapf(err, "unable to delete policy '%s' from bucket", rule.Key)
	}

	return nil
}

// SavePolicy will rewrite all of policies in ETCD with the current data in Casbin
func (a *Adapter) SavePolicy(model model.Model) error {
	// clean old rule data
	a.destroy()

	var rules []CasbinRule

	for ptype, ast := range model["p"] {
		for _, line := range ast.Policy {
			rules = append(rules, a.convertRule(ptype, line))
		}
	}

	for ptype, ast := range model["g"] {
		for _, line := range ast.Policy {
			rules = append(rules, a.convertRule(ptype, line))
		}
	}

	return a.savePolicy(rules)
}

func (a *Adapter) convertRule(ptype string, line []string) (rule CasbinRule) {
	rule = CasbinRule{}
	rule.PType = ptype
	policys := []string{ptype}
	length := len(line)

	if len(line) > 0 {
		rule.V0 = line[0]
		policys = append(policys, line[0])
	}
	if len(line) > 1 {
		rule.V1 = line[1]
		policys = append(policys, line[1])
	}
	if len(line) > 2 {
		rule.V2 = line[2]
		policys = append(policys, line[2])
	}
	if len(line) > 3 {
		rule.V3 = line[3]
		policys = append(policys, line[3])
	}
	if len(line) > 4 {
		rule.V4 = line[4]
		policys = append(policys, line[4])
	}
	if len(line) > 5 {
		rule.V5 = line[5]
		policys = append(policys, line[5])
	}

	for i := 0; i < 6-length; i++ {
		policys = append(policys, Placeholder)
	}

	rule.Key = strings.Join(policys, "--")

	return rule
}

func (a *Adapter) savePolicy(rules []CasbinRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	bucket, err := a.getBucket(ctx, a.bucketName, true, 0)
	if err != nil {
		return errors.Wrapf(err, "unable to get bucket '%s'", bucket)
	}

	for _, rule := range rules {
		ruleData, err := json.Marshal(rule)
		if err != nil {
			return errors.Wrap(err, "unable to marshal rule")
		}

		if _, err := bucket.Put(rule.Key, ruleData); err != nil {
			return errors.Wrapf(err, "unable to put rule '%s' in bucket '%s'", rule.Key, a.bucketName)
		}
	}
	return nil
}

// destroy or clean all of policy
func (a *Adapter) destroy() error {
	return a.jsCtx.DeleteObjectStore(a.bucketName)
}

func (a *Adapter) getBucket(_ context.Context, bucket string, create bool, ttl time.Duration) (nats.KeyValue, error) {
	kv, err := a.jsCtx.KeyValue(bucket)
	if err != nil {
		if err != nats.ErrBucketNotFound {
			return nil, errors.Wrap(err, "key value fetch error in getBucket()")
		} else if create {
			kv, err = a.jsCtx.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucket,
				Description: "auto-created bucket via casbin-nats-kv-adapter",
				History:     5,
				TTL:         ttl,
			})

			if err != nil {
				return nil, errors.Wrap(err, "bucket create error in getBucket()")
			}

			return kv, nil
		}
	}

	return kv, nil
}

func (a *Adapter) connect() error {
	var connected bool
	var nc *nats.Conn
	var err error

	for _, address := range a.natsHosts {
		var options []nats.Option // TODO: TLS config

		if a.authConfig.UseTLS {
			tlsConfig, err := CreateTLSConfig(a.authConfig.CACert, a.authConfig.ClientCert, a.authConfig.ClientKey)
			if err != nil {
				return errors.Wrap(err, "failed to create TLS config")
			}

			nc, err = nats.Connect(address, nats.Secure(tlsConfig))
		} else {
			nc, err = nats.Connect(address)
		}

		nc, err = nats.Connect(address, options...)
		if err != nil {
			fmt.Printf("unable to connect to '%s': %s\n", address, err)

			continue
		}

		connected = true
		break
	}

	if !connected {
		return err
	}

	a.conn = nc

	js, err := nc.JetStream()
	if err != nil {
		return errors.Wrap(err, "failed to create jetstream context")
	}

	a.jsCtx = js

	// Create bucket if it doesn't exist
	if _, err := a.getBucket(context.Background(), a.bucketName, true, 0); err != nil {
		return errors.Wrap(err, "failed to create bucket")
	}

	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// Part of the Auto-Save feature.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	rule := CasbinRule{}

	rule.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		rule.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		rule.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		rule.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		rule.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		rule.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		rule.V5 = fieldValues[5-fieldIndex]
	}

	filter := a.constructFilter(rule)

	return a.removeFilteredPolicy(filter)
}

func (a *Adapter) constructFilter(rule CasbinRule) string {
	var filter string

	// TODO: is this the correct way to handle this?
	if rule.PType != "" {
		filter = rule.PType
	}

	if rule.V0 != "" {
		filter = fmt.Sprintf("%s--%s", filter, rule.V0)
	} else {
		filter = fmt.Sprintf("%s--.*", filter)
	}

	if rule.V1 != "" {
		filter = fmt.Sprintf("%s--%s", filter, rule.V1)
	} else {
		filter = fmt.Sprintf("%s--.*", filter)
	}

	if rule.V2 != "" {
		filter = fmt.Sprintf("%s--%s", filter, rule.V2)
	} else {
		filter = fmt.Sprintf("%s--.*", filter)
	}

	if rule.V3 != "" {
		filter = fmt.Sprintf("%s--%s", filter, rule.V3)
	} else {
		filter = fmt.Sprintf("%s--.*", filter)
	}

	if rule.V4 != "" {
		filter = fmt.Sprintf("%s--%s", filter, rule.V4)
	} else {
		filter = fmt.Sprintf("%s--.*", filter)
	}

	if rule.V5 != "" {
		filter = fmt.Sprintf("%s--%s", filter, rule.V5)
	} else {
		filter = fmt.Sprintf("%s--.*", filter)
	}

	return filter
}

func (a *Adapter) removeFilteredPolicy(filter string) error {
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()

	bucket, err := a.getBucket(ctx, a.bucketName, true, 0)
	if err != nil {
		return errors.Wrapf(err, "failed to get bucket '%s'", a.bucketName)
	}

	keys, err := bucket.Keys()
	if err != nil {
		return errors.Wrapf(err, "failed to get keys for bucket '%s'", a.bucketName)
	}

	var filteredKeys []string
	for _, key := range keys {
		matched, err := regexp.MatchString(filter, key)
		if err != nil {
			return err
		}
		if matched {
			filteredKeys = append(filteredKeys, key)
		}
	}

	for _, key := range filteredKeys {
		if err := bucket.Delete(key); err != nil {
			return errors.Wrapf(err, "failed to delete key '%s' from bucket '%s'", key, a.bucketName)
		}
	}
	return nil
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {
	a.conn.Close()
}

func (a *Adapter) close() {
	a.conn.Close()
}

func CreateTLSConfig(caCert, clientCert, clientKey string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
	if err != nil {
		return nil, errors.Wrap(err, "unable to load cert + key")
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(caCert))

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}, nil
}
