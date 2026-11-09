package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// regionProfile contains only verified production endpoints and official environment names.
// QODER_REGION is an adapter alias; it is not an official CLI setting.
type regionProfile struct {
	name, web, openapi, infer, configDirEnv, patEnv, root string
}

const vpcDomainSuffix = "vpc.qoder.com.cn"

// vpcEndpoints mirrors the official Qoder CN CLI mapping from one VPC instance
// name to the three service hosts. The adapter does not read the official
// vpc_endpoint setting or QODERCN_VPC_ENDPOINT; callers must pass the instance
// through -vpc-endpoint / QODER2API_VPC_ENDPOINT.
type vpcEndpoints struct {
	instance, web, openapi, infer string
}

func invalidVPCEndpoint() (vpcEndpoints, error) {
	return vpcEndpoints{}, fmt.Errorf("invalid VPC endpoint: expected an instance name or a domain under %s", vpcDomainSuffix)
}

func validVPCInstance(instance string) bool {
	if len(instance) < 1 || len(instance) > 63 || instance[0] == '-' || instance[len(instance)-1] == '-' {
		return false
	}
	for _, r := range instance {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

// parseVPCEndpoint accepts "acme", "acme.vpc.qoder.com.cn", or one of the
// per-service hosts and returns the derived CN endpoints. It intentionally
// rejects paths, ports, credentials, queries, and fragments so one value cannot
// silently redirect only part of the protocol.
func parseVPCEndpoint(value string) (vpcEndpoints, error) {
	if value == "" {
		return vpcEndpoints{}, nil
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\t") {
		return invalidVPCEndpoint()
	}
	withScheme := value
	if !strings.Contains(value, "://") {
		withScheme = "https://" + value
	}
	u, err := url.Parse(withScheme)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" ||
		u.Port() != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Path != "" && strings.Trim(u.Path, "/") != "") || strings.Contains(value, "#") {
		return invalidVPCEndpoint()
	}
	host := strings.ToLower(u.Hostname())
	instance := host
	if strings.HasSuffix(host, "."+vpcDomainSuffix) {
		instance = strings.TrimSuffix(host, "."+vpcDomainSuffix)
		instance = strings.TrimSuffix(instance, "-openapi")
		instance = strings.TrimSuffix(instance, "-gateway")
	} else if strings.Contains(host, ".") {
		return invalidVPCEndpoint()
	}
	if !validVPCInstance(instance) {
		return invalidVPCEndpoint()
	}
	return vpcEndpoints{
		instance: instance,
		web:      "https://" + instance + "." + vpcDomainSuffix,
		openapi:  "https://" + instance + "-openapi." + vpcDomainSuffix,
		infer:    "https://" + instance + "-gateway." + vpcDomainSuffix,
	}, nil
}

func resolveRegion(name string) (regionProfile, error) {
	switch name {
	case "global":
		return regionProfile{"global", defaultBase, defaultOpenapi, defaultInfer, "QODER_CONFIG_DIR", "QODER_PERSONAL_ACCESS_TOKEN", ".qoder"}, nil
	case "cn":
		return regionProfile{"cn", "https://qoder.cn", "https://openapi.qoder.com.cn", "https://gateway.qoder.com.cn", "QODERCN_CONFIG_DIR", "QODERCN_PERSONAL_ACCESS_TOKEN", ".qoder-cn"}, nil
	default:
		return regionProfile{}, fmt.Errorf("invalid region: expected global or cn")
	}
}

func normalizeBaseURL(value, label string) (string, error) {
	invalid := func() (string, error) {
		return "", fmt.Errorf("invalid %s: expected an http(s) base URL without credentials, query, or fragment", label)
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\t") {
		return invalid()
	}
	u, err := url.Parse(value)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#") {
		return invalid()
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return invalid()
		}
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	return u.String(), nil
}

func (cfg *appConfig) resolveProfile(lookupEnv func(string) (string, bool)) error {
	vpc, err := parseVPCEndpoint(cfg.vpcEndpoint)
	if err != nil {
		return err
	}
	if cfg.region == "" {
		if vpc.instance != "" {
			cfg.region = "cn"
		} else {
			cfg.region = "global"
		}
	}
	profile, err := resolveRegion(cfg.region)
	if err != nil {
		return err
	}
	if vpc.instance != "" && cfg.region != "cn" {
		return fmt.Errorf("VPC endpoint requires region cn")
	}
	if cfg.login && cfg.loginPAT != "" {
		return fmt.Errorf("-login and -login-pat are mutually exclusive")
	}
	if cfg.authDir == "" {
		root := lookupEnvOr(lookupEnv, profile.configDirEnv, filepath.Join(homeDir(), profile.root))
		if vpc.instance != "" {
			cfg.authDir = filepath.Join(root, ".vpc", vpc.instance, ".auth")
		} else {
			cfg.authDir = filepath.Join(root, ".auth")
		}
	}
	webFallback, openapiFallback, inferFallback := profile.web, profile.openapi, profile.infer
	if vpc.instance != "" {
		webFallback, openapiFallback, inferFallback = vpc.web, vpc.openapi, vpc.infer
	}
	endpoints := []struct {
		value           *string
		fallback, label string
	}{
		{&cfg.webEndpoint, webFallback, "web endpoint"}, {&cfg.openapiEndpoint, openapiFallback, "OpenAPI endpoint"}, {&cfg.inferEndpoint, inferFallback, "inference endpoint"},
	}
	for _, endpoint := range endpoints {
		if *endpoint.value == "" {
			*endpoint.value = endpoint.fallback
		}
		normalized, err := normalizeBaseURL(*endpoint.value, endpoint.label)
		if err != nil {
			return err
		}
		*endpoint.value = normalized
	}
	return nil
}
