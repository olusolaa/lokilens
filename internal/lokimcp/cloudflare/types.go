package cloudflare

import "encoding/json"

type Response struct {
	Data   json.RawMessage `json:"data"`
	Errors []GraphQLError  `json:"errors"`
}

type GraphQLError struct {
	Message string `json:"message"`
}

type zonesData struct {
	Viewer struct {
		Zones []map[string]json.RawMessage `json:"zones"`
	} `json:"viewer"`
}
