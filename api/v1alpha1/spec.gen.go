// Package v1alpha1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.15.0 DO NOT EDIT.
package v1alpha1

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
	"RVdfrv4/AAD//1sv0J60AwEA",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
