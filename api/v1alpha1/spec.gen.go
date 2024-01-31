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
