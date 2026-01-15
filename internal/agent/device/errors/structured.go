package errors

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/flightctl/flightctl/internal/consts"
	"google.golang.org/grpc/codes"
)

// FormatError converts a raw error into a StructuredError.
func FormatError(err error) *StructuredError {
	phase, component := extractPhaseAndComponent(err)
	statusCode := ToCode(err)
	category := inferCategory(statusCode)
	element := extractElement(err.Error())

	return &StructuredError{
		Timestamp:  time.Now(),
		Phase:      phase,
		Component:  component,
		StatusCode: statusCode,
		Category:   category,
		Element:    element,
	}
}

// StructuredError represents a sanitized, structured error for status display.
type StructuredError struct {
	Phase      string
	Category   Category
	Component  string
	Element    string
	StatusCode codes.Code
	Timestamp  time.Time
}

// Message returns the formatted error message string.
func (se *StructuredError) Message() string {
	return se.buildMessage()
}

var (
	ErrComponentUnknown = errors.New("unknown")
	ErrPhaseUnknown     = errors.New("Unknown")
)

// Category represents the high-level functional area describing WHAT failed.
type Category string

const (
	CategoryNetwork       Category = "Network"
	CategoryConfiguration Category = "Configuration"
	CategoryFilesystem    Category = "Filesystem"
	CategorySecurity      Category = "Security"
	CategoryStorage       Category = "Storage"
	CategoryResource      Category = "Resource"
	CategorySystem        Category = "System"
	CategoryUnknown       Category = "Unknown"
)

var phaseSentinels = []error{
	ErrPhasePreparing,
	ErrPhaseApplyingUpdate,
	ErrPhaseActivatingConfig,
}

// phaseToUpdateState maps phase sentinel errors to their corresponding UpdateState values.
var phaseToUpdateState = map[error]consts.UpdateState{
	ErrPhasePreparing:        consts.UpdateStatePreparing,
	ErrPhaseApplyingUpdate:   consts.UpdateStateApplyingUpdate,
	ErrPhaseActivatingConfig: consts.UpdateStateRebooting,
}

var componentSentinels = []error{
	ErrComponentResources,
	ErrComponentUpdatePolicy,
	ErrComponentApplications,
	ErrComponentConfig,
	ErrComponentSystemd,
	ErrComponentLifecycle,
	ErrComponentOS,
}

// These don't follow the standard DeviceSpec API keys.
var subComponentSentinels = map[error]error{
	ErrComponentDownloadPolicy: ErrComponentUpdatePolicy,
	ErrComponentPrefetch:       ErrComponentApplications,
	ErrComponentHooks:          ErrComponentLifecycle,
	ErrComponentOSReconciled:   ErrComponentOS,
}

var statusCategoryOverrides = map[codes.Code]Category{
	codes.Unavailable:        CategoryNetwork,
	codes.DeadlineExceeded:   CategoryNetwork,
	codes.Unauthenticated:    CategorySecurity,
	codes.PermissionDenied:   CategorySecurity,
	codes.DataLoss:           CategoryStorage,
	codes.NotFound:           CategoryFilesystem,
	codes.AlreadyExists:      CategoryFilesystem,
	codes.Internal:           CategorySystem,
	codes.ResourceExhausted:  CategoryResource,
	codes.InvalidArgument:    CategoryConfiguration,
	codes.OutOfRange:         CategoryConfiguration,
	codes.FailedPrecondition: CategoryConfiguration,
	codes.Unimplemented:      CategorySystem,
	codes.Canceled:           CategorySystem,
	codes.Aborted:            CategorySystem,
	codes.Unknown:            CategorySystem,
}

// extractPhaseAndComponent identifies the phase and component from an error.
func extractPhaseAndComponent(err error) (phase, component string) {
	// if the sync process was changed without updating the formatting we default to unknown
	phase = ErrPhaseUnknown.Error()
	component = ErrComponentUnknown.Error()

	for _, p := range phaseSentinels {
		if errors.Is(err, p) {
			state := phaseToUpdateState[p]
			phase = string(state)
			break
		}
	}

	for _, comp := range componentSentinels {
		if errors.Is(err, comp) {
			component = comp.Error()
			return
		}
	}

	for subComponent, comp := range subComponentSentinels {
		if errors.Is(err, subComponent) {
			component = comp.Error()
			return
		}
	}

	return phase, component
}

// inferCategory infers the category from the status code.
func inferCategory(statusCode codes.Code) Category {
	if cat, ok := statusCategoryOverrides[statusCode]; ok {
		return cat
	}
	return CategoryUnknown
}

// elementPattern defines a prefix/suffix pair for extracting element names from error messages.
// If suffix is empty, the element is extracted from the prefix to the end of the string.
type elementPattern struct {
	prefix string
	suffix string
}

var elementPatterns = []elementPattern{
	// Volume patterns
	{"inspect volume \"", "\""},
	{"removing volume content \"", "\""},
	{"creating volume \"", "\""},
	{"extracting artifact to volume \"", "\""},

	// Service/quadlet patterns
	{"service: \"", "\""},
	{"service \"", "\""},
	{"getting service name for ", ":"},
	{"namespacing ", ":"},
	{"creating drop-in for ", ":"},
	{"reading drop-in directory ", ":"},

	// App patterns (specific first)
	{"copying image contents for app ", " ("},
	{"parsing compose spec for app ", " ("},
	{"validating compose spec for app ", " ("},
	{"parsing quadlet spec for app ", " ("},
	{"validating quadlet spec for app ", " ("},
	{"detecting OCI type for app ", " ("},
	{"extracting artifact contents for app ", " ("},
	{"creating tmp dir for app ", " ("},
	{"verify embedded app ", ":"},
	{"getting provider type for app ", ":"},
	{"getting image spec for app ", ":"},
	{"extracting nested targets for app ", ":"},
	{"for app ", " ("},
	{"for app ", ":"},
	{"embedded app ", ":"},

	// Target patterns
	{"starting target ", ":"},
	{"stopping target ", ":"},
	{"pulling oci target ", ": "},
	{"failed to enqueue target ", ": "},

	// OCI/Image patterns
	{"getting image digest for ", ":"},
	{"getting artifact digest for ", ":"},
	{"OCI reference ", " not found"},
	{"extracting OCI: ", " contents"},

	// File/directory patterns
	{"failed to create directory \"", "\""},
	{"creating directory ", ":"},
	{"creating file ", ":"},
	{"writing file ", ":"},
	{"could not remove file ", ":"},
	{"could not overwrite file ", " with"},
	{"failed to resolve symlink ", ":"},
	{"failed to stat symlink target ", ":"},
	{"invalid file path in tar: ", ","},
	{"remove file \"", "\""},
	{"write file ", ":"},
	{"reading \"", "\""},
	{"writing to \"", "\""},
	{"for file \"", "\""},
	{"copying ", ":"},
	{"reading tmp directory ", ":"},
	{"failed to check if directory ", " exists"},

	// User/group patterns
	{"failed to retrieve UserID for username: ", ""},
	{"failed to retrieve GroupID for group: ", ""},

	// Hook patterns
	{"reading hook actions from \"", "\""},
	{"parsing hook actions from \"", "\""},
	{"unknown hook action type \"", "\""},
	{"unknown hook condition type \"", "\""},
	{"workdir ", ":"},

	// Misc patterns
	{"unknown monitor type: ", ""},
	{"invalid regex: ", ","},
	{"unsupported content encoding: \"", "\""},
	{"unsupported action type: ", ""},
	{"invalid oci type ", ""},

	// Generic quoted fallback (must be last)
	{"\"", "\""},
}

// extractElement extracts a resource/element name from an error message string.
func extractElement(errStr string) string {
	if errStr == "" {
		return ""
	}

	for _, p := range elementPatterns {
		_, after, found := strings.Cut(errStr, p.prefix)
		if !found {
			continue
		}

		var element string
		if p.suffix == "" {
			element = after
		} else {
			captured, _, foundSuffix := strings.Cut(after, p.suffix)
			if !foundSuffix {
				continue
			}
			element = captured
		}
		if valid := cleanAndValidateElement(element); valid != "" {
			return valid
		}
	}

	return ""
}

// cleanAndValidateElement trims whitespace and, for long elements, keeps the last 64 runes with "..." prefix (UTF-8 safe).
func cleanAndValidateElement(element string) string {
	element = strings.TrimSpace(element)
	if element == "" {
		return ""
	}

	lenElement := utf8.RuneCountInString(element)
	indexElement := lenElement - 64
	if lenElement > 64 {
		runes := []rune(element)
		element = "..." + string(runes[indexElement:])
	}

	return element
}

func (se *StructuredError) buildMessage() string {
	element := ""
	if se.Element != "" {
		element = fmt.Sprintf(" for %q", se.Element)
	}

	return fmt.Sprintf("[%s] While %s, %s failed%s: %s issue - %s",
		se.Timestamp,
		se.Phase,
		se.Component,
		element,
		se.Category,
		statusCodeMessage(se.StatusCode),
	)
}

func statusCodeMessage(code codes.Code) string {
	switch code {
	case codes.Canceled:
		return "Operation was cancelled"
	case codes.InvalidArgument:
		return "Invalid configuration or input"
	case codes.NotFound:
		return "Required resource not found"
	case codes.AlreadyExists:
		return "Resource already exists"
	case codes.PermissionDenied:
		return "Permission denied"
	case codes.ResourceExhausted:
		return "Insufficient resources (disk space, memory)"
	case codes.FailedPrecondition:
		return "Precondition not met (waiting for dependencies)"
	case codes.Aborted:
		return "Operation was aborted"
	case codes.OutOfRange:
		return "Value out of acceptable range"
	case codes.Unimplemented:
		return "Feature not supported"
	case codes.Unavailable:
		return "Service unavailable (network issue)"
	case codes.DeadlineExceeded:
		return "Request timed out"
	case codes.Internal:
		return "Internal error occurred"
	case codes.DataLoss:
		return "Unrecoverable data loss detected"
	case codes.Unauthenticated:
		return "Authentication failed"
	default:
		// Unknown status code
		return "An error occurred"
	}
}
