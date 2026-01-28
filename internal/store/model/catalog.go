package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/flterrors"
	"github.com/flightctl/flightctl/internal/util"
	"github.com/google/uuid"
	"github.com/samber/lo"
)

// Catalog represents a catalog source configuration in the database.
type Catalog struct {
	Resource

	// The desired state, stored as opaque JSON object.
	Spec *JSONField[domain.CatalogSpec] `gorm:"type:jsonb"`

	// The last reported state, stored as opaque JSON object.
	Status *JSONField[domain.CatalogStatus] `gorm:"type:jsonb"`
}

func (c *Catalog) String() string {
	val, _ := json.Marshal(c)
	return string(val)
}

func NewCatalogFromApiResource(resource *domain.Catalog) (*Catalog, error) {
	if resource == nil || resource.Metadata.Name == nil {
		return &Catalog{}, nil
	}

	status := domain.CatalogStatus{Conditions: []domain.Condition{}}
	if resource.Status != nil {
		status = *resource.Status
	}
	var resourceVersion *int64
	if resource.Metadata.ResourceVersion != nil {
		i, err := strconv.ParseInt(lo.FromPtr(resource.Metadata.ResourceVersion), 10, 64)
		if err != nil {
			return nil, flterrors.ErrIllegalResourceVersionFormat
		}
		resourceVersion = &i
	}
	return &Catalog{
		Resource: Resource{
			Name:            *resource.Metadata.Name,
			Labels:          lo.FromPtrOr(resource.Metadata.Labels, make(map[string]string)),
			Annotations:     lo.FromPtrOr(resource.Metadata.Annotations, make(map[string]string)),
			Generation:      resource.Metadata.Generation,
			Owner:           resource.Metadata.Owner,
			ResourceVersion: resourceVersion,
		},
		Spec:   MakeJSONField(resource.Spec),
		Status: MakeJSONField(status),
	}, nil
}

func CatalogAPIVersion() string {
	return fmt.Sprintf("%s/%s", domain.APIGroup, domain.CatalogAPIVersion)
}

func (c *Catalog) ToApiResource(opts ...APIResourceOption) (*domain.Catalog, error) {
	if c == nil {
		return &domain.Catalog{}, nil
	}

	var spec domain.CatalogSpec
	if c.Spec != nil {
		spec = c.Spec.Data
	}

	status := domain.CatalogStatus{Conditions: []domain.Condition{}}
	if c.Status != nil {
		status = c.Status.Data
	}

	return &domain.Catalog{
		ApiVersion: CatalogAPIVersion(),
		Kind:       domain.CatalogKind,
		Metadata: domain.ObjectMeta{
			Name:              lo.ToPtr(c.Name),
			CreationTimestamp: lo.ToPtr(c.CreatedAt.UTC()),
			Labels:            lo.ToPtr(util.EnsureMap(c.Resource.Labels)),
			Annotations:       lo.ToPtr(util.EnsureMap(c.Resource.Annotations)),
			Generation:        c.Generation,
			Owner:             c.Owner,
			ResourceVersion:   lo.Ternary(c.ResourceVersion != nil, lo.ToPtr(strconv.FormatInt(lo.FromPtr(c.ResourceVersion), 10)), nil),
		},
		Spec:   spec,
		Status: &status,
	}, nil
}

func CatalogsToApiResource(catalogs []Catalog, cont *string, numRemaining *int64) (domain.CatalogList, error) {
	catalogList := make([]domain.Catalog, len(catalogs))
	for i, catalog := range catalogs {
		apiResource, _ := catalog.ToApiResource()
		catalogList[i] = *apiResource
	}
	ret := domain.CatalogList{
		ApiVersion: CatalogAPIVersion(),
		Kind:       domain.CatalogListKind,
		Items:      catalogList,
		Metadata:   domain.ListMeta{},
	}
	if cont != nil {
		ret.Metadata.Continue = cont
		ret.Metadata.RemainingItemCount = numRemaining
	}
	return ret, nil
}

func (c *Catalog) GetKind() string {
	return domain.CatalogKind
}

func (c *Catalog) HasNilSpec() bool {
	return c.Spec == nil
}

func (c *Catalog) HasSameSpecAs(otherResource any) bool {
	other, ok := otherResource.(*Catalog)
	if !ok {
		return false
	}
	if other == nil {
		return false
	}
	if c.Spec == nil && other.Spec == nil {
		return true
	}
	if (c.Spec == nil && other.Spec != nil) || (c.Spec != nil && other.Spec == nil) {
		return false
	}
	return reflect.DeepEqual(c.Spec.Data, other.Spec.Data)
}

func (c *Catalog) GetStatusAsJson() ([]byte, error) {
	if c.Status == nil {
		return []byte("null"), nil
	}
	return c.Status.MarshalJSON()
}

// CatalogItem represents a cached catalog item in the database.
// Each item represents an application with channels mapping to versions.
type CatalogItem struct {
	OrgID       uuid.UUID `gorm:"type:uuid;primaryKey"`
	CatalogName string    `gorm:"primaryKey"` // Name of the Catalog this item belongs to
	AppName     string    `gorm:"primaryKey"` // Application name
	Type        string    // Application type (container-image, helm-chart, quadlet, video, ai-model, etc.)
	Reference   string    // Base content reference (no version/tag - version comes from channels)
	Channels    *JSONField[map[string]string]             `gorm:"type:jsonb"` // Channel name -> version tag (e.g., {"stable": "v2.40.0", "fast": "v2.45.0"})
	Values      *JSONField[map[string]any]                `gorm:"type:jsonb"` // Default configuration values
	DisplayInfo *JSONField[domain.CatalogItemDisplayInfo] `gorm:"type:jsonb"` // Display metadata (name, icon, readme, etc.)
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (ci *CatalogItem) String() string {
	val, _ := json.Marshal(ci)
	return string(val)
}

func CatalogItemAPIVersion() string {
	return fmt.Sprintf("%s/%s", domain.APIGroup, domain.CatalogAPIVersion)
}

func (ci *CatalogItem) ToApiResource() *domain.CatalogItem {
	if ci == nil {
		return &domain.CatalogItem{}
	}

	var values map[string]any
	if ci.Values != nil {
		values = ci.Values.Data
	}

	var channels map[string]string
	if ci.Channels != nil {
		channels = ci.Channels.Data
	}

	var displayInfo *domain.CatalogItemDisplayInfo
	if ci.DisplayInfo != nil {
		displayInfo = &ci.DisplayInfo.Data
	}

	return &domain.CatalogItem{
		ApiVersion: CatalogItemAPIVersion(),
		Kind:       domain.CatalogItemKind,
		Metadata: domain.ObjectMeta{
			Name:              lo.ToPtr(ci.AppName),
			CreationTimestamp: lo.ToPtr(ci.CreatedAt.UTC()),
		},
		Spec: domain.CatalogItemSpec{
			Catalog:     ci.CatalogName,
			Type:        ci.Type,
			Reference:   ci.Reference,
			Channels:    channels,
			Values:      &values,
			DisplayInfo: displayInfo,
		},
	}
}

func CatalogItemsToApiResource(items []CatalogItem, cont *string, numRemaining *int64) domain.CatalogItemList {
	itemList := make([]domain.CatalogItem, len(items))
	for i, item := range items {
		itemList[i] = *item.ToApiResource()
	}
	ret := domain.CatalogItemList{
		ApiVersion: CatalogItemAPIVersion(),
		Kind:       domain.CatalogItemListKind,
		Items:      itemList,
		Metadata:   domain.ListMeta{},
	}
	if cont != nil {
		ret.Metadata.Continue = cont
		ret.Metadata.RemainingItemCount = numRemaining
	}
	return ret
}
