package domain

import v1beta1 "github.com/flightctl/flightctl/api/core/v1beta1"

// ========== Resource Types ==========

type Catalog = v1beta1.Catalog
type CatalogList = v1beta1.CatalogList
type CatalogSpec = v1beta1.CatalogSpec
type CatalogStatus = v1beta1.CatalogStatus

// ========== Catalog Item Types ==========

type CatalogItem = v1beta1.CatalogItem
type CatalogItemList = v1beta1.CatalogItemList
type CatalogItemSpec = v1beta1.CatalogItemSpec
type CatalogItemDisplayInfo = v1beta1.CatalogItemDisplayInfo

// ========== Configuration Types ==========

type CatalogCacheConfig = v1beta1.CatalogCacheConfig
type CatalogAnnotationConfig = v1beta1.CatalogAnnotationConfig
type CatalogAnnotationOverride = v1beta1.CatalogAnnotationOverride

// ========== Enum Types ==========

type CatalogSpecType = v1beta1.CatalogSpecType
type CatalogItemDisplayInfoVisibility = v1beta1.CatalogItemDisplayInfoVisibility
type CatalogAnnotationOverrideVisibility = v1beta1.CatalogAnnotationOverrideVisibility

// ========== Constants ==========

const (
	// Catalog types
	CatalogSpecTypeLocal  = v1beta1.Local
	CatalogSpecTypeRemote = v1beta1.Remote

	// Visibility values
	CatalogVisibilityDraft      = v1beta1.CatalogItemDisplayInfoVisibilityDraft
	CatalogVisibilityPublished  = v1beta1.CatalogItemDisplayInfoVisibilityPublished
	CatalogVisibilityDeprecated = v1beta1.CatalogItemDisplayInfoVisibilityDeprecated
)

// ========== List Params ==========

type ListCatalogsParams = v1beta1.ListCatalogsParams
type ListCatalogItemsParams = v1beta1.ListCatalogItemsParams
