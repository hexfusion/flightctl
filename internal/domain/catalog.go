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

// ========== Enum Types ==========

type CatalogItemDisplayInfoVisibility = v1beta1.CatalogItemDisplayInfoVisibility

// ========== Constants ==========

const (
	// Visibility values
	CatalogVisibilityDraft      = v1beta1.Draft
	CatalogVisibilityPublished  = v1beta1.Published
	CatalogVisibilityDeprecated = v1beta1.Deprecated
)

// ========== List Params ==========

type ListCatalogsParams = v1beta1.ListCatalogsParams
type ListCatalogItemsParams = v1beta1.ListCatalogItemsParams
