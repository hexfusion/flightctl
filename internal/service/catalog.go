package service

import (
	"context"
	"errors"

	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/store/selector"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func (h *ServiceHandler) CreateCatalog(ctx context.Context, orgId uuid.UUID, catalog domain.Catalog) (*domain.Catalog, domain.Status) {
	// don't set fields that are managed by the service
	catalog.Status = nil
	NilOutManagedObjectMetaProperties(&catalog.Metadata)

	if errs := catalog.Validate(); len(errs) > 0 {
		return nil, domain.StatusBadRequest(errors.Join(errs...).Error())
	}

	result, err := h.store.Catalog().Create(ctx, orgId, &catalog, h.callbackCatalogUpdated)
	return result, StoreErrorToApiStatus(err, true, domain.CatalogKind, catalog.Metadata.Name)
}

func (h *ServiceHandler) ListCatalogs(ctx context.Context, orgId uuid.UUID, params domain.ListCatalogsParams) (*domain.CatalogList, domain.Status) {
	listParams, status := prepareListParams(params.Continue, params.LabelSelector, params.FieldSelector, params.Limit)
	if status != domain.StatusOK() {
		return nil, status
	}

	result, err := h.store.Catalog().List(ctx, orgId, *listParams)
	if err == nil {
		return result, domain.StatusOK()
	}

	var se *selector.SelectorError

	switch {
	case selector.AsSelectorError(err, &se):
		return nil, domain.StatusBadRequest(se.Error())
	default:
		return nil, domain.StatusInternalServerError(err.Error())
	}
}

func (h *ServiceHandler) GetCatalog(ctx context.Context, orgId uuid.UUID, name string) (*domain.Catalog, domain.Status) {
	result, err := h.store.Catalog().Get(ctx, orgId, name)
	return result, StoreErrorToApiStatus(err, false, domain.CatalogKind, &name)
}

func (h *ServiceHandler) ReplaceCatalog(ctx context.Context, orgId uuid.UUID, name string, catalog domain.Catalog) (*domain.Catalog, domain.Status) {
	// don't overwrite fields that are managed by the service
	catalog.Status = nil
	NilOutManagedObjectMetaProperties(&catalog.Metadata)
	if errs := catalog.Validate(); len(errs) > 0 {
		return nil, domain.StatusBadRequest(errors.Join(errs...).Error())
	}
	if name != *catalog.Metadata.Name {
		return nil, domain.StatusBadRequest("resource name specified in metadata does not match name in path")
	}

	result, created, err := h.store.Catalog().CreateOrUpdate(ctx, orgId, &catalog, h.callbackCatalogUpdated)
	return result, StoreErrorToApiStatus(err, created, domain.CatalogKind, &name)
}

func (h *ServiceHandler) DeleteCatalog(ctx context.Context, orgId uuid.UUID, name string) domain.Status {
	callback := func(ctx context.Context, tx *gorm.DB, orgId uuid.UUID, owner string) error {
		// No owned resources for Catalog currently
		return nil
	}

	err := h.store.Catalog().Delete(ctx, orgId, name, callback, h.callbackCatalogDeleted)
	status := StoreErrorToApiStatus(err, false, domain.CatalogKind, &name)
	return status
}

// Only metadata.labels and spec can be patched. If we try to patch other fields, HTTP 400 Bad Request is returned.
func (h *ServiceHandler) PatchCatalog(ctx context.Context, orgId uuid.UUID, name string, patch domain.PatchRequest) (*domain.Catalog, domain.Status) {
	currentObj, err := h.store.Catalog().Get(ctx, orgId, name)
	if err != nil {
		return nil, StoreErrorToApiStatus(err, false, domain.CatalogKind, &name)
	}

	newObj := &domain.Catalog{}
	err = ApplyJSONPatch(ctx, currentObj, newObj, patch, "/catalogs/"+name)
	if err != nil {
		return nil, domain.StatusBadRequest(err.Error())
	}

	if errs := newObj.Validate(); len(errs) > 0 {
		return nil, domain.StatusBadRequest(errors.Join(errs...).Error())
	}
	if errs := currentObj.ValidateUpdate(newObj); len(errs) > 0 {
		return nil, domain.StatusBadRequest(errors.Join(errs...).Error())
	}

	NilOutManagedObjectMetaProperties(&newObj.Metadata)
	newObj.Metadata.ResourceVersion = nil
	result, err := h.store.Catalog().Update(ctx, orgId, newObj, h.callbackCatalogUpdated)
	return result, StoreErrorToApiStatus(err, false, domain.CatalogKind, &name)
}

func (h *ServiceHandler) GetCatalogStatus(ctx context.Context, orgId uuid.UUID, name string) (*domain.Catalog, domain.Status) {
	return h.GetCatalog(ctx, orgId, name)
}

func (h *ServiceHandler) ReplaceCatalogStatus(ctx context.Context, orgId uuid.UUID, name string, catalog domain.Catalog) (*domain.Catalog, domain.Status) {
	if errs := catalog.Validate(); len(errs) > 0 {
		return nil, domain.StatusBadRequest(errors.Join(errs...).Error())
	}
	if name != *catalog.Metadata.Name {
		return nil, domain.StatusBadRequest("resource name specified in metadata does not match name in path")
	}

	result, err := h.store.Catalog().UpdateStatus(ctx, orgId, &catalog, h.callbackCatalogUpdated)
	return result, StoreErrorToApiStatus(err, false, domain.CatalogKind, &name)
}

func (h *ServiceHandler) PatchCatalogStatus(ctx context.Context, orgId uuid.UUID, name string, patch domain.PatchRequest) (*domain.Catalog, domain.Status) {
	currentObj, err := h.store.Catalog().Get(ctx, orgId, name)
	if err != nil {
		return nil, StoreErrorToApiStatus(err, false, domain.CatalogKind, &name)
	}

	newObj := &domain.Catalog{}
	err = ApplyJSONPatch(ctx, currentObj, newObj, patch, "/catalogs/"+name+"/status")
	if err != nil {
		return nil, domain.StatusBadRequest(err.Error())
	}

	if errs := newObj.Validate(); len(errs) > 0 {
		return nil, domain.StatusBadRequest(errors.Join(errs...).Error())
	}

	result, err := h.store.Catalog().UpdateStatus(ctx, orgId, newObj, h.callbackCatalogUpdated)
	return result, StoreErrorToApiStatus(err, false, domain.CatalogKind, &name)
}

func (h *ServiceHandler) ListCatalogItems(ctx context.Context, orgId uuid.UUID, catalogName string, params domain.ListCatalogItemsParams) (*domain.CatalogItemList, domain.Status) {
	listParams, status := prepareListParams(params.Continue, params.LabelSelector, nil, params.Limit)
	if status != domain.StatusOK() {
		return nil, status
	}

	result, err := h.store.Catalog().ListItems(ctx, orgId, catalogName, *listParams)
	if err == nil {
		return result, domain.StatusOK()
	}

	var se *selector.SelectorError

	switch {
	case selector.AsSelectorError(err, &se):
		return nil, domain.StatusBadRequest(se.Error())
	default:
		return nil, StoreErrorToApiStatus(err, false, domain.CatalogKind, &catalogName)
	}
}

// callbackCatalogUpdated is the catalog-specific callback that handles catalog events
func (h *ServiceHandler) callbackCatalogUpdated(ctx context.Context, resourceKind domain.ResourceKind, orgId uuid.UUID, name string, oldResource, newResource interface{}, created bool, err error) {
	h.eventHandler.HandleCatalogUpdatedEvents(ctx, resourceKind, orgId, name, oldResource, newResource, created, err)
}

// callbackCatalogDeleted is the catalog-specific callback that handles catalog deletion events
func (h *ServiceHandler) callbackCatalogDeleted(ctx context.Context, resourceKind domain.ResourceKind, orgId uuid.UUID, name string, oldResource, newResource interface{}, created bool, err error) {
	h.eventHandler.HandleGenericResourceDeletedEvents(ctx, resourceKind, orgId, name, oldResource, newResource, created, err)
}

// GetCatalogManifest retrieves an OCI manifest for a catalog item (OCI Distribution API).
// Returns the manifest JSON bytes, the content type (media type), and status.
func (h *ServiceHandler) GetCatalogManifest(ctx context.Context, orgId uuid.UUID, catalogName, appName, reference string) ([]byte, string, domain.Status) {
	// Get the catalog to verify it exists and check its type
	catalog, err := h.store.Catalog().Get(ctx, orgId, catalogName)
	if err != nil {
		return nil, "", StoreErrorToApiStatus(err, false, domain.CatalogKind, &catalogName)
	}

	// Get the manifest from the catalog item store
	manifest, mediaType, err := h.store.Catalog().GetManifest(ctx, orgId, catalogName, appName, reference)
	if err != nil {
		return nil, "", StoreErrorToApiStatus(err, false, domain.CatalogItemKind, &appName)
	}

	// For remote catalogs, we may need to fetch from the upstream registry
	// This is a placeholder for future implementation
	_ = catalog

	return manifest, mediaType, domain.StatusOK()
}
