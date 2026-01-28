package store

import (
	"context"
	"errors"

	"github.com/flightctl/flightctl/internal/domain"
	"github.com/flightctl/flightctl/internal/flterrors"
	"github.com/flightctl/flightctl/internal/store/model"
	"github.com/flightctl/flightctl/internal/util"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type Catalog interface {
	InitialMigration(ctx context.Context) error

	Create(ctx context.Context, orgId uuid.UUID, catalog *domain.Catalog, callbackEvent EventCallback) (*domain.Catalog, error)
	Update(ctx context.Context, orgId uuid.UUID, catalog *domain.Catalog, callbackEvent EventCallback) (*domain.Catalog, error)
	CreateOrUpdate(ctx context.Context, orgId uuid.UUID, catalog *domain.Catalog, callbackEvent EventCallback) (*domain.Catalog, bool, error)
	Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.Catalog, error)
	List(ctx context.Context, orgId uuid.UUID, listParams ListParams) (*domain.CatalogList, error)
	Delete(ctx context.Context, orgId uuid.UUID, name string, callback RemoveOwnerCallback, callbackEvent EventCallback) error
	UpdateStatus(ctx context.Context, orgId uuid.UUID, resource *domain.Catalog, eventCallback EventCallback) (*domain.Catalog, error)
	Count(ctx context.Context, orgId uuid.UUID, listParams ListParams) (int64, error)

	// CatalogItem operations
	ListItems(ctx context.Context, orgId uuid.UUID, catalogName string, listParams ListParams) (*domain.CatalogItemList, error)
}

type CatalogStore struct {
	dbHandler           *gorm.DB
	log                 logrus.FieldLogger
	genericStore        *GenericStore[*model.Catalog, model.Catalog, domain.Catalog, domain.CatalogList]
	eventCallbackCaller EventCallbackCaller
}

// Make sure we conform to Catalog interface
var _ Catalog = (*CatalogStore)(nil)

func NewCatalog(db *gorm.DB, log logrus.FieldLogger) Catalog {
	genericStore := NewGenericStore[*model.Catalog, model.Catalog, domain.Catalog, domain.CatalogList](
		db,
		log,
		model.NewCatalogFromApiResource,
		(*model.Catalog).ToApiResource,
		model.CatalogsToApiResource,
	)
	return &CatalogStore{dbHandler: db, log: log, genericStore: genericStore, eventCallbackCaller: CallEventCallback(domain.CatalogKind, log)}
}

func (s *CatalogStore) getDB(ctx context.Context) *gorm.DB {
	return s.dbHandler.WithContext(ctx)
}

func (s *CatalogStore) InitialMigration(ctx context.Context) error {
	db := s.getDB(ctx)

	if err := db.AutoMigrate(&model.Catalog{}); err != nil {
		return err
	}

	// Create GIN index for Catalog labels
	if !db.Migrator().HasIndex(&model.Catalog{}, "idx_catalogs_labels") {
		if db.Dialector.Name() == "postgres" {
			if err := db.Exec("CREATE INDEX idx_catalogs_labels ON catalogs USING GIN (labels)").Error; err != nil {
				return err
			}
		} else {
			if err := db.Migrator().CreateIndex(&model.Catalog{}, "Labels"); err != nil {
				return err
			}
		}
	}

	// Create GIN index for Catalog annotations
	if !db.Migrator().HasIndex(&model.Catalog{}, "idx_catalogs_annotations") {
		if db.Dialector.Name() == "postgres" {
			if err := db.Exec("CREATE INDEX idx_catalogs_annotations ON catalogs USING GIN (annotations)").Error; err != nil {
				return err
			}
		} else {
			if err := db.Migrator().CreateIndex(&model.Catalog{}, "Annotations"); err != nil {
				return err
			}
		}
	}

	// Migrate CatalogItem table
	if err := db.AutoMigrate(&model.CatalogItem{}); err != nil {
		return err
	}

	return nil
}

func (s *CatalogStore) Create(ctx context.Context, orgId uuid.UUID, resource *domain.Catalog, eventCallback EventCallback) (*domain.Catalog, error) {
	catalog, err := s.genericStore.Create(ctx, orgId, resource)
	s.eventCallbackCaller(ctx, eventCallback, orgId, lo.FromPtr(resource.Metadata.Name), nil, catalog, true, err)
	return catalog, err
}

func (s *CatalogStore) Update(ctx context.Context, orgId uuid.UUID, resource *domain.Catalog, eventCallback EventCallback) (*domain.Catalog, error) {
	newCatalog, oldCatalog, err := s.genericStore.Update(ctx, orgId, resource, nil, true, nil)
	s.eventCallbackCaller(ctx, eventCallback, orgId, lo.FromPtr(resource.Metadata.Name), oldCatalog, newCatalog, false, err)
	return newCatalog, err
}

func (s *CatalogStore) CreateOrUpdate(ctx context.Context, orgId uuid.UUID, resource *domain.Catalog, eventCallback EventCallback) (*domain.Catalog, bool, error) {
	newCatalog, oldCatalog, created, err := s.genericStore.CreateOrUpdate(ctx, orgId, resource, nil, true, nil)
	s.eventCallbackCaller(ctx, eventCallback, orgId, lo.FromPtr(resource.Metadata.Name), oldCatalog, newCatalog, created, err)
	return newCatalog, created, err
}

func (s *CatalogStore) Get(ctx context.Context, orgId uuid.UUID, name string) (*domain.Catalog, error) {
	return s.genericStore.Get(ctx, orgId, name)
}

func (s *CatalogStore) List(ctx context.Context, orgId uuid.UUID, listParams ListParams) (*domain.CatalogList, error) {
	return s.genericStore.List(ctx, orgId, listParams)
}

func (s *CatalogStore) Delete(ctx context.Context, orgId uuid.UUID, name string, callback RemoveOwnerCallback, callbackEvent EventCallback) error {
	existingRecord := model.Catalog{Resource: model.Resource{OrgID: orgId, Name: name}}
	err := s.getDB(ctx).Transaction(func(innerTx *gorm.DB) (err error) {
		result := innerTx.Take(&existingRecord)
		if result.Error != nil {
			return ErrorFromGormError(result.Error)
		}

		result = innerTx.Unscoped().Delete(&existingRecord)
		if result.Error != nil {
			return ErrorFromGormError(result.Error)
		}
		owner := util.SetResourceOwner(domain.CatalogKind, name)
		return callback(ctx, innerTx, orgId, *owner)
	})

	if err == nil && callbackEvent != nil {
		s.eventCallbackCaller(ctx, callbackEvent, orgId, name, nil, nil, false, err)
	}
	if err != nil {
		if errors.Is(err, flterrors.ErrResourceNotFound) {
			return nil
		}
		return err
	}

	return nil
}

func (s *CatalogStore) UpdateStatus(ctx context.Context, orgId uuid.UUID, resource *domain.Catalog, eventCallback EventCallback) (*domain.Catalog, error) {
	// Get the old resource to compare conditions
	var oldCatalog *domain.Catalog
	existingResource, err := s.Get(ctx, orgId, lo.FromPtr(resource.Metadata.Name))
	if err == nil && existingResource != nil {
		oldCatalog = existingResource
	}

	// Update the status
	newCatalog, err := s.genericStore.UpdateStatus(ctx, orgId, resource)
	if err != nil {
		return newCatalog, err
	}

	// Call the event callback to emit condition-specific events
	s.eventCallbackCaller(ctx, eventCallback, orgId, lo.FromPtr(resource.Metadata.Name), oldCatalog, newCatalog, false, err)

	return newCatalog, err
}

func (s *CatalogStore) Count(ctx context.Context, orgId uuid.UUID, listParams ListParams) (int64, error) {
	query, err := ListQuery(&model.Catalog{}).Build(ctx, s.getDB(ctx), orgId, listParams)
	if err != nil {
		return 0, err
	}
	var catalogsCount int64
	if err := query.Count(&catalogsCount).Error; err != nil {
		return 0, ErrorFromGormError(err)
	}
	return catalogsCount, nil
}

func (s *CatalogStore) ListItems(ctx context.Context, orgId uuid.UUID, catalogName string, listParams ListParams) (*domain.CatalogItemList, error) {
	db := s.getDB(ctx)

	// First verify the catalog exists
	var catalog model.Catalog
	if err := db.Where("org_id = ? AND name = ?", orgId, catalogName).Take(&catalog).Error; err != nil {
		return nil, ErrorFromGormError(err)
	}

	// Query catalog items for this source
	var items []model.CatalogItem
	query := db.Where("org_id = ? AND catalog_name = ?", orgId, catalogName)

	// Apply limit if specified
	if listParams.Limit > 0 {
		query = query.Limit(listParams.Limit + 1) // +1 to check if there are more
	}

	// Order by app_name for consistent pagination
	query = query.Order("app_name ASC")

	if err := query.Find(&items).Error; err != nil {
		return nil, ErrorFromGormError(err)
	}

	// Handle pagination
	var cont *string
	var numRemaining *int64
	if listParams.Limit > 0 && len(items) > listParams.Limit {
		items = items[:listParams.Limit]
		// Set continue token (simplified - in production you'd encode the last item's position)
		remaining := int64(1) // Indicates there are more items
		numRemaining = &remaining
	}

	result := model.CatalogItemsToApiResource(items, cont, numRemaining)
	return &result, nil
}

