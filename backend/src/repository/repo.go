package repository

import (
	"analizier/backend/src/models"
	"fmt"
	"gorm.io/gorm"
)

type TrafficRepository interface {
	Create(traffic *models.Traffic) error
	CreateBulk(traffics []*models.Traffic) error
	GetAll(limit int, offset int) ([]models.Traffic, error)
	WriteFlowAnomaly() error
}

type sqliteTrafficRepo struct {
	db *gorm.DB
}

func NewSqliteTrafficRepo(db *gorm.DB) TrafficRepository {
	return &sqliteTrafficRepo{db: db}
}

func (r *sqliteTrafficRepo) Create(traffic *models.Traffic) error {
	return fmt.Errorf("not implemented")
}

func (r *sqliteTrafficRepo) CreateBulk(traffics []*models.Traffic) error {
	return fmt.Errorf("not implemented")
}

func (r *sqliteTrafficRepo) GetAll(limit int, offset int) ([]models.Traffic, error) {
	return nil, fmt.Errorf("not implemented")
}
func (r *sqliteTrafficRepo) WriteFlowAnomaly() error {
	return fmt.Errorf("not implemented")
}
